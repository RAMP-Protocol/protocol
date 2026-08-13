package helpers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Ed25519 signed delivery URLs (ADR-013). The Exchange issues a URL signed over
// the canonical message "GET\n<url>"; the edge worker (src/edge/src/verify.ts)
// and this SDK verify it identically. The signature covers the URL as OPAQUE
// BYTES: neither signer nor verifier re-normalizes
// scheme/host/path — a mixed-case host, an explicit default port, and a raw
// space or percent in the path are all preserved verbatim. The ONLY transform is
// deterministic query handling (add exp/kid/agent_id, remove sig, sort the
// query), done identically across sdk/{go,ts,python}. This is why the canonical
// string is built by splitting the raw URL at its first '?' and preserving the
// prefix byte-for-byte, rather than round-tripping through url.URL.String()
// (which escapes the path and normalizes the host).
//
// agent_id, when present, is the requesting agent's RFC 7638 JWK thumbprint; it
// is covered by the signature, binding the URL to the agent's key (proof of
// possession). An empty agent_id yields an unbound (bearer) URL.

// Query-parameter names on signed delivery URLs (shared with the edge verifier).
const (
	AgentIDParam = "agent_id"
	urlSigParam  = "sig"
	urlExpParam  = "exp"
	urlKIDParam  = "kid"
)

// Signed-URL error sentinels.
var (
	ErrURLMissingSignature       = errors.New("helpers: signed URL missing sig param")
	ErrURLMissingExpiry          = errors.New("helpers: signed URL missing/invalid exp param")
	ErrURLExpired                = errors.New("helpers: signed URL expired")
	ErrURLSignatureInvalid       = errors.New("helpers: signed URL signature invalid")
	ErrURLNotAgentBound          = errors.New("helpers: signed URL is not agent-bound (bearer)")
	ErrProofOfPossessionMismatch = errors.New("helpers: presented key does not match the URL's agent_id binding")
)

// SignedURL carries the issued URL plus audit metadata. Hash is SHA-256 of the
// full URL (the transaction_log.signed_url_hash value).
type SignedURL struct {
	URL    string
	Expiry time.Time
	Hash   []byte
}

// VerifiedURL carries the verified metadata extracted from a signed URL.
type VerifiedURL struct {
	AgentID string // RFC 7638 thumbprint the URL is bound to ("" = bearer)
	KeyID   string // the kid param, if present
	Expiry  time.Time
}

// Bound reports whether the URL is agent-bound (carries an agent_id).
func (v VerifiedURL) Bound() bool { return v.AgentID != "" }

// splitURL divides a raw URL into its verbatim prefix (scheme+host+path) and its
// raw query (the bytes after the first '?'). Signed delivery URLs carry no
// fragment, so a '#' — if present — stays with the prefix and is signed verbatim
// like any other path byte. Preserving the prefix as raw bytes is what makes the
// canonicalization VERBATIM (no host/port/path normalization).
func splitURL(rawURL string) (prefix, rawQuery string) {
	if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		return rawURL[:i], rawURL[i+1:]
	}
	return rawURL, ""
}

// encodeQuery serializes key/value pairs exactly as Go's url.Values.Encode():
// sort by key (stable per-key value order), url.QueryEscape each key and value
// (space -> '+', unreserved A-Za-z0-9-._~ kept, everything else %XX uppercase),
// joined "k=v&k=v". sdk/ts and sdk/python reproduce this byte-for-byte.
func encodeQuery(pairs [][2]string) string {
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	var b strings.Builder
	for i, kv := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(kv[0]))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(kv[1]))
	}
	return b.String()
}

// canonicalSignedURL builds the URL whose bytes the signature covers: the raw
// prefix (verbatim) plus the deterministically re-encoded query. It parses the
// raw query WITHOUT normalizing the prefix, drops sig, applies the mutate
// callback (used by the signer to set exp/kid/agent_id), sorts, and re-encodes.
// Both SignURLEd25519 and VerifyURLEd25519 route through this one builder so the
// signer and verifier agree on the byte contract by construction.
func canonicalSignedURL(rawURL string, mutate func(pairs [][2]string) [][2]string) (string, error) {
	prefix, rawQuery := splitURL(rawURL)
	pairs, err := parseQueryPairs(rawQuery)
	if err != nil {
		return "", err
	}
	kept := pairs[:0]
	for _, kv := range pairs {
		if kv[0] != urlSigParam {
			kept = append(kept, kv)
		}
	}
	if mutate != nil {
		kept = mutate(kept)
	}
	encoded := encodeQuery(kept)
	if encoded == "" {
		return prefix, nil
	}
	return prefix + "?" + encoded, nil
}

// parseQueryPairs splits a raw query string into ordered key/value pairs,
// url.QueryUnescape-ing each side (so the re-encode is idempotent on
// already-encoded input). A '+' decodes to space, matching Go's url.ParseQuery.
func parseQueryPairs(rawQuery string) ([][2]string, error) {
	if rawQuery == "" {
		return nil, nil
	}
	parts := strings.Split(rawQuery, "&")
	pairs := make([][2]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, _ := strings.Cut(part, "=")
		k, err := url.QueryUnescape(key)
		if err != nil {
			return nil, fmt.Errorf("helpers: bad query key %q: %w", key, err)
		}
		v, err := url.QueryUnescape(value)
		if err != nil {
			return nil, fmt.Errorf("helpers: bad query value %q: %w", value, err)
		}
		pairs = append(pairs, [2]string{k, v})
	}
	return pairs, nil
}

// setParam sets (replacing any existing) a single query key, preserving order:
// an existing key is overwritten in place, a new key is appended.
func setParam(pairs [][2]string, key, value string) [][2]string {
	for i := range pairs {
		if pairs[i][0] == key {
			pairs[i][1] = value
			return pairs
		}
	}
	return append(pairs, [2]string{key, value})
}

// SignURLEd25519 signs rawURL with priv, embedding exp (and kid when keyID is
// set, agent_id when agentID is set) and the base64url-no-pad signature over
// "GET\n<url>". The URL is signed as OPAQUE BYTES — scheme/host/path are
// preserved verbatim; only the query is deterministically re-encoded. The result
// matches the edge worker's verifier.
func SignURLEd25519(priv ed25519.PrivateKey, keyID, rawURL, agentID string, expiry time.Time) (SignedURL, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedURL{}, fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	addParams := func(pairs [][2]string) [][2]string {
		pairs = setParam(pairs, urlExpParam, strconv.FormatInt(expiry.Unix(), 10))
		if keyID != "" {
			pairs = setParam(pairs, urlKIDParam, keyID)
		}
		if agentID != "" {
			pairs = setParam(pairs, AgentIDParam, agentID)
		}
		return pairs
	}
	unsigned, err := canonicalSignedURL(rawURL, addParams)
	if err != nil {
		return SignedURL{}, err
	}
	sig := ed25519.Sign(priv, []byte("GET\n"+unsigned))
	sigParam := base64.RawURLEncoding.EncodeToString(sig)
	signed, err := canonicalSignedURL(unsigned, func(pairs [][2]string) [][2]string {
		return setParam(pairs, urlSigParam, sigParam)
	})
	if err != nil {
		return SignedURL{}, err
	}
	return SignedURL{URL: signed, Expiry: expiry, Hash: HashURL(signed)}, nil
}

// VerifyURLEd25519 verifies a signed URL against pub, then checks expiry against
// now. On success it returns the bound agent_id (if any), kid, and expiry. It
// verifies the signature before trusting expiry (both are covered by the sig).
func VerifyURLEd25519(rawURL string, pub ed25519.PublicKey, now time.Time) (VerifiedURL, error) {
	if len(pub) != ed25519.PublicKeySize {
		return VerifiedURL{}, fmt.Errorf("helpers: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	_, rawQuery := splitURL(rawURL)
	pairs, err := parseQueryPairs(rawQuery)
	if err != nil {
		return VerifiedURL{}, fmt.Errorf("helpers: parse url: %w", err)
	}
	q := pairsToMap(pairs)
	sigB64 := q[urlSigParam]
	if sigB64 == "" {
		return VerifiedURL{}, ErrURLMissingSignature
	}
	expUnix, err := strconv.ParseInt(q[urlExpParam], 10, 64)
	if err != nil {
		return VerifiedURL{}, ErrURLMissingExpiry
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return VerifiedURL{}, fmt.Errorf("%w: bad base64url", ErrURLSignatureInvalid)
	}

	// Reconstruct the exact bytes the signer covered: the URL with sig dropped,
	// scheme/host/path verbatim, query deterministically re-encoded.
	unsigned, err := canonicalSignedURL(rawURL, nil)
	if err != nil {
		return VerifiedURL{}, fmt.Errorf("helpers: parse url: %w", err)
	}
	if !ed25519.Verify(pub, []byte("GET\n"+unsigned), sig) {
		return VerifiedURL{}, ErrURLSignatureInvalid
	}

	expiry := time.Unix(expUnix, 0)
	if expiry.Before(now) {
		return VerifiedURL{}, fmt.Errorf("%w: exp=%d now=%d", ErrURLExpired, expUnix, now.Unix())
	}
	return VerifiedURL{AgentID: q[AgentIDParam], KeyID: q[urlKIDParam], Expiry: expiry}, nil
}

// pairsToMap flattens ordered pairs to a last-wins map for single-value lookups
// (sig/exp/kid/agent_id are never repeated on a signed delivery URL).
func pairsToMap(pairs [][2]string) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		m[kv[0]] = kv[1]
	}
	return m
}

// CheckProofOfPossession enforces the agent binding: the presented public key's
// RFC 7638 thumbprint must equal the URL's agent_id. It returns ErrURLNotAgentBound
// for a bearer URL (the caller decides whether bearer access is acceptable) and
// ErrProofOfPossessionMismatch when the key does not match.
func (v VerifiedURL) CheckProofOfPossession(presentedPub ed25519.PublicKey) error {
	if !v.Bound() {
		return ErrURLNotAgentBound
	}
	tp, err := Thumbprint(presentedPub)
	if err != nil {
		return err
	}
	if tp != v.AgentID {
		return ErrProofOfPossessionMismatch
	}
	return nil
}

// RedactURL reduces a signed URL to scheme://host/path, for a value headed
// somewhere more durable than the caller who already holds it — a log line, or an
// error an operator will read.
//
// url.URL.Redacted() is NOT the tool for this. It masks userinfo passwords, and a
// delivery URL carries its credential in the QUERY: sig, kid, exp and agent_id.
// Redacted() would pass the signature through untouched while reading like a
// redaction, which is worse than not redacting at all.
//
// An unparseable input yields "" rather than the original: a value that could not
// be sanitized is not one to emit.
func RedactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	stripped := *parsed
	stripped.RawQuery, stripped.Fragment, stripped.User = "", "", nil
	return stripped.String()
}

// HashURL returns the SHA-256 digest of a signed URL (the
// transaction_log.signed_url_hash value, 32 bytes).
func HashURL(signed string) []byte {
	sum := sha256.Sum256([]byte(signed))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
