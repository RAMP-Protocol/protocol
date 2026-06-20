package ramphelpers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Ed25519 signed delivery URLs (ADR-013). The Exchange issues a URL signed over
// the canonical message "GET\n<url-without-sig>"; the edge worker
// (src/edge/src/verify.ts) and this SDK verify it identically. The signature
// covers the FULL URL (scheme+host+path+query minus sig), so the byte-parity
// hinges on the query being sorted — Go's url.Values.Encode() sorts, and the
// edge removes only the sig param without reordering, so both reconstruct the
// same canonical bytes.
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
	ErrURLMissingSignature       = errors.New("ramphelpers: signed URL missing sig param")
	ErrURLMissingExpiry          = errors.New("ramphelpers: signed URL missing/invalid exp param")
	ErrURLExpired                = errors.New("ramphelpers: signed URL expired")
	ErrURLSignatureInvalid       = errors.New("ramphelpers: signed URL signature invalid")
	ErrURLNotAgentBound          = errors.New("ramphelpers: signed URL is not agent-bound (bearer)")
	ErrProofOfPossessionMismatch = errors.New("ramphelpers: presented key does not match the URL's agent_id binding")
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

// SignURLEd25519 signs rawURL with priv, embedding exp (and kid when keyID is
// set, agent_id when agentID is set) and the base64url-no-pad signature over
// "GET\n<url-without-sig>". The result matches the edge worker's verifier.
func SignURLEd25519(priv ed25519.PrivateKey, keyID, rawURL, agentID string, expiry time.Time) (SignedURL, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedURL{}, fmt.Errorf("ramphelpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return SignedURL{}, fmt.Errorf("ramphelpers: parse url: %w", err)
	}
	q := parsed.Query()
	q.Set(urlExpParam, strconv.FormatInt(expiry.Unix(), 10))
	if keyID != "" {
		q.Set(urlKIDParam, keyID)
	}
	if agentID != "" {
		q.Set(AgentIDParam, agentID)
	}
	q.Del(urlSigParam)
	parsed.RawQuery = q.Encode() // sorted; the canonical message signs this form

	canonical := "GET\n" + parsed.String()
	sig := ed25519.Sign(priv, []byte(canonical))
	q.Set(urlSigParam, base64.RawURLEncoding.EncodeToString(sig))
	parsed.RawQuery = q.Encode()

	signed := parsed.String()
	return SignedURL{URL: signed, Expiry: expiry, Hash: HashURL(signed)}, nil
}

// VerifyURLEd25519 verifies a signed URL against pub, then checks expiry against
// now. On success it returns the bound agent_id (if any), kid, and expiry. It
// verifies the signature before trusting expiry (both are covered by the sig).
func VerifyURLEd25519(rawURL string, pub ed25519.PublicKey, now time.Time) (VerifiedURL, error) {
	if len(pub) != ed25519.PublicKeySize {
		return VerifiedURL{}, fmt.Errorf("ramphelpers: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return VerifiedURL{}, fmt.Errorf("ramphelpers: parse url: %w", err)
	}
	q := parsed.Query()
	sigB64 := q.Get(urlSigParam)
	if sigB64 == "" {
		return VerifiedURL{}, ErrURLMissingSignature
	}
	expRaw := q.Get(urlExpParam)
	expUnix, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil {
		return VerifiedURL{}, ErrURLMissingExpiry
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return VerifiedURL{}, fmt.Errorf("%w: bad base64url", ErrURLSignatureInvalid)
	}

	q.Del(urlSigParam)
	parsed.RawQuery = q.Encode()
	canonical := "GET\n" + parsed.String()
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return VerifiedURL{}, ErrURLSignatureInvalid
	}

	expiry := time.Unix(expUnix, 0)
	if expiry.Before(now) {
		return VerifiedURL{}, fmt.Errorf("%w: exp=%d now=%d", ErrURLExpired, expUnix, now.Unix())
	}
	return VerifiedURL{AgentID: q.Get(AgentIDParam), KeyID: q.Get(urlKIDParam), Expiry: expiry}, nil
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

// HashURL returns the SHA-256 digest of a signed URL (the
// transaction_log.signed_url_hash value, 32 bytes).
func HashURL(signed string) []byte {
	sum := sha256.Sum256([]byte(signed))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
