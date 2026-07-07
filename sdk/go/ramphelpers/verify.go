package ramphelpers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Pure RFC 9421 request verification: given the request, its exact body bytes,
// and the verifying public key, VerifyRequest enforces the RAMP covered-component
// policy and the created/expires window, then checks the Ed25519 signature. It
// performs NO IO — key resolution is the caller's (the injected KeyResolver,
// keyresolver.go) and the body is supplied, not read off req.Body — so it is the
// same logic the server interceptor, the edge, and a client verifying what it
// received all share (ADR-020 §4).

// Verifier-side error sentinels.
var (
	ErrMissingSignatureInput    = errors.New("ramphelpers: missing Signature-Input header")
	ErrMissingSignature         = errors.New("ramphelpers: missing Signature header")
	ErrMissingContentDigest     = errors.New("ramphelpers: missing Content-Digest header")
	ErrMalformedSignatureInput  = errors.New("ramphelpers: malformed Signature-Input")
	ErrUnsupportedAlgorithm     = errors.New("ramphelpers: unsupported alg (ed25519 only)")
	ErrDigestMismatch           = errors.New("ramphelpers: content-digest mismatch")
	ErrSignatureVerify          = errors.New("ramphelpers: signature verification failed")
	ErrMissingRequiredComponent = errors.New("ramphelpers: required covered component missing")
	ErrExpired                  = errors.New("ramphelpers: signature expired")
	ErrFutureCreated            = errors.New("ramphelpers: signature created in the future")
	ErrMissingCreated           = errors.New("ramphelpers: missing created param")
	ErrMissingExpires           = errors.New("ramphelpers: missing expires param")
)

// defaultMaxFutureSkew bounds how far a created timestamp may lead the verifier's
// clock (replay defence). 300s matches the OAuth 2.0 reauth skew convention.
const defaultMaxFutureSkew = 300 * time.Second

// VerifyOptions tune VerifyRequest. The zero value is production-correct: Now
// defaults to the wall clock and MaxFutureSkew to defaultMaxFutureSkew. Tests
// inject Now for determinism.
type VerifyOptions struct {
	Now           time.Time
	MaxFutureSkew time.Duration
}

// VerifiedRequest carries the proven signature metadata. PublicKey is the key
// the signature verified against, carried so downstream consumers bind to the
// proven key (e.g. its RFC 7638 thumbprint as agent_id) rather than re-resolving
// the claimed KeyID.
type VerifiedRequest struct {
	KeyID     string
	Algorithm string
	Label     string
	Signature string
	Created   int64
	Expires   int64
	PublicKey ed25519.PublicKey
}

// VerifyRequest verifies req+body against pub. body MUST be the exact bytes that
// produced the request payload.
func VerifyRequest(req *http.Request, body []byte, pub ed25519.PublicKey, opts VerifyOptions) (*VerifiedRequest, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxSkew := opts.MaxFutureSkew
	if maxSkew == 0 {
		maxSkew = defaultMaxFutureSkew
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ramphelpers: public key length %d != %d", len(pub), ed25519.PublicKeySize)
	}

	params, sigBytes, err := parseSignatureHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(params.Alg, AlgEd25519) {
		return nil, fmt.Errorf("%w: alg=%q", ErrUnsupportedAlgorithm, params.Alg)
	}
	if err := enforceRequiredComponents(params.Covered); err != nil {
		return nil, err
	}
	if err := enforceEntitlementCoverage(req.Header, params.Covered); err != nil {
		return nil, err
	}
	if err := enforceCreatedExpires(params, now, maxSkew); err != nil {
		return nil, err
	}
	if err := verifyContentDigest(req.Header, body, params.Covered); err != nil {
		return nil, err
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		return nil, ErrSignatureVerify
	}
	return &VerifiedRequest{
		KeyID:     params.KeyID,
		Algorithm: params.Alg,
		Label:     params.Label,
		Signature: req.Header.Get("Signature"),
		Created:   params.Created,
		Expires:   params.Expires,
		PublicKey: pub,
	}, nil
}

func enforceRequiredComponents(covered []string) error {
	seen := make(map[string]bool, len(covered))
	for _, c := range covered {
		seen[strings.ToLower(c)] = true
	}
	for _, need := range rampCoveredComponents {
		if !seen[need] {
			return fmt.Errorf("%w: %s", ErrMissingRequiredComponent, need)
		}
	}
	return nil
}

// enforceEntitlementCoverage requires the signature to commit to the
// entitlement-biscuit header iff it is present (absent → no constraint; present
// without coverage → rejection, so a biscuit cannot be slipped under a valid
// signature).
func enforceEntitlementCoverage(h http.Header, covered []string) error {
	if h.Get(entitlementHeader) == "" {
		return nil
	}
	for _, c := range covered {
		if strings.ToLower(c) == entitlementHeaderLower {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrMissingRequiredComponent, entitlementHeaderLower)
}

func enforceCreatedExpires(p sigParams, now time.Time, maxSkew time.Duration) error {
	if p.Created == 0 {
		return ErrMissingCreated
	}
	if p.Expires == 0 {
		return ErrMissingExpires
	}
	nowUnix := now.Unix()
	if p.Expires < nowUnix {
		return fmt.Errorf("%w: expires=%d now=%d", ErrExpired, p.Expires, nowUnix)
	}
	if p.Created > nowUnix+int64(maxSkew.Seconds()) {
		return fmt.Errorf("%w: created=%d now=%d", ErrFutureCreated, p.Created, nowUnix)
	}
	return nil
}

func verifyContentDigest(h http.Header, body []byte, covered []string) error {
	need := false
	for _, c := range covered {
		if strings.EqualFold(c, "content-digest") {
			need = true
			break
		}
	}
	if !need {
		return nil
	}
	raw := h.Get("Content-Digest")
	if raw == "" {
		return ErrMissingContentDigest
	}
	sum := sha256.Sum256(body)
	expected := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if strings.TrimSpace(raw) != expected {
		return ErrDigestMismatch
	}
	return nil
}

// --- Signature-Input / Signature structured-field parsing (RFC 9421 subset) ---

func parseSignatureHeaders(h http.Header) (sigParams, []byte, error) {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return sigParams{}, nil, ErrMissingSignatureInput
	}
	rawSig := h.Get("Signature")
	if rawSig == "" {
		return sigParams{}, nil, ErrMissingSignature
	}
	params, err := parseSignatureInput(rawInput)
	if err != nil {
		return sigParams{}, nil, err
	}
	sigBytes, err := parseSignatureField(rawSig, params.Label)
	if err != nil {
		return sigParams{}, nil, err
	}
	return params, sigBytes, nil
}

func parseSignatureInput(raw string) (sigParams, error) {
	eq := strings.Index(raw, "=")
	if eq <= 0 {
		return sigParams{}, fmt.Errorf("%w: missing label", ErrMalformedSignatureInput)
	}
	label := strings.TrimSpace(raw[:eq])
	rest := strings.TrimSpace(raw[eq+1:])
	lparen := strings.Index(rest, "(")
	rparen := strings.Index(rest, ")")
	if lparen != 0 || rparen < 0 {
		return sigParams{}, fmt.Errorf("%w: expected ( ... )", ErrMalformedSignatureInput)
	}
	inner := rest[1:rparen]
	params := sigParams{Label: label}
	fields, err := parseQuotedList(inner)
	if err != nil {
		return sigParams{}, err
	}
	params.Covered = fields
	tail := strings.TrimSpace(rest[rparen+1:])
	for _, kv := range splitParams(tail) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return sigParams{}, fmt.Errorf("%w: bad param %q", ErrMalformedSignatureInput, kv)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "keyid":
			params.KeyID = strings.Trim(v, `"`)
		case "alg":
			params.Alg = strings.Trim(v, `"`)
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return sigParams{}, fmt.Errorf("%w: created=%q", ErrMalformedSignatureInput, v)
			}
			params.Created = n
		case "expires":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return sigParams{}, fmt.Errorf("%w: expires=%q", ErrMalformedSignatureInput, v)
			}
			params.Expires = n
		}
	}
	if params.KeyID == "" {
		return sigParams{}, fmt.Errorf("%w: keyid required", ErrMalformedSignatureInput)
	}
	return params, nil
}

func parseQuotedList(inner string) ([]string, error) {
	var out []string
	i := 0
	for i < len(inner) {
		for i < len(inner) && (inner[i] == ' ' || inner[i] == '\t') {
			i++
		}
		if i >= len(inner) {
			break
		}
		if inner[i] != '"' {
			return nil, fmt.Errorf("%w: expected quoted identifier at %q", ErrMalformedSignatureInput, inner[i:])
		}
		j := i + 1
		for j < len(inner) && inner[j] != '"' {
			j++
		}
		if j >= len(inner) {
			return nil, fmt.Errorf("%w: unterminated quoted string", ErrMalformedSignatureInput)
		}
		out = append(out, inner[i+1:j])
		i = j + 1
	}
	return out, nil
}

func splitParams(s string) []string {
	s = strings.TrimPrefix(s, ";")
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ';' && !inQuote {
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

func parseSignatureField(raw, label string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	prefix := label + "="
	if !strings.HasPrefix(raw, prefix) {
		return nil, fmt.Errorf("%w: Signature label %q not present", ErrMalformedSignatureInput, label)
	}
	body := strings.TrimPrefix(raw, prefix)
	if !strings.HasPrefix(body, ":") || !strings.HasSuffix(body, ":") {
		return nil, fmt.Errorf("%w: Signature value not byte-sequence", ErrMalformedSignatureInput)
	}
	b64 := body[1 : len(body)-1]
	out, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: Signature base64: %w", ErrMalformedSignatureInput, err)
	}
	return out, nil
}
