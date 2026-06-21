package helpers

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
	ErrMissingSignatureInput    = errors.New("helpers: missing Signature-Input header")
	ErrMissingSignature         = errors.New("helpers: missing Signature header")
	ErrMissingContentDigest     = errors.New("helpers: missing Content-Digest header")
	ErrMalformedSignatureInput  = errors.New("helpers: malformed Signature-Input")
	ErrUnsupportedAlgorithm     = errors.New("helpers: unsupported alg (ed25519 only)")
	ErrDigestMismatch           = errors.New("helpers: content-digest mismatch")
	ErrSignatureVerify          = errors.New("helpers: signature verification failed")
	ErrMissingRequiredComponent = errors.New("helpers: required covered component missing")
	ErrExpired                  = errors.New("helpers: signature expired")
	ErrFutureCreated            = errors.New("helpers: signature created in the future")
	ErrMissingCreated           = errors.New("helpers: missing created param")
	ErrMissingExpires           = errors.New("helpers: missing expires param")
	// ErrBrokenSignatureChain signals a multisig request whose signatures do not
	// form a valid forwarding chain: labels are non-contiguous, reordered, or a
	// sigN (N>1) does not cover exactly its predecessor via
	// "signature";key="sigN-1" (RAMP-56 forwarding chain, RFC 9421 §2.4).
	ErrBrokenSignatureChain = errors.New("helpers: signature chain broken (gap/reorder/missing link)")
	// ErrTooManyHops signals that the number of signatures on a request exceeds
	// the verifier's configured MaxSignatures budget (Exchange hop bound).
	ErrTooManyHops = errors.New("helpers: signature count exceeds hop budget")
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
	// MaxSignatures bounds the number of signatures accepted on a multisig
	// request — the Exchange hop bound (RAMP-56). 0 means unbounded; only the
	// Exchange-terminal consumer sets it (= max_intermediary_hops + 1). A request
	// carrying more signatures is rejected with ErrTooManyHops before any
	// signature is cryptographically verified. Ignored by single-sig VerifyRequest.
	MaxSignatures int
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
// produced the request payload. It verifies the FIRST signature label only — for
// a single-signer request that is the whole request; for a multisig request use
// VerifyMultisigRequest / VerifyMultisigRequestResolved.
func VerifyRequest(req *http.Request, body []byte, pub ed25519.PublicKey, opts VerifyOptions) (*VerifiedRequest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("helpers: public key length %d != %d", len(pub), ed25519.PublicKeySize)
	}
	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		return nil, err
	}
	return verifySingleSignature(req, allParams[0], sigMap, body, staticPub(pub), opts)
}

// resolveFunc adapts a fixed public key or a KeyResolver to the lookup shape
// verifySingleSignature needs.
type resolveFunc func(keyID string) (ed25519.PublicKey, error)

func staticPub(pub ed25519.PublicKey) resolveFunc {
	return func(string) (ed25519.PublicKey, error) { return pub, nil }
}

// verifySingleSignature runs the full per-signature validation chain (alg,
// covered-component policy, entitlement coverage, created/expires window,
// content-digest, then the Ed25519 check over the signature base). Shared by the
// single-sig and multisig paths so both judge a signature by identical rules.
func verifySingleSignature(
	req *http.Request, params sigParams, sigMap map[string][]byte,
	body []byte, resolve resolveFunc, opts VerifyOptions,
) (*VerifiedRequest, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxSkew := opts.MaxFutureSkew
	if maxSkew == 0 {
		maxSkew = defaultMaxFutureSkew
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
	pub, err := resolve(params.KeyID)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("helpers: public key length %d != %d", len(pub), ed25519.PublicKeySize)
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return nil, err
	}
	sigBytes, ok := sigMap[params.Label]
	if !ok {
		return nil, fmt.Errorf("%w: label %q not in Signature", ErrMalformedSignatureInput, params.Label)
	}
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		return nil, ErrSignatureVerify
	}
	return &VerifiedRequest{
		KeyID:     params.KeyID,
		Algorithm: params.Alg,
		Label:     params.Label,
		Signature: base64.StdEncoding.EncodeToString(sigBytes),
		Created:   params.Created,
		Expires:   params.Expires,
		PublicKey: pub,
	}, nil
}

func enforceRequiredComponents(covered []CoveredComponent) error {
	seen := make(map[string]bool, len(covered))
	for _, c := range covered {
		seen[strings.ToLower(c.Name)] = true
	}
	for _, need := range requiredCoveredComponents {
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
func enforceEntitlementCoverage(h http.Header, covered []CoveredComponent) error {
	if h.Get(entitlementHeader) == "" {
		return nil
	}
	for _, c := range covered {
		if strings.ToLower(c.Name) == entitlementHeaderLower {
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

func verifyContentDigest(h http.Header, body []byte, covered []CoveredComponent) error {
	need := false
	for _, c := range covered {
		if strings.EqualFold(c.Name, "content-digest") {
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

// parseAllSignatures extracts ALL signature labels from the Signature-Input and
// Signature headers, returning one sigParams per label (in header order) and a
// label→signature-bytes map. Handles 1 or N signatures uniformly; a single-sig
// request is just the N=1 case.
func parseAllSignatures(h http.Header) ([]sigParams, map[string][]byte, error) {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return nil, nil, ErrMissingSignatureInput
	}
	rawSig := h.Get("Signature")
	if rawSig == "" {
		return nil, nil, ErrMissingSignature
	}
	inputLabels := parseMultiLabelInput(rawInput)
	if len(inputLabels) == 0 {
		return nil, nil, fmt.Errorf("%w: no labels found", ErrMalformedSignatureInput)
	}
	allParams := make([]sigParams, 0, len(inputLabels))
	for _, labelInput := range inputLabels {
		params, err := parseSignatureInput(labelInput)
		if err != nil {
			return nil, nil, err
		}
		allParams = append(allParams, params)
	}
	sigMap := make(map[string][]byte, len(allParams))
	for _, params := range allParams {
		sigBytes, err := parseSignatureField(rawSig, params.Label)
		if err != nil {
			return nil, nil, err
		}
		sigMap[params.Label] = sigBytes
	}
	return allParams, sigMap, nil
}

// parseMultiLabelInput splits a Signature-Input header value on top-level commas
// (those outside quotes and parentheses), returning individual
// label=(...);params strings.
func parseMultiLabelInput(raw string) []string {
	var out []string
	var cur strings.Builder
	inParen := 0
	inQuote := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '"' && (i == 0 || raw[i-1] != '\\') {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if inQuote {
			cur.WriteByte(c)
			continue
		}
		switch {
		case c == '(':
			inParen++
			cur.WriteByte(c)
		case c == ')':
			inParen--
			cur.WriteByte(c)
		case c == ',' && inParen == 0:
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
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
	fields, err := parseComponentList(inner)
	if err != nil {
		return sigParams{}, err
	}
	params.Covered = fields
	if err := parseInputParamsTail(strings.TrimSpace(rest[rparen+1:]), &params); err != nil {
		return sigParams{}, err
	}
	if params.KeyID == "" {
		return sigParams{}, fmt.Errorf("%w: keyid required", ErrMalformedSignatureInput)
	}
	return params, nil
}

// parseInputParamsTail consumes the ;keyid="…";alg="…";created=…;expires=… tail
// of a Signature-Input label into params.
func parseInputParamsTail(tail string, params *sigParams) error {
	for _, kv := range splitParams(tail) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("%w: bad param %q", ErrMalformedSignatureInput, kv)
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
				return fmt.Errorf("%w: created=%q", ErrMalformedSignatureInput, v)
			}
			params.Created = n
		case "expires":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("%w: expires=%q", ErrMalformedSignatureInput, v)
			}
			params.Expires = n
		}
	}
	return nil
}

// parseComponentList parses a space-separated list of RFC 9421 component
// identifiers, each a quoted name optionally followed by `;param="value"`
// parameters with no intervening space. Only string-valued parameters are
// supported (sufficient for the forwarding-chain `"signature";key="sig1"`).
func parseComponentList(inner string) ([]CoveredComponent, error) {
	var out []CoveredComponent
	i := 0
	for i < len(inner) {
		for i < len(inner) && (inner[i] == ' ' || inner[i] == '\t') {
			i++
		}
		if i >= len(inner) {
			break
		}
		comp, next, err := parseOneComponent(inner, i)
		if err != nil {
			return nil, err
		}
		out = append(out, comp)
		i = next
	}
	return out, nil
}

// parseOneComponent parses a single component identifier starting at index i
// (which must point at the opening quote). Returns the component and the index
// just past it (past any trailing parameters).
func parseOneComponent(inner string, i int) (CoveredComponent, int, error) {
	if inner[i] != '"' {
		return CoveredComponent{}, 0,
			fmt.Errorf("%w: expected quoted identifier at %q", ErrMalformedSignatureInput, inner[i:])
	}
	j := i + 1
	for j < len(inner) && inner[j] != '"' {
		j++
	}
	if j >= len(inner) {
		return CoveredComponent{}, 0, fmt.Errorf("%w: unterminated quoted string", ErrMalformedSignatureInput)
	}
	comp := CoveredComponent{Name: inner[i+1 : j]}
	i = j + 1
	for i < len(inner) && inner[i] == ';' {
		p, next, err := parseComponentParam(inner, i+1)
		if err != nil {
			return CoveredComponent{}, 0, err
		}
		comp.Params = append(comp.Params, p)
		i = next
	}
	return comp, i, nil
}

// parseComponentParam parses a `key="value"` parameter starting at index i (just
// past the leading semicolon). Returns the param and the index past it.
func parseComponentParam(inner string, i int) (ComponentParam, int, error) {
	ks := i
	for i < len(inner) && inner[i] != '=' {
		i++
	}
	if i >= len(inner) {
		return ComponentParam{}, 0, fmt.Errorf("%w: component param missing '='", ErrMalformedSignatureInput)
	}
	key := strings.TrimSpace(inner[ks:i])
	i++ // consume '='
	if i >= len(inner) || inner[i] != '"' {
		return ComponentParam{}, 0, fmt.Errorf("%w: component param value not quoted", ErrMalformedSignatureInput)
	}
	vs := i + 1
	j := vs
	for j < len(inner) && inner[j] != '"' {
		j++
	}
	if j >= len(inner) {
		return ComponentParam{}, 0, fmt.Errorf("%w: unterminated component param value", ErrMalformedSignatureInput)
	}
	return ComponentParam{Key: key, Val: inner[vs:j]}, j + 1, nil
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

// parseSignatureField pulls the binary signature bytes for label out of the
// Signature header. Handles both the single form `sig1=:base64:` and the
// multi-label form `sig1=:base64:, sig2=:base64:`.
func parseSignatureField(raw, label string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	for _, part := range parseMultiLabelSignature(raw) {
		part = strings.TrimSpace(part)
		prefix := label + "="
		if !strings.HasPrefix(part, prefix) {
			continue
		}
		body := strings.TrimPrefix(part, prefix)
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
	return nil, fmt.Errorf("%w: Signature label %q not present", ErrMalformedSignatureInput, label)
}

// parseMultiLabelSignature splits a Signature header value on top-level commas
// (those outside a `:...:` byte-sequence). Format: `sig1=:b64:, sig2=:b64:`.
func parseMultiLabelSignature(raw string) []string {
	var out []string
	var cur strings.Builder
	inByteSeq := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == ':':
			inByteSeq = !inByteSeq
			cur.WriteByte(c)
		case c == ',' && !inByteSeq:
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// VerifyMultisigRequest verifies ALL signatures on req against keys from
// resolve, returning the VerifiedRequest list in label order (sig1, sig2, …).
// It rejects a chain exceeding opts.MaxSignatures (when set) before any crypto,
// enforces the structural forwarding chain, then cryptographically verifies each
// signature — so a stripped, reordered, or substituted predecessor is rejected.
func VerifyMultisigRequest(req *http.Request, body []byte, resolve resolveFunc, opts VerifyOptions) ([]VerifiedRequest, error) {
	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		return nil, err
	}
	if opts.MaxSignatures > 0 && len(allParams) > opts.MaxSignatures {
		return nil, fmt.Errorf("%w: got %d max %d", ErrTooManyHops, len(allParams), opts.MaxSignatures)
	}
	if err := enforceSignatureChain(allParams); err != nil {
		return nil, err
	}
	verified := make([]VerifiedRequest, 0, len(allParams))
	for _, params := range allParams {
		v, verr := verifySingleSignature(req, params, sigMap, body, resolve, opts)
		if verr != nil {
			return nil, verr
		}
		verified = append(verified, *v)
	}
	return verified, nil
}

// enforceSignatureChain checks that allParams form a valid forwarding chain
// (RAMP-56): labels are exactly sig1..sigN contiguous in Signature-Input order,
// sig1 carries no "signature" component, and every sigK (K>1) covers exactly one
// "signature";key="sig(K-1)" link to its immediate predecessor. This is the
// STRUCTURAL gate only; the cryptographic binding is enforced by the per-sig
// verify (each sigK's base resolves its chain link to the live bytes of
// sig(K-1)). A single signature trivially satisfies the chain.
func enforceSignatureChain(allParams []sigParams) error {
	for i, p := range allParams {
		wantLabel := fmt.Sprintf("sig%d", i+1)
		if p.Label != wantLabel {
			return fmt.Errorf("%w: label %q at position %d, want %q", ErrBrokenSignatureChain, p.Label, i+1, wantLabel)
		}
		link, count := chainLink(p.Covered)
		if i == 0 {
			if count != 0 {
				return fmt.Errorf("%w: sig1 must not carry a signature component", ErrBrokenSignatureChain)
			}
			continue
		}
		wantPrev := fmt.Sprintf("sig%d", i)
		if count != 1 || link != wantPrev {
			return fmt.Errorf("%w: %s must cover exactly \"signature\";key=%q (got %d links, key=%q)",
				ErrBrokenSignatureChain, wantLabel, wantPrev, count, link)
		}
	}
	return nil
}

// chainLink returns the key parameter of the single "signature" covered
// component and the number of "signature" components present. A well-formed link
// has count == 1; count == 0 means no link, count > 1 is malformed.
func chainLink(covered []CoveredComponent) (key string, count int) {
	for _, c := range covered {
		if strings.EqualFold(c.Name, "signature") {
			count++
			key = componentParam(c, "key")
		}
	}
	return key, count
}
