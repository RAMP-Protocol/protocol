package helpers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
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
	// "signature";key="sigN-1" (forwarding chain, RFC 9421 §2.4).
	ErrBrokenSignatureChain = errors.New("helpers: signature chain broken (gap/reorder/missing link)")
	// ErrTooManyHops signals that the number of signatures on a request exceeds
	// the verifier's configured MaxSignatures budget (Exchange hop bound).
	ErrTooManyHops = errors.New("helpers: signature count exceeds hop budget")
	// ErrSignatureLifetimeTooLong signals that a signature's declared window
	// (expires − created) exceeds the verifier's MaxSignatureAge clamp.
	ErrSignatureLifetimeTooLong = errors.New("helpers: signature lifetime exceeds max age")
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
	// request — the Exchange hop bound. 0 means unbounded; only the
	// Exchange-terminal consumer sets it (= max_intermediary_hops + 1). A request
	// carrying more signatures is rejected with ErrTooManyHops before any
	// signature is cryptographically verified. Ignored by single-sig VerifyRequest.
	MaxSignatures int
	// MaxSignatureAge clamps a signature's declared lifetime (expires − created).
	// MaxFutureSkew only bounds the future edge; without an upper bound on the
	// window a signer can set expires = now + 10y and, if the replay store is
	// absent or forgotten, keep replaying the same bytes for years. 0 (default)
	// means unbounded — back-compatible; a server-terminal consumer sets it (the
	// RAMP target is minutes). A signature whose window exceeds it is rejected
	// with ErrSignatureLifetimeTooLong before the Ed25519 check.
	MaxSignatureAge time.Duration
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
	// SignatureAgent is the (covered, therefore signed) Signature-Agent header
	// value — the signer's WBA key-directory URL. Empty when the signer bound
	// no directory (the static bootstrap path).
	SignatureAgent string
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
	if err := enforceCreatedExpires(params, now, maxSkew, opts.MaxSignatureAge); err != nil {
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
		// Signature-Agent is a required covered component (enforced above), so
		// its value is signed and safe to expose as the proven directory.
		SignatureAgent: signatureAgentOf(req),
	}, nil
}

// signatureAgentOf returns the request's Signature-Agent header value,
// whitespace-trimmed. The covered-component enforcement above guarantees the
// header is signed whenever this value is consumed off a VerifiedRequest.
func signatureAgentOf(req *http.Request) string {
	return strings.TrimSpace(req.Header.Get(SignatureAgentHeader))
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
// entitlement-token header iff it is present (absent → no constraint; present
// without coverage → rejection, so an unsigned entitlement token cannot be
// slipped under a valid signature). Format-neutral: it checks coverage, never
// the token's contents, so it holds identically for JWT/opaque tokens.
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

func enforceCreatedExpires(p sigParams, now time.Time, maxSkew, maxAge time.Duration) error {
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
	// Lifetime clamp: a signer-chosen far-future expires is a wide replay window
	// (worst case when no replay store is wired). Reject a window longer than the
	// verifier allows. 0 = unbounded (back-compat).
	if maxAge > 0 && p.Expires-p.Created > int64(maxAge.Seconds()) {
		return fmt.Errorf("%w: window=%ds max=%ds", ErrSignatureLifetimeTooLong, p.Expires-p.Created, int64(maxAge.Seconds()))
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

// --- Signature-Input / Signature structured-field parsing (RFC 9421 / RFC 8941) ---
//
// Parsing is delegated to dunglas/httpsfv (the RFC 8941 structured-field
// library) rather than hand-rolled: httpsfv.UnmarshalDictionary tokenizes the
// Signature-Input and Signature dictionaries, so quoting, inner-list, integer,
// and byte-sequence edge cases are the library's contract, not this package's.
// The signature BASE construction stays hand-built (sigbase.go) — it is the
// cross-language byte contract (ADR-020 §8), a distinct concern from parsing.

// parseAllSignatures extracts ALL signature labels from the Signature-Input and
// Signature headers, returning one sigParams per label (in header order) and a
// label→signature-bytes map. Handles 1 or N signatures uniformly; a single-sig
// request is just the N=1 case.
func parseAllSignatures(h http.Header) ([]sigParams, map[string][]byte, error) {
	inputValues := h.Values("Signature-Input")
	if len(inputValues) == 0 {
		return nil, nil, ErrMissingSignatureInput
	}
	sigValues := h.Values("Signature")
	if len(sigValues) == 0 {
		return nil, nil, ErrMissingSignature
	}
	inputDict, err := httpsfv.UnmarshalDictionary(inputValues)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: Signature-Input: %w", ErrMalformedSignatureInput, err)
	}
	sigDict, err := httpsfv.UnmarshalDictionary(sigValues)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: Signature: %w", ErrMalformedSignatureInput, err)
	}
	names := inputDict.Names()
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("%w: no labels found", ErrMalformedSignatureInput)
	}
	rawInner := rawInnerByLabel(inputValues)
	allParams := make([]sigParams, 0, len(names))
	sigMap := make(map[string][]byte, len(names))
	for _, label := range names {
		params, perr := parseInputLabel(inputDict, label)
		if perr != nil {
			return nil, nil, perr
		}
		params.RawInner = rawInner[label]
		allParams = append(allParams, params)
		sigBytes, serr := parseSigLabel(sigDict, label)
		if serr != nil {
			return nil, nil, serr
		}
		sigMap[label] = sigBytes
	}
	return allParams, sigMap, nil
}

// rawInnerByLabel extracts the VERBATIM member value (everything after
// "label=") for each dictionary member across the Signature-Input header
// values, so the verifier can rebuild the signature base with the exact inner
// list the signer emitted (RFC 9421 §2.5). Splitting is quoted-string-aware
// (a keyid may legally contain ',' or parens inside its quotes) and later
// occurrences of a label overwrite earlier ones, matching SFV dictionary
// last-wins semantics so the raw text corresponds to the member httpsfv parsed.
func rawInnerByLabel(values []string) map[string]string {
	out := make(map[string]string)
	for _, v := range values {
		for _, member := range splitTopLevelMembers(v) {
			eq := strings.IndexByte(member, '=')
			if eq <= 0 {
				continue
			}
			label := strings.TrimSpace(member[:eq])
			out[label] = strings.TrimSpace(member[eq+1:])
		}
	}
	return out
}

// splitTopLevelMembers splits one SFV dictionary header value on top-level
// commas, honoring quoted strings and their backslash escapes.
func splitTopLevelMembers(s string) []string {
	var parts []string
	start := 0
	inQuote := false
	escaped := false
	for i := range len(s) {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// parseInputLabel converts one Signature-Input dictionary member (an inner list
// of covered components plus the signature params) into a sigParams.
func parseInputLabel(d *httpsfv.Dictionary, label string) (sigParams, error) {
	member, ok := d.Get(label)
	if !ok {
		return sigParams{}, fmt.Errorf("%w: label %q absent", ErrMalformedSignatureInput, label)
	}
	list, ok := member.(httpsfv.InnerList)
	if !ok {
		return sigParams{}, fmt.Errorf("%w: label %q is not an inner list", ErrMalformedSignatureInput, label)
	}
	covered := make([]CoveredComponent, 0, len(list.Items))
	for _, item := range list.Items {
		comp, cerr := coveredFromItem(item)
		if cerr != nil {
			return sigParams{}, cerr
		}
		covered = append(covered, comp)
	}
	params := sigParams{Label: label, Covered: covered}
	if err := applySignatureParams(&params, list.Params); err != nil {
		return sigParams{}, err
	}
	if params.KeyID == "" {
		return sigParams{}, fmt.Errorf("%w: keyid required", ErrMalformedSignatureInput)
	}
	return params, nil
}

// coveredFromItem converts one structured-field item (a covered-component
// identifier such as "@method" or "signature";key="sig1") into a
// CoveredComponent. Only string-valued component params are carried (the
// forwarding-chain key= param is the only one RAMP emits).
func coveredFromItem(item httpsfv.Item) (CoveredComponent, error) {
	name, ok := item.Value.(string)
	if !ok {
		return CoveredComponent{}, fmt.Errorf("%w: component identifier not a string", ErrMalformedSignatureInput)
	}
	comp := CoveredComponent{Name: name}
	if item.Params == nil {
		return comp, nil
	}
	for _, k := range item.Params.Names() {
		v, present := item.Params.Get(k)
		if !present {
			continue
		}
		sv, isStr := v.(string)
		if !isStr {
			return CoveredComponent{}, fmt.Errorf("%w: component param %q not a string", ErrMalformedSignatureInput, k)
		}
		comp.Params = append(comp.Params, ComponentParam{Key: k, Val: sv})
	}
	return comp, nil
}

// applySignatureParams reads the keyid/alg/created/expires signature parameters
// off the inner list's params into p.
func applySignatureParams(p *sigParams, params *httpsfv.Params) error {
	if params == nil {
		return nil
	}
	if v, ok := params.Get("keyid"); ok {
		s, isStr := v.(string)
		if !isStr {
			return fmt.Errorf("%w: keyid not a string", ErrMalformedSignatureInput)
		}
		p.KeyID = s
	}
	if v, ok := params.Get("alg"); ok {
		s, isStr := v.(string)
		if !isStr {
			return fmt.Errorf("%w: alg not a string", ErrMalformedSignatureInput)
		}
		p.Alg = s
	}
	if v, ok := params.Get("created"); ok {
		n, isInt := v.(int64)
		if !isInt {
			return fmt.Errorf("%w: created not an integer", ErrMalformedSignatureInput)
		}
		p.Created = n
	}
	if v, ok := params.Get("expires"); ok {
		n, isInt := v.(int64)
		if !isInt {
			return fmt.Errorf("%w: expires not an integer", ErrMalformedSignatureInput)
		}
		p.Expires = n
	}
	return nil
}

// parseSigLabel extracts the raw signature bytes for label from the Signature
// dictionary. Each member is an item whose value is a byte sequence ([]byte),
// which httpsfv base64-decodes from the `:…:` wire form.
func parseSigLabel(d *httpsfv.Dictionary, label string) ([]byte, error) {
	member, ok := d.Get(label)
	if !ok {
		return nil, fmt.Errorf("%w: Signature label %q not present", ErrMalformedSignatureInput, label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return nil, fmt.Errorf("%w: Signature label %q is not an item", ErrMalformedSignatureInput, label)
	}
	raw, ok := item.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: Signature value not a byte sequence", ErrMalformedSignatureInput)
	}
	return raw, nil
}

// signatureBytesForLabel parses the Signature header off h and returns the raw
// signature bytes for label. It backs the forwarding-chain link resolution:
// a predecessor hop's signature is referenced by label from the
// current hop's covered "signature";key="…" component.
func signatureBytesForLabel(h http.Header, label string) ([]byte, error) {
	sigValues := h.Values("Signature")
	if len(sigValues) == 0 {
		return nil, ErrMissingSignature
	}
	sigDict, err := httpsfv.UnmarshalDictionary(sigValues)
	if err != nil {
		return nil, fmt.Errorf("%w: Signature: %w", ErrMalformedSignatureInput, err)
	}
	return parseSigLabel(sigDict, label)
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

// enforceSignatureChain checks that allParams form a valid forwarding chain:
// labels are exactly sig1..sigN contiguous in Signature-Input order,
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
