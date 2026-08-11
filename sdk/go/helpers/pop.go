package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Agent-binding proof of possession for signed delivery URLs (ADR-013).
//
// When a signed URL carries an agent_id — the RFC 7638 thumbprint of the key
// that signed the offer acceptance — a code-capable edge requires the fetcher to
// prove possession of that key, fully offline. The proof is two headers on the
// GET: the raw public key in X-RAMP-Agent-Key, and an RFC 9421 signature over
// @method + @target-uri. The edge then enforces a three-way identity:
//
//	agent_id (URL) == keyid (Signature-Input) == thumbprint(presented key)
//
// The last equality is the one that cannot be dropped. Verifying the signature
// against the presented key alone proves nothing — any actor could present their
// own key plus a valid self-signature.
//
// This is the SIGN face. The verify face ships in sdk/ts and sdk/python (the
// edge runs there); Go is the byte oracle both are pinned to, through
// testdata/pop-vectors.json.

// AgentKeyHeader carries the raw Ed25519 public key the fetcher presents, as
// base64url with no padding. ADR-013 chose a dedicated header over an inline JWK
// in keyid: the edge hashes this value and requires the digest to equal the
// URL's agent_id, so a fetcher cannot present one key while naming another.
const AgentKeyHeader = "X-RAMP-Agent-Key"

// popLabel is the only signature label this profile emits. Unlike the RAMP
// request profile there is no forwarding chain here — a delivery fetch is a
// single hop to the edge — so sigN>1 never arises and the label is fixed rather
// than computed.
const popLabel = "sig1"

// ErrMissingTargetURI signals a proof requested without the URL it is meant to
// bind. @target-uri is half the covered set; signing without it would produce a
// proof valid for any URL the presented key is offered against, which is the
// replay this profile exists to stop.
var ErrMissingTargetURI = errors.New("helpers: missing target URI (required by the agent-binding profile)")

// ErrKeyIDMismatch signals that the keyid does not match the RFC 7638
// thumbprint of the key presented alongside it. The edge checks the same
// equality and answers thumbprint_mismatch, but by then the cause — a custody
// layer that paired a keyid with the wrong key — is several hops from the
// symptom. Refusing here names it at the source.
var ErrKeyIDMismatch = errors.New("helpers: keyid is not the thumbprint of the presented key")

// ErrInvalidPoPInput signals a proof input that cannot be written into a
// signature base without changing its shape — a control byte in the method or the
// target URI, which the line-delimited base would read as a component boundary.
var ErrInvalidPoPInput = errors.New("helpers: proof input is not usable in a signature base")

// isControlByte reports whether r is a C0 control or DEL. Applied to the two
// values written verbatim into the signature base.
func isControlByte(r rune) bool { return r < 0x20 || r == 0x7f }

// PoPOptions carries what a delivery-URL proof of possession needs beyond the
// key material. Only URL, Created and Expires are required.
type PoPOptions struct {
	// URL is the signed delivery URL, used VERBATIM as @target-uri — the exact
	// bytes the Exchange minted, query parameters and all.
	//
	// This is a string and not a request value on purpose. The edge rebuilds the
	// base from the raw request line it received, so the signing side must not
	// route the URL through a parsed value first: doing so yields the DECODED
	// path, expanding every percent-escape before it reaches the signed bytes.
	// %2F is the sharpest case, since it decodes to a real separator and the
	// signature would then cover a different path structure than the wire carried.
	// The result is a proof that cannot verify, surfacing as a blanket 403 with no
	// indication that the URL was the problem.
	URL string
	// KeyID is the RFC 9421 keyid: the RFC 7638 thumbprint of the presented key.
	// It is the anchor of the three-way identity the edge enforces. Empty means
	// "take the Signer's own key id". Either way it is cross-checked against the
	// presented key before anything is signed.
	KeyID string
	// Created is the unix-seconds instant the proof was made. The edge rejects a
	// created more than 300s in its own future, so a signer whose clock runs fast
	// fails closed.
	Created int64
	// Expires is the unix-seconds cutoff after which the proof is stale. Keep it
	// short: the covered set is only method and URL, so within this window the
	// proof is replayable by anyone who observes the request.
	Expires int64
	// Method is the HTTP method being signed. Empty means GET. A signed URL is
	// read-only in practice, but @method is covered precisely so a proof made for
	// a GET cannot be lifted onto a write.
	Method string
}

// AgentBinding is the proof a fetcher attaches to a bound delivery request: the
// three header values, ready to apply. It is returned as values rather than
// written onto a request so a caller can sign before it has built one, so this
// tier stays free of any dialing surface, and so the emitted bytes can be
// asserted directly against the shared cross-language vectors.
type AgentBinding struct {
	// AgentKey is the X-RAMP-Agent-Key value: base64url, no padding.
	AgentKey string
	// SignatureInput is the full Signature-Input value, label included.
	SignatureInput string
	// Signature is the full Signature value, label included. The byte string
	// inside the colons is STANDARD base64 while AgentKey above is base64url — an
	// asymmetry that comes from RFC 8941's byte-sequence encoding meeting a header
	// this profile defines itself, and one a verifier will not forgive.
	Signature string
}

// Apply writes the binding's three headers onto h.
func (b AgentBinding) Apply(h http.Header) {
	h.Set(AgentKeyHeader, b.AgentKey)
	h.Set("Signature-Input", b.SignatureInput)
	h.Set("Signature", b.Signature)
}

// popSignatureBase builds the RFC 9421 signature base for the agent-binding
// profile: the two covered components followed by the parameters line, joined
// with newlines and with no trailing newline.
//
// It takes raw strings rather than a request value for the reason PoPOptions.URL
// documents — the verbatim URL is the contract — and because the RAMP base
// builder in sigbase.go reconstructs @target-uri from a parsed URL's decoded
// path, which is exactly the transformation this profile must not perform. The
// two builders are pinned against each other in the internal base test: they
// agree on every ordinary delivery URL and diverge only where the path carries a
// percent-escape.
//
// rawParams is taken as given rather than rebuilt: on the verifying side it
// arrives verbatim in the Signature-Input header, so treating it as an opaque
// string here is what keeps the two faces symmetric.
func popSignatureBase(method, rawURL, rawParams string) string {
	return strings.Join([]string{
		`"@method": ` + strings.ToUpper(method),
		`"@target-uri": ` + rawURL,
		`"@signature-params": ` + rawParams,
	}, "\n")
}

// popSignatureParams renders the @signature-params value for this profile.
//
// The parameter ORDER is part of the wire contract, not a formatting choice: the
// base is signed over this exact string and the verifier reconstructs it from the
// header as received. keyid, alg, created, expires — matching the TypeScript and
// Python faces. A generic RFC 9421 emitter tends to produce
// created;expires;alg;keyid instead, and that mismatch is the whole reason this
// profile builds its own base instead of routing through SignRequest.
func popSignatureParams(keyID string, created, expires int64) string {
	return fmt.Sprintf(
		`("@method" "@target-uri");keyid=%q;alg=%q;created=%d;expires=%d`,
		keyID, AlgEd25519, created, expires,
	)
}

// SignAgentBinding produces the proof of possession a fetcher presents when it
// retrieves a delivery URL bound to an agent key. The covered set is exactly
// @method and @target-uri: a GET carries no body to digest, and the signed URL is
// itself the credential, already covered by @target-uri, so there is no
// Authorization header worth binding. That is why SignRequest cannot serve this
// profile — it enforces the five-component RAMP set.
//
// The key arrives as a Signer plus the public half rather than as a raw private
// key: custody stays with the application (a KMS or HSM signer never exposes its
// key), and the public half must be supplied separately because the presented-key
// header carries it and a Signer cannot yield it.
func SignAgentBinding(ctx context.Context, signer Signer, pub ed25519.PublicKey, opts PoPOptions) (AgentBinding, error) {
	keyID, err := validateAgentBinding(signer, pub, opts)
	if err != nil {
		return AgentBinding{}, err
	}
	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}
	params := popSignatureParams(keyID, opts.Created, opts.Expires)
	raw, err := signer.Sign(ctx, []byte(popSignatureBase(method, opts.URL, params)))
	if err != nil {
		return AgentBinding{}, fmt.Errorf("helpers: sign agent binding: %w", err)
	}
	return AgentBinding{
		AgentKey:       base64.RawURLEncoding.EncodeToString(pub),
		SignatureInput: popLabel + "=" + params,
		Signature:      popLabel + "=:" + base64.StdEncoding.EncodeToString(raw) + ":",
	}, nil
}

// validateAgentBinding checks every precondition of a bound fetch and returns the
// keyid the proof will declare. It runs before any signing so a caller that has
// mispaired a key and a keyid learns it here rather than from a 403 that names
// nothing.
func validateAgentBinding(signer Signer, pub ed25519.PublicKey, opts PoPOptions) (string, error) {
	if signer == nil {
		return "", errors.New("helpers: agent-binding signer is nil")
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("helpers: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if opts.URL == "" {
		return "", ErrMissingTargetURI
	}
	// The base is line-delimited and both values are written into it verbatim, so
	// a control byte in either would add or split a line and the bytes signed here
	// would stop describing the request the verifier reconstructs. Refused rather
	// than escaped: no legitimate method or target URI contains one, and a
	// signature base is the wrong place to be lenient.
	if i := strings.IndexFunc(opts.URL, isControlByte); i >= 0 {
		return "", fmt.Errorf("%w: target URI carries a control byte at %d", ErrInvalidPoPInput, i)
	}
	if i := strings.IndexFunc(opts.Method, isControlByte); i >= 0 {
		return "", fmt.Errorf("%w: method carries a control byte at %d", ErrInvalidPoPInput, i)
	}
	// A proof carrying no created sails through as a signature claiming 1970: the
	// edge bounds how far created may lead its clock, not how far it may lag, so
	// freshness would be silently absent rather than loudly wrong.
	if opts.Created <= 0 {
		return "", ErrMissingCreated
	}
	if opts.Expires <= 0 {
		return "", ErrMissingExpires
	}
	if signer.Algorithm() != AlgEd25519 {
		return "", fmt.Errorf("%w: agent binding requires %q, signer offers %q",
			ErrUnsupportedAlgorithm, AlgEd25519, signer.Algorithm())
	}
	keyID := opts.KeyID
	if keyID == "" {
		keyID = signer.KeyID()
	}
	thumb, err := Thumbprint(pub)
	if err != nil {
		return "", fmt.Errorf("helpers: derive keyid thumbprint: %w", err)
	}
	if keyID != thumb {
		return "", fmt.Errorf("%w: keyid %q, presented-key thumbprint %q", ErrKeyIDMismatch, keyID, thumb)
	}
	return keyID, nil
}
