package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// AlgEd25519 is the RFC 9421 alg value for Ed25519 signatures.
const AlgEd25519 = "ed25519"

// BrokerKeyIDPrefix is the keyID prefix that marks a broker relay key on the
// wire (shape "broker.<instance>.<rotation>"). Relay-key loaders stamp it and
// the multisig classifier uses it to route a signature into the relay slot.
// Shared so the producing and consuming sides cannot drift.
const BrokerKeyIDPrefix = "broker."

// Signer performs the raw crypto half of RFC 9421 request signing. The SDK
// builds the signature base (covered components + parameters); the Signer signs
// exactly those bytes. Splitting it this way means a KMS/HSM/remote signer
// satisfies the same interface and the SDK never sees the private key — custody
// stays with the application (ADR-020 §3, ramp-sdk-api.md "The core abstraction:
// Signer").
type Signer interface {
	// KeyID is the RFC 9421 keyid the verifier resolves a public key for.
	KeyID() string
	// Algorithm is the RFC 9421 alg value (e.g. AlgEd25519).
	Algorithm() string
	// Sign returns the signature over the signature base. ctx lets a remote
	// signer carry deadlines/cancellation; local signers ignore it.
	Sign(ctx context.Context, signatureBase []byte) ([]byte, error)
}

// ed25519Signer is the built-in local Ed25519 signer.
type ed25519Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewEd25519Signer wraps an in-memory Ed25519 private key as a Signer. For
// KMS/HSM custody, implement Signer directly instead.
func NewEd25519Signer(keyID string, priv ed25519.PrivateKey) (Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("helpers: signer keyID is empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return &ed25519Signer{keyID: keyID, priv: priv}, nil
}

// NewEd25519SignerFromSeed builds a Signer from a 32-byte Ed25519 seed.
func NewEd25519SignerFromSeed(keyID string, seed []byte) (Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("helpers: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return NewEd25519Signer(keyID, ed25519.NewKeyFromSeed(seed))
}

func (s *ed25519Signer) KeyID() string     { return s.keyID }
func (s *ed25519Signer) Algorithm() string { return AlgEd25519 }

func (s *ed25519Signer) Sign(_ context.Context, base []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, base), nil
}

// SignOptions tune SignRequest. Created/Expires are injected (L1 reads no clock)
// as unix-seconds; the verifier enforces the window against its own clock.
type SignOptions struct {
	Created int64
	Expires int64
}

// SignRequest signs req with the RAMP covered-component set and mutates it in
// place: it sets Content-Digest over body, binds the Authorization header
// (even when empty, so a later token injection is detected), builds the RFC
// 9421 signature base, asks the Signer to sign it, and writes the
// Signature-Input and Signature headers. body must be the exact bytes that will
// be transmitted.
func SignRequest(ctx context.Context, req *http.Request, body []byte, signer Signer, opts SignOptions) error {
	if signer == nil {
		return fmt.Errorf("helpers: nil signer")
	}
	req.Header.Set("Content-Digest", ContentDigest(body))
	bindAuthorization(req)

	params := sigParams{
		Label:   "sig1",
		Covered: coveredFor(req),
		KeyID:   signer.KeyID(),
		Alg:     signer.Algorithm(),
		Created: opts.Created,
		Expires: opts.Expires,
	}
	return signWithParams(ctx, req, params, signer, sigWriteSet)
}

// AppendSignature chains a new signature onto req WITHOUT disturbing any
// existing one (RAMP-56 forwarding chain). It preserves an existing
// Content-Digest (only setting it when missing), binds Authorization, finds the
// next label sig(N+1) and predecessor sigN, builds the chain-linked covered set
// (the RAMP base plus "signature";key="sigN" so sig(N+1) commits to its
// predecessor), asks the Signer to sign, and APPENDS to the Signature-Input /
// Signature headers. Appending to a request with no existing signatures produces
// a sig1 byte-for-byte identical to SignRequest — single-sig is the N=1 case.
func AppendSignature(ctx context.Context, req *http.Request, body []byte, signer Signer, opts SignOptions) error {
	if signer == nil {
		return fmt.Errorf("helpers: nil signer")
	}
	if req.Header.Get("Content-Digest") == "" {
		req.Header.Set("Content-Digest", ContentDigest(body))
	}
	bindAuthorization(req)
	prevLabel, hasPrev := findPrevLabel(req.Header)
	params := sigParams{
		Label:   findNextLabel(req.Header),
		Covered: rampChainCoveredComponents(req, prevLabel, hasPrev),
		KeyID:   signer.KeyID(),
		Alg:     signer.Algorithm(),
		Created: opts.Created,
		Expires: opts.Expires,
	}
	return signWithParams(ctx, req, params, signer, sigWriteAppend)
}

// bindAuthorization ensures the Authorization header is present so the signature
// commits to its value (empty string included) and a later injection cannot
// piggy-back the same signature.
func bindAuthorization(req *http.Request) {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "")
	}
}

// sigWriteMode selects whether signWithParams replaces or appends the emitted
// Signature-Input / Signature headers.
type sigWriteMode int

const (
	sigWriteSet sigWriteMode = iota
	sigWriteAppend
)

// signWithParams builds the signature base for params, signs it via signer, and
// writes the Signature-Input / Signature headers per mode. Shared by SignRequest
// and AppendSignature so base construction and header emission live in one place.
func signWithParams(ctx context.Context, req *http.Request, params sigParams, signer Signer, mode sigWriteMode) error {
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, []byte(base))
	if err != nil {
		return fmt.Errorf("helpers: signer.Sign: %w", err)
	}
	input := params.Label + "=" + signatureInputInner(params)
	value := fmt.Sprintf("%s=:%s:", params.Label, base64.StdEncoding.EncodeToString(sig))
	if mode == sigWriteAppend {
		if existing := req.Header.Get("Signature-Input"); existing != "" {
			input = existing + ", " + input
		}
		if existing := req.Header.Get("Signature"); existing != "" {
			value = existing + ", " + value
		}
	}
	req.Header.Set("Signature-Input", input)
	req.Header.Set("Signature", value)
	return nil
}

// maxSignatureLabelN scans Signature-Input for the highest sigN label and
// returns N (0 when none). Shared by findNextLabel and findPrevLabel.
func maxSignatureLabelN(h http.Header) int {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return 0
	}
	maxN := 0
	for _, labelInput := range parseMultiLabelInput(rawInput) {
		eq := strings.Index(labelInput, "=")
		if eq <= 0 {
			continue
		}
		label := strings.TrimSpace(labelInput[:eq])
		if !strings.HasPrefix(label, "sig") {
			continue
		}
		// Atoi rejects trailing junk (e.g. "sig1x"), unlike Sscanf.
		if num, err := strconv.Atoi(strings.TrimPrefix(label, "sig")); err == nil && num > maxN {
			maxN = num
		}
	}
	return maxN
}

// findNextLabel returns the label for the next appended signature: sig(maxN+1),
// or "sig1" when no signatures exist.
func findNextLabel(h http.Header) string {
	return fmt.Sprintf("sig%d", maxSignatureLabelN(h)+1)
}

// findPrevLabel returns the highest existing sigN label — the predecessor an
// appended signature must chain to — and whether one exists.
func findPrevLabel(h http.Header) (string, bool) {
	maxN := maxSignatureLabelN(h)
	if maxN == 0 {
		return "", false
	}
	return fmt.Sprintf("sig%d", maxN), true
}
