package ramphelpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
)

// AlgEd25519 is the RFC 9421 alg value for Ed25519 signatures.
const AlgEd25519 = "ed25519"

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
		return nil, fmt.Errorf("ramphelpers: signer keyID is empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ramphelpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return &ed25519Signer{keyID: keyID, priv: priv}, nil
}

// NewEd25519SignerFromSeed builds a Signer from a 32-byte Ed25519 seed.
func NewEd25519SignerFromSeed(keyID string, seed []byte) (Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ramphelpers: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
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
		return fmt.Errorf("ramphelpers: nil signer")
	}
	req.Header.Set("Content-Digest", ContentDigest(body))
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "")
	}

	params := sigParams{
		Label:   "sig1",
		Covered: coveredFor(req),
		KeyID:   signer.KeyID(),
		Alg:     signer.Algorithm(),
		Created: opts.Created,
		Expires: opts.Expires,
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, []byte(base))
	if err != nil {
		return fmt.Errorf("ramphelpers: signer.Sign: %w", err)
	}
	req.Header.Set("Signature-Input", "sig1="+signatureInputInner(params))
	req.Header.Set("Signature", fmt.Sprintf("sig1=:%s:", base64.StdEncoding.EncodeToString(sig)))
	return nil
}
