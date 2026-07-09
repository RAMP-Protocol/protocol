package helpers_test

// Tests for the VerifiedRequest.SignatureAgent field and the resolver-context
// threading (WithSignatureAgent / SignatureAgentFromContext): a verified request
// carries its signed Signature-Agent value on the result, and a KeyResolver can
// read it from the resolution context during the resolved verify entrypoints.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestVerifyRequest_signatureAgentOnResult pins that a verified request whose
// covered set includes signature-agent carries the header value on the returned
// VerifiedRequest.SignatureAgent field.
func TestVerifyRequest_signatureAgentOnResult(t *testing.T) {
	body := []byte(`{"resource_id":"r3"}`)
	// A non-empty value so the assertion distinguishes the header value from the
	// empty-bind fallback.
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set("Signature-Agent", "https://agent.example")
	})

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.SignatureAgent != "https://agent.example" {
		t.Errorf("SignatureAgent = %q; want %q", vr.SignatureAgent, "https://agent.example")
	}
}

// TestVerifyMultisig_resolverSeesSignatureAgent pins the resolver-context
// threading requirement: a KeyResolver called during multisig resolution must be
// able to read the request's Signature-Agent value from the resolution context
// via helpers.SignatureAgentFromContext — the platform relay path where the
// resolver uses the agent's directory to validate the signing key's provenance.
func TestVerifyMultisig_resolverSeesSignatureAgent(t *testing.T) {
	// Build a signed request with Signature-Agent set.
	body := []byte(`{"resource_id":"r4"}`)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "relay.agent.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/ramp.v1.ExchangeService/Execute", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature-Agent", "https://relay.example")
	if err := helpers.SignRequest(context.Background(), req, body, signer, helpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// A spy KeyResolver that captures the SignatureAgent from resolution context.
	var capturedAgent string
	spyResolver := &signatureAgentSpyResolver{
		delegate: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub}),
		onResolve: func(ctx context.Context, _ string) {
			capturedAgent = helpers.SignatureAgentFromContext(ctx)
		},
	}

	_, err = helpers.VerifyMultisigRequestResolved(context.Background(), req, body, spyResolver, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyMultisigRequestResolved: %v", err)
	}
	if capturedAgent == "" {
		t.Error("KeyResolver.Resolve context had empty SignatureAgent; want 'https://relay.example' pre-threaded by the SDK")
	}
	if capturedAgent != "https://relay.example" {
		t.Errorf("SignatureAgent in resolver context = %q; want %q", capturedAgent, "https://relay.example")
	}
}

// signatureAgentSpyResolver delegates Resolve to a real KeyResolver and calls
// onResolve with the context so a test can inspect what the SDK threaded in.
type signatureAgentSpyResolver struct {
	delegate  helpers.KeyResolver
	onResolve func(ctx context.Context, keyID string)
}

func (s *signatureAgentSpyResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if s.onResolve != nil {
		s.onResolve(ctx, keyID)
	}
	return s.delegate.Resolve(ctx, keyID)
}

var _ helpers.KeyResolver = (*signatureAgentSpyResolver)(nil)

// TestVerifyRequest_signatureAgentEmptyBindAccepted pins that a request WITHOUT
// Signature-Agent set (where bindSignatureAgent binds an empty string "") still
// verifies successfully. The WBA empty-bind semantics (app signer.go:46-52) must
// be mirrored exactly: the signer binds "" so the covered component is always
// satisfiable, and the verifier accepts the empty-string component value.
func TestVerifyRequest_signatureAgentEmptyBindAccepted(t *testing.T) {
	body := []byte(`{"resource_id":"r5"}`)
	// signFixture does not set Signature-Agent — bindSignatureAgent binds "" so
	// the covered component is satisfiable and verify passes.
	req, pub := signFixture(t, body, nil)

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest with empty-bind Signature-Agent: %v", err)
	}
	// Empty bind: SignatureAgent is "" and accessible.
	if vr.SignatureAgent != "" {
		t.Errorf("SignatureAgent = %q; want empty string (empty-bind semantics)", vr.SignatureAgent)
	}
	// Core VerifiedRequest fields are still populated correctly.
	if vr.KeyID != "agent.v1" {
		t.Errorf("KeyID = %q; want %q", vr.KeyID, "agent.v1")
	}
}
