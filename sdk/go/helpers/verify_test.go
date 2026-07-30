package helpers_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

const (
	tCreated = int64(1700000000)
	tExpires = int64(1700000300)
)

var tNow = time.Unix(1700000100, 0) // inside [created, expires]

// signResolvedFixture builds a signed request carrying signatureAgent in its
// Signature-Agent header, plus a spy KeyResolver that records the directory the
// SDK threaded into the resolution context. It exists because the
// resolver-context assertions need a keyID the resolver can be seeded with, which
// signFixture does not expose — every such test was otherwise re-inlining the
// same nine-step keygen → signer → request → header → sign → spy sequence.
//
// Returns the signed request, the resolver to hand to a resolved verify
// entrypoint, and a reader for what that resolver saw (meaningful only after the
// verify call has run).
func signResolvedFixture(t *testing.T, body []byte, keyID, signatureAgent string) (
	*http.Request, helpers.KeyResolver, func() string,
) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/Execute", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(helpers.SignatureAgentHeader, signatureAgent)
	if err := helpers.SignRequest(context.Background(), req, body, signer,
		helpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	var captured string
	spy := &signatureAgentSpyResolver{
		delegate: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub}),
		onResolve: func(ctx context.Context, _ string) {
			captured = helpers.SignatureAgentFromContext(ctx)
		},
	}
	return req, spy, func() string { return captured }
}

func signFixture(t *testing.T, body []byte, mutate func(*http.Request)) (*http.Request, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer("agent.v1", priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/ramp.v1.ExchangeService/Execute", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	if err := helpers.SignRequest(context.Background(), req, body, signer, helpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return req, pub
}

func TestVerifyRequest_roundTrip(t *testing.T) {
	body := []byte(`{"offer_id":"of_1"}`)
	req, pub := signFixture(t, body, nil)
	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.KeyID != "agent.v1" || vr.Algorithm != helpers.AlgEd25519 {
		t.Errorf("metadata = %q %q", vr.KeyID, vr.Algorithm)
	}
	if vr.Created != tCreated || vr.Expires != tExpires {
		t.Errorf("window = %d..%d", vr.Created, vr.Expires)
	}
	if !pub.Equal(vr.PublicKey) {
		t.Error("proven key should be echoed back")
	}
}

func TestVerifyRequest_roundTripWithEntitlementToken(t *testing.T) {
	body := []byte("x")
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set("X-Entitlement-Token", "tok")
	})
	if _, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow}); err != nil {
		t.Fatalf("VerifyRequest with entitlement token: %v", err)
	}
}

func TestVerifyRequest_tamperedBody(t *testing.T) {
	body := []byte("original")
	req, pub := signFixture(t, body, nil)
	_, err := helpers.VerifyRequest(req, []byte("tampered"), pub, helpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, helpers.ErrDigestMismatch) {
		t.Errorf("err = %v, want ErrDigestMismatch", err)
	}
}

func TestVerifyRequest_wrongKey(t *testing.T) {
	body := []byte("x")
	req, _ := signFixture(t, body, nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	_, err := helpers.VerifyRequest(req, body, otherPub, helpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, helpers.ErrSignatureVerify) {
		t.Errorf("err = %v, want ErrSignatureVerify", err)
	}
}

func TestVerifyRequest_expired(t *testing.T) {
	body := []byte("x")
	req, pub := signFixture(t, body, nil)
	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: time.Unix(tExpires+1, 0)})
	if !errors.Is(err, helpers.ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyRequest_futureCreated(t *testing.T) {
	body := []byte("x")
	req, pub := signFixture(t, body, nil)
	// Now far before created, beyond the skew window.
	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: time.Unix(tCreated-10000, 0)})
	if !errors.Is(err, helpers.ErrFutureCreated) {
		t.Errorf("err = %v, want ErrFutureCreated", err)
	}
}

func TestVerifyRequest_entitlementInjectionRejected(t *testing.T) {
	// Sign without an entitlement token, then inject the header post-signing. The
	// signature does not cover it, so verification must reject (uncovered token).
	body := []byte("x")
	req, pub := signFixture(t, body, nil)
	req.Header.Set("X-Entitlement-Token", "injected")
	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, helpers.ErrMissingRequiredComponent) {
		t.Errorf("err = %v, want ErrMissingRequiredComponent", err)
	}
}

func TestVerifyRequest_missingHeaders(t *testing.T) {
	body := []byte("x")
	req, err0 := http.NewRequest(http.MethodPost, "https://e.example/x", strings.NewReader("x"))
	if err0 != nil {
		t.Fatal(err0)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, helpers.ErrMissingSignatureInput) {
		t.Errorf("err = %v, want ErrMissingSignatureInput", err)
	}
}

func TestVerifyRequest_shortKey(t *testing.T) {
	body := []byte("x")
	req, _ := signFixture(t, body, nil)
	_, err := helpers.VerifyRequest(req, body, make(ed25519.PublicKey, 10), helpers.VerifyOptions{Now: tNow})
	if err == nil {
		t.Error("short key should error")
	}
}
