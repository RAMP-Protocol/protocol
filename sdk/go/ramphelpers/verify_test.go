package ramphelpers_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

const (
	tCreated = int64(1700000000)
	tExpires = int64(1700000300)
)

var tNow = time.Unix(1700000100, 0) // inside [created, expires]

func signFixture(t *testing.T, body []byte, mutate func(*http.Request)) (*http.Request, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ramphelpers.NewEd25519Signer("agent.v1", priv)
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
	if err := ramphelpers.SignRequest(context.Background(), req, body, signer, ramphelpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return req, pub
}

func TestVerifyRequest_roundTrip(t *testing.T) {
	body := []byte(`{"offer_id":"of_1"}`)
	req, pub := signFixture(t, body, nil)
	vr, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.KeyID != "agent.v1" || vr.Algorithm != ramphelpers.AlgEd25519 {
		t.Errorf("metadata = %q %q", vr.KeyID, vr.Algorithm)
	}
	if vr.Created != tCreated || vr.Expires != tExpires {
		t.Errorf("window = %d..%d", vr.Created, vr.Expires)
	}
	if !pub.Equal(vr.PublicKey) {
		t.Error("proven key should be echoed back")
	}
}

func TestVerifyRequest_roundTripWithBiscuit(t *testing.T) {
	body := []byte("x")
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set("X-RAMP-Entitlement-Biscuit", "tok")
	})
	if _, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{Now: tNow}); err != nil {
		t.Fatalf("VerifyRequest with biscuit: %v", err)
	}
}

func TestVerifyRequest_tamperedBody(t *testing.T) {
	body := []byte("original")
	req, pub := signFixture(t, body, nil)
	_, err := ramphelpers.VerifyRequest(req, []byte("tampered"), pub, ramphelpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, ramphelpers.ErrDigestMismatch) {
		t.Errorf("err = %v, want ErrDigestMismatch", err)
	}
}

func TestVerifyRequest_wrongKey(t *testing.T) {
	body := []byte("x")
	req, _ := signFixture(t, body, nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	_, err := ramphelpers.VerifyRequest(req, body, otherPub, ramphelpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, ramphelpers.ErrSignatureVerify) {
		t.Errorf("err = %v, want ErrSignatureVerify", err)
	}
}

func TestVerifyRequest_expired(t *testing.T) {
	body := []byte("x")
	req, pub := signFixture(t, body, nil)
	_, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{Now: time.Unix(tExpires+1, 0)})
	if !errors.Is(err, ramphelpers.ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyRequest_futureCreated(t *testing.T) {
	body := []byte("x")
	req, pub := signFixture(t, body, nil)
	// Now far before created, beyond the skew window.
	_, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{Now: time.Unix(tCreated-10000, 0)})
	if !errors.Is(err, ramphelpers.ErrFutureCreated) {
		t.Errorf("err = %v, want ErrFutureCreated", err)
	}
}

func TestVerifyRequest_biscuitInjectionRejected(t *testing.T) {
	// Sign without a biscuit, then inject the header post-signing. The signature
	// does not cover it, so verification must reject (uncovered biscuit).
	body := []byte("x")
	req, pub := signFixture(t, body, nil)
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "injected")
	_, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, ramphelpers.ErrMissingRequiredComponent) {
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
	_, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, ramphelpers.ErrMissingSignatureInput) {
		t.Errorf("err = %v, want ErrMissingSignatureInput", err)
	}
}

func TestVerifyRequest_shortKey(t *testing.T) {
	body := []byte("x")
	req, _ := signFixture(t, body, nil)
	_, err := ramphelpers.VerifyRequest(req, body, make(ed25519.PublicKey, 10), ramphelpers.VerifyOptions{Now: tNow})
	if err == nil {
		t.Error("short key should error")
	}
}
