package helpers_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestStaticKeyResolver(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	r := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"a.v1": pub})
	got, err := r.Resolve(context.Background(), "a.v1")
	if err != nil || !got.Equal(pub) {
		t.Fatalf("resolve hit: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "missing"); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Errorf("miss err = %v, want ErrUnknownKey", err)
	}
	pub2, _, _ := ed25519.GenerateKey(nil)
	r.Put("b.v1", pub2)
	if got, _ := r.Resolve(context.Background(), "b.v1"); !got.Equal(pub2) {
		t.Error("Put then resolve failed")
	}
}

func TestVerifyRequestResolved_endToEnd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := helpers.NewEd25519Signer("ex.v1", priv)
	body := []byte(`{"x":1}`)
	req, _ := http.NewRequest(http.MethodPost, "https://e.example/ramp.v1.S/M", strings.NewReader(string(body)))
	if err := helpers.SignRequest(context.Background(), req, body, signer, helpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatal(err)
	}

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"ex.v1": pub})
	vr, err := helpers.VerifyRequestResolved(context.Background(), req, body, resolver, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	if vr.KeyID != "ex.v1" {
		t.Errorf("keyid = %q", vr.KeyID)
	}

	// Unknown signing key → resolver miss surfaces.
	empty := helpers.NewStaticKeyResolver(nil)
	if _, err := helpers.VerifyRequestResolved(context.Background(), req, body, empty, helpers.VerifyOptions{Now: tNow}); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Errorf("unknown key err = %v, want ErrUnknownKey", err)
	}
}
