package ramphelpers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

func jwksHandler(keys map[string]ed25519.PublicKey, hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		type jwk struct{ Kid, Kty, Crv, X string }
		doc := struct {
			Keys []jwk `json:"keys"`
		}{}
		for kid, pub := range keys {
			doc.Keys = append(doc.Keys, jwk{kid, "OKP", "Ed25519", base64.RawURLEncoding.EncodeToString(pub)})
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func TestStaticKeyResolver(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	r := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"a.v1": pub})
	got, err := r.Resolve(context.Background(), "a.v1")
	if err != nil || !got.Equal(pub) {
		t.Fatalf("resolve hit: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "missing"); !errors.Is(err, ramphelpers.ErrUnknownKey) {
		t.Errorf("miss err = %v, want ErrUnknownKey", err)
	}
	pub2, _, _ := ed25519.GenerateKey(nil)
	r.Put("b.v1", pub2)
	if got, _ := r.Resolve(context.Background(), "b.v1"); !got.Equal(pub2) {
		t.Error("Put then resolve failed")
	}
}

func TestWellKnownKeyResolver_fetchCacheMiss(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	hits := 0
	srv := httptest.NewServer(jwksHandler(map[string]ed25519.PublicKey{"ex.v1": pub}, &hits))
	defer srv.Close()

	r := ramphelpers.NewWellKnownKeyResolver(srv.URL, ramphelpers.WellKnownOptions{TTL: time.Hour})
	got, err := r.Resolve(context.Background(), "ex.v1")
	if err != nil || !got.Equal(pub) {
		t.Fatalf("resolve: %v", err)
	}
	// Second resolve is cached — no extra fetch.
	if _, err := r.Resolve(context.Background(), "ex.v1"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("fetch hits = %d, want 1 (cached)", hits)
	}
	// Unknown kid (within cache) does not refetch and is unknown.
	if _, err := r.Resolve(context.Background(), "nope"); !errors.Is(err, ramphelpers.ErrUnknownKey) {
		t.Errorf("unknown kid err = %v", err)
	}
}

func TestWellKnownKeyResolver_ttlRefresh(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	hits := 0
	srv := httptest.NewServer(jwksHandler(map[string]ed25519.PublicKey{"ex.v1": pub}, &hits))
	defer srv.Close()

	now := time.Unix(1700000000, 0)
	r := ramphelpers.NewWellKnownKeyResolver(srv.URL, ramphelpers.WellKnownOptions{
		TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	if _, err := r.Resolve(context.Background(), "ex.v1"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // expire the cache
	if _, err := r.Resolve(context.Background(), "ex.v1"); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("fetch hits = %d, want 2 (TTL expired → refetch)", hits)
	}
}

func TestWellKnownKeyResolver_allowlist(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(jwksHandler(map[string]ed25519.PublicKey{"ex.v1": pub}, nil))
	defer srv.Close()
	r := ramphelpers.NewWellKnownKeyResolver(srv.URL, ramphelpers.WellKnownOptions{
		Allow: func(k string) bool { return k == "allowed" },
	})
	if _, err := r.Resolve(context.Background(), "ex.v1"); !errors.Is(err, ramphelpers.ErrUnknownKey) {
		t.Errorf("disallowed key err = %v, want ErrUnknownKey", err)
	}
}

func TestVerifyRequestResolved_endToEnd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := ramphelpers.NewEd25519Signer("ex.v1", priv)
	body := []byte(`{"x":1}`)
	req, _ := http.NewRequest(http.MethodPost, "https://e.example/ramp.v1.S/M", strings.NewReader(string(body)))
	if err := ramphelpers.SignRequest(context.Background(), req, body, signer, ramphelpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatal(err)
	}

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"ex.v1": pub})
	vr, err := ramphelpers.VerifyRequestResolved(context.Background(), req, body, resolver, ramphelpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	if vr.KeyID != "ex.v1" {
		t.Errorf("keyid = %q", vr.KeyID)
	}

	// Unknown signing key → resolver miss surfaces.
	empty := ramphelpers.NewStaticKeyResolver(nil)
	if _, err := ramphelpers.VerifyRequestResolved(context.Background(), req, body, empty, ramphelpers.VerifyOptions{Now: tNow}); !errors.Is(err, ramphelpers.ErrUnknownKey) {
		t.Errorf("unknown key err = %v, want ErrUnknownKey", err)
	}
}
