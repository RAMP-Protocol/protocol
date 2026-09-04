package resolvers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

func jwksHandler(keys map[string]ed25519.PublicKey, hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		// RFC 7517 member names are lowercase (kty/crv/x/kid). The json tags are
		// required: go-jose parses JWK members case-sensitively, so a tag-less
		// struct (capitalized "Kty"/"Crv"/"X") produces a non-RFC document that a
		// spec-conformant parser rejects. The prior hand-rolled decoder accepted it
		// via Go's case-insensitive struct-tag matching — a leniency bug, not a
		// contract; a real well-known endpoint emits lowercase members.
		type jwk struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		}
		doc := struct {
			Keys []jwk `json:"keys"`
		}{}
		for kid, pub := range keys {
			doc.Keys = append(doc.Keys, jwk{kid, "OKP", "Ed25519", base64.RawURLEncoding.EncodeToString(pub)})
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func TestWellKnownKeyResolver_fetchCacheMiss(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	hits := 0
	srv := httptest.NewServer(jwksHandler(map[string]ed25519.PublicKey{"ex.v1": pub}, &hits))
	defer srv.Close()

	r := resolvers.NewWellKnownKeyResolver(srv.URL, resolvers.WellKnownOptions{TTL: time.Hour})
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
	if _, err := r.Resolve(context.Background(), "nope"); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Errorf("unknown kid err = %v", err)
	}
}

func TestWellKnownKeyResolver_ttlRefresh(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	hits := 0
	srv := httptest.NewServer(jwksHandler(map[string]ed25519.PublicKey{"ex.v1": pub}, &hits))
	defer srv.Close()

	now := time.Unix(1700000000, 0)
	r := resolvers.NewWellKnownKeyResolver(srv.URL, resolvers.WellKnownOptions{
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
	r := resolvers.NewWellKnownKeyResolver(srv.URL, resolvers.WellKnownOptions{
		Allow: func(k string) bool { return k == "allowed" },
	})
	if _, err := r.Resolve(context.Background(), "ex.v1"); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Errorf("disallowed key err = %v, want ErrUnknownKey", err)
	}
}

// The manifest version gate is the endpoint face's alone. A key document is a
// plain JWK Set, not a manifest: it carries no WellKnownManifest.ver, and one that
// happens to carry a `ver` the endpoint face would refuse still resolves keys.
// This pins that decision — moving the gate into the shared fetch fails here.
func TestWellKnownKeyResolver_isNotGatedOnAManifestVersion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	x := base64.RawURLEncoding.EncodeToString(pub)
	for _, tc := range []struct{ name, verMember string }{
		{"no ver", ""},
		{"unrecognised major", `"ver":"2.0",`},
		{"non-string ver", `"ver":1,`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{%s"keys":[{"kid":"ex.v1","kty":"OKP","crv":"Ed25519","x":%q}]}`, tc.verMember, x)
			}))
			defer srv.Close()
			r := resolvers.NewWellKnownKeyResolver(srv.URL, resolvers.WellKnownOptions{TTL: time.Hour})
			got, err := r.Resolve(context.Background(), "ex.v1")
			if err != nil || !got.Equal(pub) {
				t.Fatalf("resolve = %v, %v; a key document is not gated on a manifest version", got, err)
			}
		})
	}
}
