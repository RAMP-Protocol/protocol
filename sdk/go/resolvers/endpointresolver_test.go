package resolvers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// manifestHandler serves a /.well-known/ramp.json WellKnownManifest body whose
// top-level "endpoint" (proto field 12) is endpoint. It counts requests so a
// test can prove a cache hit short-circuits the fetch. A nil endpoint omits the
// field entirely, modeling an otherwise-valid manifest with no endpoint.
func manifestHandler(endpoint *string, hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		doc := map[string]any{"role": "ROLE_EXCHANGE"}
		if endpoint != nil {
			doc["endpoint"] = *endpoint
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
}

// hostOf returns the host:port of a httptest server so the host-keyed resolver
// can be driven with the host as its ResolveEndpoint argument (the resolver
// builds {scheme}://{host}/.well-known/ramp.json internally).
func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return u.Host
}

// TestWellKnownEndpointResolver_perHostIsolation is the M1 correction: two
// DISTINCT exchange hosts must resolve to their OWN endpoints from their OWN
// manifests. A single-host-only resolver (or a single shared cache slot) fails
// this — it is the core host-keyed contract the broker's per-request
// Offer.exchange resolution depends on.
func TestWellKnownEndpointResolver_perHostIsolation(t *testing.T) {
	epA := "https://exchange-a.example/ramp.v1.ExchangeService"
	epB := "https://exchange-b.example/ramp.v1.ExchangeService"
	srvA := httptest.NewServer(manifestHandler(&epA, nil))
	defer srvA.Close()
	srvB := httptest.NewServer(manifestHandler(&epB, nil))
	defer srvB.Close()

	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL:    time.Hour,
		Scheme: "http",             // httptest serves plain HTTP; production default is https
		HTTP:   http.DefaultClient, // default is now SSRF-guarded; inject unguarded for loopback
	})

	gotA, err := r.ResolveEndpoint(context.Background(), hostOf(t, srvA))
	if err != nil || gotA != epA {
		t.Fatalf("host A resolve = %q, %v; want %q", gotA, err, epA)
	}
	gotB, err := r.ResolveEndpoint(context.Background(), hostOf(t, srvB))
	if err != nil || gotB != epB {
		t.Fatalf("host B resolve = %q, %v; want %q", gotB, err, epB)
	}
	// Re-resolving host A must still return A's endpoint, never B's — proving
	// the cache is keyed per host and the second host did not clobber the first.
	if again, err := r.ResolveEndpoint(context.Background(), hostOf(t, srvA)); err != nil || again != epA {
		t.Fatalf("host A re-resolve = %q, %v; want %q (per-host cache isolation)", again, err, epA)
	}
}

// TestWellKnownEndpointResolver_cacheHit proves the second resolve for the SAME
// host short-circuits and does not refetch (request-counting handler).
func TestWellKnownEndpointResolver_cacheHit(t *testing.T) {
	ep := "https://exchange.example/ramp.v1.ExchangeService"
	hits := 0
	srv := httptest.NewServer(manifestHandler(&ep, &hits))
	defer srv.Close()

	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL:    time.Hour,
		Scheme: "http",
		HTTP:   http.DefaultClient,
	})
	host := hostOf(t, srv)
	if got, err := r.ResolveEndpoint(context.Background(), host); err != nil || got != ep {
		t.Fatalf("first resolve = %q, %v; want %q", got, err, ep)
	}
	if got, err := r.ResolveEndpoint(context.Background(), host); err != nil || got != ep {
		t.Fatalf("second resolve = %q, %v; want %q", got, err, ep)
	}
	if hits != 1 {
		t.Errorf("fetch hits = %d, want 1 (second resolve cached)", hits)
	}
}

// TestWellKnownEndpointResolver_ttlRefresh injects the clock (Now option) and
// proves TTL expiry triggers a refetch, mirroring keyresolver_test.go.
func TestWellKnownEndpointResolver_ttlRefresh(t *testing.T) {
	ep := "https://exchange.example/ramp.v1.ExchangeService"
	hits := 0
	srv := httptest.NewServer(manifestHandler(&ep, &hits))
	defer srv.Close()

	now := time.Unix(1700000000, 0)
	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL:    time.Minute,
		Scheme: "http",
		Now:    func() time.Time { return now },
		HTTP:   http.DefaultClient,
	})
	host := hostOf(t, srv)
	if _, err := r.ResolveEndpoint(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // expire the cache
	if _, err := r.ResolveEndpoint(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("fetch hits = %d, want 2 (TTL expired -> refetch)", hits)
	}
}

// TestWellKnownEndpointResolver_non200 — a non-200 well-known response is a
// transport failure and must surface as an error (no endpoint returned).
func TestWellKnownEndpointResolver_non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	// Inject an unguarded client: the default is now SSRF-guarded (would refuse the
	// loopback httptest origin); this test exercises the fetch/decode path, not the guard.
	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})
	if got, err := r.ResolveEndpoint(context.Background(), hostOf(t, srv)); err == nil {
		t.Errorf("ResolveEndpoint = %q, nil; want error on non-200", got)
	}
}

// TestWellKnownEndpointResolver_decodeFailure — a malformed body must surface as
// an error, not a silent empty endpoint.
func TestWellKnownEndpointResolver_decodeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	// Inject an unguarded client: the default is now SSRF-guarded (would refuse the
	// loopback httptest origin); this test exercises the fetch/decode path, not the guard.
	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})
	if got, err := r.ResolveEndpoint(context.Background(), hostOf(t, srv)); err == nil {
		t.Errorf("ResolveEndpoint = %q, nil; want error on malformed body", got)
	}
}

// TestWellKnownEndpointResolver_missingEndpointField — a valid manifest that
// simply omits the endpoint field must yield a CLEAR error distinct from a
// transport/decode failure (the endpoint is defined-but-absent, the inert-field
// gap this resolver closes).
func TestWellKnownEndpointResolver_missingEndpointField(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(manifestHandler(nil, &hits)) // valid manifest, no endpoint
	defer srv.Close()

	// Inject an unguarded client: the default is now SSRF-guarded (would refuse the
	// loopback httptest origin); this test exercises the fetch/decode path, not the guard.
	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})
	got, err := r.ResolveEndpoint(context.Background(), hostOf(t, srv))
	if err == nil {
		t.Fatalf("ResolveEndpoint = %q, nil; want error on missing endpoint field", got)
	}
	if hits != 1 {
		t.Errorf("fetch hits = %d, want 1 (manifest fetched once)", hits)
	}
}
