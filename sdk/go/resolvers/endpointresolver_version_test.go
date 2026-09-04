package resolvers_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// versionedManifestHandler serves a manifest with a caller-chosen `ver`. A nil
// ver omits the member entirely, modeling a manifest with no version at all.
func versionedManifestHandler(ver *string, endpoint string, hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		doc := map[string]any{"role": "ROLE_EXCHANGE", "endpoint": endpoint}
		if ver != nil {
			doc["ver"] = *ver
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func newVersionTestResolver() *resolvers.WellKnownEndpointResolver {
	return resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
	})
}

// A manifest at the same major and a higher minor is accepted: a minor revision
// of the manifest is additive, so a reader keeps reading.
func TestWellKnownEndpointResolver_acceptsASameMajorHigherMinor(t *testing.T) {
	ver := "1.1"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versionedManifestHandler(&ver, srv.URL+"/ramp.v1.ExchangeService", nil).ServeHTTP(w, r)
	}))
	defer srv.Close()
	got, err := newVersionTestResolver().ResolveEndpoint(context.Background(), hostOf(t, srv))
	if err != nil {
		t.Fatalf("resolve failed: %v; a same-major manifest must be accepted", err)
	}
	if want := srv.URL + "/ramp.v1.ExchangeService"; got != want {
		t.Errorf("resolve = %q, want %q", got, want)
	}
}

// An unrecognised major is refused with the version verdict, and the refusal is
// not cached: once the origin serves an acceptable document, the next resolve
// succeeds without waiting out a TTL.
func TestWellKnownEndpointResolver_refusesAnUnrecognisedMajorAndDoesNotCacheIt(t *testing.T) {
	ver := "2.0"
	var hits int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versionedManifestHandler(&ver, srv.URL+"/ramp.v1.ExchangeService", &hits).ServeHTTP(w, r)
	}))
	defer srv.Close()
	r := newVersionTestResolver()
	host := hostOf(t, srv)

	got, err := r.ResolveEndpoint(context.Background(), host)
	if err == nil {
		t.Fatalf("resolve returned %q; a 2.0 manifest must be refused", got)
	}
	if !errors.Is(err, resolvers.ErrManifestVersionRefused) {
		t.Errorf("error = %v, want it to carry resolvers.ErrManifestVersionRefused", err)
	}
	if !errors.Is(err, helpers.ErrManifestVersionRefused) {
		t.Errorf("error = %v, want it to carry helpers.ErrManifestVersionRefused too", err)
	}

	ver = helpers.WellKnownManifestVersion
	if _, err := r.ResolveEndpoint(context.Background(), host); err != nil {
		t.Fatalf("resolve after the origin recovered failed: %v; a refusal must not be cached", err)
	}
	if hits != 2 {
		t.Errorf("origin hits = %d, want 2 (the refusal was fetched again, not served from cache)", hits)
	}
}

// A manifest with no `ver` at all is refused before its endpoint is read. The
// endpoint is a perfectly usable one, so the refusal can only be the version gate.
func TestWellKnownEndpointResolver_refusesAManifestWithNoVersion(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versionedManifestHandler(nil, srv.URL+"/ramp.v1.ExchangeService", nil).ServeHTTP(w, r)
	}))
	defer srv.Close()
	got, err := newVersionTestResolver().ResolveEndpoint(context.Background(), hostOf(t, srv))
	if err == nil {
		t.Fatalf("resolve returned %q; a manifest with no ver must be refused", got)
	}
	if !errors.Is(err, resolvers.ErrManifestVersionRefused) {
		t.Errorf("error = %v, want it to carry ErrManifestVersionRefused", err)
	}
	if errors.Is(err, resolvers.ErrNoEndpoint) || errors.Is(err, resolvers.ErrEndpointRefused) {
		t.Errorf("error = %v; the version gate must fire before the endpoint is examined", err)
	}
}

// The version gate precedes the endpoint gate: a wrong-version manifest that ALSO
// advertises no endpoint reports the version, because no other member is read.
func TestWellKnownEndpointResolver_versionGatePrecedesEndpointGate(t *testing.T) {
	ver := "2.0"
	srv := httptest.NewServer(versionedManifestHandler(&ver, "", nil))
	defer srv.Close()
	_, err := newVersionTestResolver().ResolveEndpoint(context.Background(), hostOf(t, srv))
	if !errors.Is(err, resolvers.ErrManifestVersionRefused) {
		t.Fatalf("error = %v, want ErrManifestVersionRefused", err)
	}
	if errors.Is(err, resolvers.ErrNoEndpoint) {
		t.Errorf("error = %v; ErrNoEndpoint must not be reached when the version is refused", err)
	}
}

// A `ver` that is not a JSON string is refused as absent — a VERDICT, the answer
// Python and TS give — rather than failing the decode, which the client tier
// would classify as unreachable and retry forever against a document that will
// not change. The refusal is one sentinel under two names, so either matches.
func TestWellKnownEndpointResolver_refusesANonStringVersionAsAVerdict(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"number", `{"ver":1,"role":"ROLE_EXCHANGE","endpoint":%q}`},
		{"null", `{"ver":null,"role":"ROLE_EXCHANGE","endpoint":%q}`},
		{"object", `{"ver":{"major":1},"role":"ROLE_EXCHANGE","endpoint":%q}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, tc.doc, srv.URL+"/ramp.v1.ExchangeService")
			}))
			defer srv.Close()
			_, err := newVersionTestResolver().ResolveEndpoint(context.Background(), hostOf(t, srv))
			if !errors.Is(err, resolvers.ErrManifestVersionRefused) {
				t.Fatalf("err = %v, want the version verdict: a non-string ver is absent, not a decode failure", err)
			}
			if !errors.Is(err, helpers.ErrManifestVersionRefused) {
				t.Error("the helpers sentinel must match too: it is the same sentinel under two names")
			}
			// Refused AS ABSENT, the wording Python and TS produce for the same
			// document — not as a malformed string spelled from the raw bytes.
			if !strings.Contains(err.Error(), "ver is absent") {
				t.Errorf("err = %v, want a non-string ver reported as absent", err)
			}
		})
	}
}
