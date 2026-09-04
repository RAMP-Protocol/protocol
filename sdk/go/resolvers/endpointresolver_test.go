package resolvers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
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
		doc := map[string]any{"ver": helpers.WellKnownManifestVersion, "role": "ROLE_EXCHANGE"}
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

// TestWellKnownEndpointResolver_perHostIsolation verifies per-host isolation: two
// DISTINCT exchange hosts must resolve to their OWN endpoints from their OWN
// manifests. A single-host-only resolver (or a single shared cache slot) fails
// this — it is the core host-keyed contract the broker's per-request
// Offer.exchange resolution depends on.
func TestWellKnownEndpointResolver_perHostIsolation(t *testing.T) {
	// Late-bound: an Exchange advertises ITSELF, so the endpoint is not known
	// until its server has an address. The handler reads it per request.
	var epA, epB string
	srvA := httptest.NewServer(manifestHandler(&epA, nil))
	defer srvA.Close()
	srvB := httptest.NewServer(manifestHandler(&epB, nil))
	defer srvB.Close()
	epA = srvA.URL + "/ramp.v1.ExchangeService"
	epB = srvB.URL + "/ramp.v1.ExchangeService"

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
	var ep string
	hits := 0
	srv := httptest.NewServer(manifestHandler(&ep, &hits))
	defer srv.Close()
	ep = srv.URL + "/ramp.v1.ExchangeService"

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
	var ep string
	hits := 0
	srv := httptest.NewServer(manifestHandler(&ep, &hits))
	defer srv.Close()
	ep = srv.URL + "/ramp.v1.ExchangeService"

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

// The endpoint an Exchange advertises must be on the host that served the
// manifest, or a subdomain of it. The manifest is only as trustworthy as the host
// serving it, so an endpoint pointing anywhere else is one this resolver will not
// hand back — whatever the caller intended to do with it.
//
// Checked HERE rather than in each caller: every consumer needs the rule and none
// can be relied on to remember it, and a dial-time address guard has no objection
// to an unrelated PUBLIC host.
func TestWellKnownEndpointResolver_refusesAnEndpointOnAnotherHost(t *testing.T) {
	cases := map[string]string{
		"unrelated host":       "https://evil.example/ramp.v1.ExchangeService",
		"label-boundary trick": "https://evil-127.0.0.1.example/ramp.v1.ExchangeService",
		"userinfo":             "https://user:pass@127.0.0.1/ramp.v1.ExchangeService",
	}
	for name, ep := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint := ep
			srv := httptest.NewServer(manifestHandler(&endpoint, nil))
			defer srv.Close()

			r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
				TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
			})
			got, err := r.ResolveEndpoint(context.Background(), hostOf(t, srv))
			if err == nil {
				t.Fatalf("resolve returned %q; the endpoint must be refused", got)
			}
			// A VERDICT, not a transport failure: the Exchange answered and the
			// answer is unusable, so a caller classifying retryability must read
			// this as final.
			if !errors.Is(err, resolvers.ErrEndpointRefused) {
				t.Errorf("error = %v, want it to carry ErrEndpointRefused", err)
			}
		})
	}
}

// Credentials are refused even when the endpoint names no scheme, and the value
// that names none is otherwise fine.
//
// Both endpoints below are on the serving host and port, so the only thing that
// can decide either case is the userinfo. That isolation is the point: the pair
// separates "refused for carrying a credential" from "refused for not looking
// like a URL", and only the first is the rule.
//
// It is a regression test. The refusal used to be decided over a plain parse of
// the raw value, where "u:p@host" reads as scheme "u" with no userinfo at all,
// while the anchor check read the same string as https and matched the host — so
// the one shape this refusal exists to stop was the one shape that passed it.
func TestWellKnownEndpointResolver_refusesASchemelessEndpointCarryingCredentials(t *testing.T) {
	// Late-bound: the endpoint is the server's own address, which is not known
	// until it is listening.
	var endpoint string
	srv := httptest.NewServer(manifestHandler(&endpoint, nil))
	defer srv.Close()
	host := hostOf(t, srv)

	newResolver := func() *resolvers.WellKnownEndpointResolver {
		return resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
			TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
		})
	}

	endpoint = "user:pass@" + host + "/ramp.v1.ExchangeService"
	got, err := newResolver().ResolveEndpoint(context.Background(), host)
	if err == nil {
		t.Fatalf("resolve returned %q; an endpoint carrying credentials must be refused", got)
	}
	if !errors.Is(err, resolvers.ErrEndpointRefused) {
		t.Errorf("error = %v, want it to carry ErrEndpointRefused", err)
	}

	// The control. Same shape, same host, no credential — accepted, so the refusal
	// above cannot be read as "a schemeless endpoint is refused".
	endpoint = host + "/ramp.v1.ExchangeService"
	got, err = newResolver().ResolveEndpoint(context.Background(), host)
	if err != nil {
		t.Fatalf("resolve of the credential-free endpoint failed: %v", err)
	}
	if got != endpoint {
		t.Errorf("resolve = %q, want %q", got, endpoint)
	}
}

// The PORT is part of the anchor. An endpoint on another port of the serving host
// is a different service — one the party that published the manifest need not
// control — so it is refused like any other mismatch.
func TestWellKnownEndpointResolver_refusesAnEndpointOnAnotherPort(t *testing.T) {
	// Port 1 is not the manifest server's, and nothing is listening there, so a
	// refusal arriving from anywhere but the rule would show up as a dial error.
	endpoint := "http://127.0.0.1:1/ramp.v1.ExchangeService"
	srv := httptest.NewServer(manifestHandler(&endpoint, nil))
	defer srv.Close()

	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
	})
	got, err := r.ResolveEndpoint(context.Background(), hostOf(t, srv))
	if err == nil {
		t.Fatalf("resolve returned %q; an endpoint on another port must be refused", got)
	}
	if !errors.Is(err, resolvers.ErrEndpointRefused) {
		t.Errorf("error = %v, want it to carry ErrEndpointRefused", err)
	}
}

// A default port written out and the same port left implicit are the SAME port,
// so an operator who spells :443 in full is not refused for spelling. Driven
// through the predicate the resolver uses, since httptest always binds a
// non-default port and a loopback server cannot express the case.
func TestWellKnownEndpointResolver_acceptsAWrittenOutDefaultPort(t *testing.T) {
	for _, tc := range [][2]string{
		{"exchange.example", "https://exchange.example:443/v1"},
		{"exchange.example:443", "https://exchange.example/v1"},
	} {
		anchored, err := helpers.HostAnchored(tc[0], tc[1])
		if err != nil || !anchored {
			t.Errorf("HostAnchored(%q, %q) = %v, %v; want true", tc[0], tc[1], anchored, err)
		}
	}
}

// A subdomain of the serving host IS allowed: an Exchange may delegate to its own
// subdomain, and refusing that would be a rule about names rather than about
// trust. Driven through the predicate the resolver uses, since a loopback server
// cannot serve two hostnames.
func TestWellKnownEndpointResolver_allowsASubdomainOfTheServingHost(t *testing.T) {
	anchored, err := helpers.HostAnchored("exchange.example", "https://api.exchange.example/v1")
	if err != nil || !anchored {
		t.Fatalf("subdomain anchored = %v, %v; want true", anchored, err)
	}
}

// A caller's own deadline bounds its own call, even while a shared fetch for the
// same host is still running.
//
// singleflight is not context-aware, so a coalesced call honours nobody's deadline
// unless each waiter selects on its own. Without that a 200ms caller sits until
// the slow origin answers — which, with an injected client carrying no timeout, is
// however long the origin feels like taking.
func TestWellKnownEndpointResolver_honoursTheCallersOwnDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Defers run last-in-first-out, so release the handler BEFORE closing the
	// server: Close waits on the in-flight request, and the shared fetch carries
	// maxManifestFetch rather than this caller's spent deadline.
	defer srv.Close()
	defer close(release)

	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient, // no timeout, deliberately
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.ResolveEndpoint(ctx, hostOf(t, srv))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a call past its own deadline must fail")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the caller's own deadline to be the reason", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("returned after %v; the caller's deadline was not honoured", elapsed)
	}
}

// ...and the leader walking away does not take the burst with it. The other half
// of the same property: the shared fetch outlives whoever triggered it, so a
// waiter with a live context still gets its answer.
func TestWellKnownEndpointResolver_leaderCancellationDoesNotPoisonWaiters(t *testing.T) {
	var ep string
	gate := make(chan struct{})
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-gate // hold the fetch open until both callers are queued
		_ = json.NewEncoder(w).Encode(map[string]any{"ver": helpers.WellKnownManifestVersion, "endpoint": ep})
	}))
	defer srv.Close()
	ep = srv.URL + "/ramp.v1.ExchangeService"
	host := hostOf(t, srv)

	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
	})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _ = r.ResolveEndpoint(leaderCtx, host) }()

	waited := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond) // queue behind the leader's in-flight call
		_, err := r.ResolveEndpoint(context.Background(), host)
		waited <- err
	}()

	time.Sleep(100 * time.Millisecond)
	cancelLeader() // the leader walks away mid-fetch
	close(gate)    // let the origin answer

	<-done
	if err := <-waited; err != nil {
		t.Fatalf("a waiter with a live context must still get the endpoint: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("origin hit %d times, want 1 — the burst must coalesce", n)
	}
}

// panicTransport panics on every round trip, standing in for an
// application-supplied client that misbehaves.
type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("injected transport exploded")
}

// A panic from an injected seam fails ONE lookup; it does not take the process
// down with it.
//
// The coalescing runs through singleflight.DoChan, and when a call has waiting
// channels singleflight re-raises a panic on a fresh goroutine — `go panic(e)`
// then `select{}` — deliberately, so waiters cannot block forever. Nothing above
// the closure can recover from that, which is why the closure recovers for
// itself. WellKnownOptions.HTTP and .Now are both application code, so this is a
// reachable input rather than a hypothetical.
func TestWellKnownEndpointResolver_survivesAPanickingTransport(t *testing.T) {
	r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		TTL:    time.Hour,
		Scheme: "http",
		HTTP:   &http.Client{Transport: panicTransport{}},
	})

	got, err := r.ResolveEndpoint(context.Background(), "exchange.example")
	if err == nil {
		t.Fatalf("resolve returned %q; a panicking transport must surface as an error", got)
	}
	// The host is named so the failure is attributable, and the panic value is
	// carried so it is diagnosable rather than merely reported.
	if !strings.Contains(err.Error(), "exchange.example") ||
		!strings.Contains(err.Error(), "injected transport exploded") {
		t.Errorf("error = %v, want it to name the host and carry the panic value", err)
	}

	// The resolver is still usable afterwards: a panic must not have poisoned the
	// singleflight key or the cache.
	if _, err := r.ResolveEndpoint(context.Background(), "exchange.example"); err == nil {
		t.Error("the second call must fail the same way, not succeed from a poisoned cache")
	}
}
