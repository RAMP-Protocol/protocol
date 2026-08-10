package resolvers

// Internal test: the SSRF guard on the built-in WBA HTTP client lives on an
// unexported constructor, so it is exercised from inside the package.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestSSRFBlocked_ReservedRanges pins the reserved/non-public classification,
// including the ranges the old IsPrivate() heuristic missed: CGNAT,
// 0.0.0.0/8, and the v4-mapped / NAT64 forms that embed a private v4.
func TestSSRFBlocked_ReservedRanges(t *testing.T) {
	blocked := []string{
		"0.1.2.3",            // 0.0.0.0/8 non-zero host
		"10.0.0.1",           // RFC 1918
		"100.64.0.1",         // CGNAT — missed by IsPrivate()
		"127.0.0.1",          // loopback
		"169.254.169.254",    // link-local / cloud metadata
		"172.16.5.5",         // RFC 1918
		"192.168.1.1",        // RFC 1918
		"198.18.0.1",         // benchmarking
		"192.0.2.7",          // TEST-NET-1
		"::1",                // v6 loopback
		"fc00::1",            // ULA
		"fe80::1",            // v6 link-local
		"::ffff:169.254.1.1", // v4-mapped link-local — must unwrap
		"::ffff:10.0.0.1",    // v4-mapped RFC 1918
		"64:ff9b::a9fe:a9fe", // NAT64-embedded 169.254.169.254 — must unwrap
		"64:ff9b::0a00:0001", // NAT64-embedded 10.0.0.1
		"2001:db8::1",        // documentation
	}
	for _, s := range blocked {
		if !ssrfBlocked(netip.MustParseAddr(s)) {
			t.Errorf("ssrfBlocked(%s) = false, want blocked", s)
		}
	}
	allowed := []string{
		"8.8.8.8",              // public v4
		"1.1.1.1",              // public v4
		"93.184.216.34",        // public v4 (example.com)
		"2606:4700:4700::1111", // public v6 (cloudflare)
	}
	for _, s := range allowed {
		if ssrfBlocked(netip.MustParseAddr(s)) {
			t.Errorf("ssrfBlocked(%s) = true, want allowed", s)
		}
	}
}

// TestGuardedWBAClientBlocksLoopback: the default (caller-injected-none) client
// must refuse to dial a loopback/private target. The WBA directory host is a
// caller-supplied Signature-Agent fetched BEFORE the ed25519 check, so an
// unguarded default is a pre-auth SSRF lever. httptest servers listen on
// 127.0.0.1, so a successful GET here would prove the guard is absent.
func TestGuardedWBAClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := newGuardedWBAClient().Get(srv.URL) // srv.URL == http://127.0.0.1:<port>
	if err == nil {
		t.Fatal("guarded client dialed a loopback target — the SSRF guard did not fire")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("dial failed for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestNewWBAKeyResolverDefaultsToGuardedClient: constructing without opts.HTTP
// installs the guarded client (not http.DefaultClient), so the SSRF default is
// on unless the caller opts out by injecting their own client.
func TestNewWBAKeyResolverDefaultsToGuardedClient(t *testing.T) {
	r := NewWBAKeyResolver(WBAKeyResolverOptions{})
	if r.http == http.DefaultClient {
		t.Fatal("WBAKeyResolver fell back to http.DefaultClient — the SSRF guard is bypassed by default")
	}
	if r.http == nil {
		t.Fatal("WBAKeyResolver has no HTTP client")
	}
}

// TestNewWellKnownEndpointResolverDefaultsToGuardedClient: the endpoint resolver's
// host is request-derived (a per-request Offer.exchange), so constructing without
// opts.HTTP must install the SSRF-guarded client — a guarded client refuses a
// loopback target, so a loopback GET through the default must fail with an SSRF
// error (never reach the httptest origin).
func TestNewWellKnownEndpointResolverDefaultsToGuardedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	// Scheme "http" so the scheme guard is not the refuser; the ADDRESS guard must
	// refuse the loopback host on its own.
	t.Setenv("ALLOW_INSECURE", "true")
	r := NewWellKnownEndpointResolver(WellKnownOptions{Scheme: "http"})
	if _, err := r.ResolveEndpoint(t.Context(), u.Host); err == nil {
		t.Fatal("endpoint resolver default reached a loopback target — it did not install the SSRF-guarded client")
	}
}

// TestSSRFGuardNilsProxy: a base transport carrying a Proxy would tunnel the dial
// to the PROXY, so the dial-time address check would vet the proxy's IP instead of
// the true target — a full bypass. SSRFGuard must force Proxy=nil, so a guarded
// client built over a proxied base still refuses a loopback (internal) target at
// the dial seam rather than tunneling to the proxy.
func TestSSRFGuardNilsProxy(t *testing.T) {
	proxyURL, _ := url.Parse("http://127.0.0.1:9") // a proxy that must never be used
	base := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	guarded := SSRFGuard(base)
	if guarded.Proxy != nil {
		t.Fatal("SSRFGuard did not nil the base transport's Proxy — a proxied CONNECT could tunnel past the dial guard")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := &http.Client{Transport: guarded}
	if _, err := client.Get(srv.URL); err == nil { // srv.URL is loopback
		t.Fatal("guarded client over a proxied base reached a loopback target — Proxy was honored, bypassing the dial guard")
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("dial refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestSSRFGuardNilsCustomTLSDialers: net/http prefers a transport's own TLS
// dialer over DialContext for https, so a base carrying DialTLSContext (or the
// legacy DialTLS) would take the dial through the caller's dialer and the
// address pin would never run — on https, which is every RAMP leg. SSRFGuard
// must clear both, so a guarded client built over such a base still refuses a
// loopback target at the dial seam.
//
// The base also carries the server's own TLS config, which is what a caller
// customising TLS legitimately supplies: that must keep working, and only the
// dialer is dropped.
func TestSSRFGuardNilsCustomTLSDialers(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig

	base := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, tlsCfg)
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, tlsCfg)
		},
	}
	guarded := SSRFGuard(base)
	if guarded.DialTLSContext != nil || guarded.DialTLS != nil {
		t.Fatal("SSRFGuard left a custom TLS dialer installed — net/http prefers it over DialContext on https, so the address pin never runs")
	}
	if guarded.TLSClientConfig == nil {
		t.Error("SSRFGuard dropped the caller's TLS config; only the dialer is mutually exclusive with the pin")
	}
	client := &http.Client{Transport: guarded}
	if _, err := client.Get(srv.URL); err == nil { // srv.URL is loopback
		t.Fatal("guarded client over a base with a custom TLS dialer reached a loopback target — the dial guard was bypassed")
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("dial refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestGuardedClientRedirectDepthCap: the guarded client follows at most
// maxWBARedirects redirect hops and refuses the next — the real-dial confirmation
// that the client honors the shared redirect corpus (a chain exactly at the cap is
// followed to its 200 terminal; one hop over is refused with an SSRF error). This
// pins the cap so no future change silently inherits net/http's larger default.
func TestGuardedClientRedirectDepthCap(t *testing.T) {
	allowLoopbackForWiringTest(t)
	// The chain is plaintext http on loopback; opt out of the scheme guard so the
	// refusal under test is the depth cap. The scheme decision is pinned separately
	// by TestGuardedWBAClientRefusesPlaintextByDefault.
	t.Setenv(envAllowInsecure, "1")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /n redirects to /(n-1); /0 is the terminal 200.
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if n <= 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, srv.URL+"/"+strconv.Itoa(n-1), http.StatusFound)
	}))
	defer srv.Close()

	// Exactly at the cap: all maxWBARedirects hops followed to the 200 terminal.
	resp, err := newGuardedWBAClient().Get(srv.URL + "/" + strconv.Itoa(maxWBARedirects))
	if err != nil {
		t.Fatalf("a chain of %d redirects (at the cap) was refused, want followed: %v", maxWBARedirects, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("at-cap chain StatusCode = %d, want 200", resp.StatusCode)
	}

	// One hop over the cap: refused.
	if _, err := newGuardedWBAClient().Get(srv.URL + "/" + strconv.Itoa(maxWBARedirects+1)); err == nil {
		t.Fatalf("a chain of %d redirects (one over the cap) was followed, want refused", maxWBARedirects+1)
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("over-cap chain refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// allowLoopbackForWiringTest temporarily empties the reserved-prefix table so a
// wiring test can reach a 127.0.0.1 httptest origin THROUGH the real guarded
// client (whose dialer would otherwise refuse loopback — see
// TestGuardedWBAClientBlocksLoopback). It restores the table on cleanup. This is
// the transport-wiring seam the cross-language behavioral tests share: the
// address decision is corpus-locked elsewhere; here we prove the client's
// non-address wiring (status surfacing, redirect scheme re-vet) behaves.
func allowLoopbackForWiringTest(t *testing.T) {
	t.Helper()
	saved := ssrfBlockedPrefixes
	ssrfBlockedPrefixes = nil
	t.Cleanup(func() { ssrfBlockedPrefixes = saved })
}

// TestGuardedWBAClientSurfacesNon2xx: a non-2xx directory response must surface
// as an ordinary (StatusCode, nil-error) response, never a transport error — the
// resolver classifies the status itself (a 404 directory is "unknown key", not an
// outage). Parity with the Python (fetch_soft→None / fetch_strict→outage) and TS
// (fetchStrict→DirectoryUnavailable) non-2xx behavioral tests; Go's path is stock
// net/http, so this locks the contract rather than guarding custom wiring (the
// non-2xx crash that motivated this suite was Python's hand-built opener).
func TestGuardedClientSurfacesNon2xx(t *testing.T) {
	allowLoopbackForWiringTest(t)
	// The httptest origin is plaintext http, which the client refuses unless
	// ALLOW_INSECURE is set. Opt out of the guard that is not under test, the same
	// way allowLoopbackForWiringTest opts out of the address table: what this test
	// proves is status surfacing, and either guard would mask it.
	t.Setenv(envAllowInsecure, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resp, err := newGuardedWBAClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("non-2xx surfaced as a transport error, want a 404 response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("StatusCode = %d, want 404", resp.StatusCode)
	}
}

// TestGuardedWBAClientRefusesRedirectScheme: a 302 into a non-http(s) scheme
// (ftp/…) must be refused by CheckRedirect BEFORE any dial to it — the guard is a
// deny-by-default scheme allowlist, not an ftp-specific block (telnet, gopher,
// file, data all follow the same rule). Parity with the Python
// test_guarded_fetch_refuses_redirect_to_ftp behavioral test. Exercises the real
// newGuardedWBAClient CheckRedirect; the ftp target is never contacted.
func TestGuardedClientRefusesRedirectScheme(t *testing.T) {
	allowLoopbackForWiringTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://ftp.internal.example/secret", http.StatusFound)
	}))
	defer srv.Close()

	// The initial hop is plaintext http on loopback; newGuardedWBAClient allows
	// http+https so the request reaches the redirect. ftp is denied on EVERY hop
	// regardless, so this proves redirect scheme re-vetting.
	_, err := newGuardedWBAClient().Get(srv.URL)
	if err == nil {
		t.Fatal("guarded client followed a redirect into a non-http(s) scheme — CheckRedirect did not fire")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("redirect refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestGuardedWBAClientRefusesPlaintextByDefault pins the scheme half of the
// default client's posture, which arrived late: this client predates the scheme
// guard, and the change that introduced the guard shared the address classifier
// with this resolver while leaving the scheme policy behind. The directory fetch
// is the most exposed fetch in the SDK — the host comes from an unauthenticated
// header and the GET runs before the signature check — so it was the one place
// the documented "https unless opted out" posture did not hold.
//
// The address table is emptied so the refusal under test is the scheme one, not
// loopback being blocked.
func TestGuardedWBAClientRefusesPlaintextByDefault(t *testing.T) {
	allowLoopbackForWiringTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := newGuardedWBAClient().Get(srv.URL); err == nil {
		t.Fatal("plaintext http directory fetched in the default posture; want a refusal")
	}
}

// TestGuardedWBAClientAllowsPlaintextWhenOptedIn is the other half: a deployment
// serving directories over plaintext — a compose stack, an on-prem lab — sets the
// same flag it already sets for every other fetch, and the fetch proceeds. Without
// this the refusal above could be satisfied by a client that never fetches at all.
func TestGuardedWBAClientAllowsPlaintextWhenOptedIn(t *testing.T) {
	allowLoopbackForWiringTest(t)
	t.Setenv(envAllowInsecure, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := newGuardedWBAClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("ALLOW_INSECURE set but the fetch was still refused: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestGuardedWBAClientAddressGuardIsNotOptOutable pins the deliberate asymmetry
// with NewGuardedClientFromEnv. That client lets SKIP_SSRF switch its dial-time
// address pin off; this one must not, because the host it dials is attacker-chosen
// and unauthenticated. Adopting the scheme half of the env policy must not have
// dragged the address escape hatch along with it.
func TestGuardedWBAClientAddressGuardIsNotOptOutable(t *testing.T) {
	t.Setenv(envSkipSSRF, "1")
	t.Setenv(envAllowInsecure, "1")
	// No allowLoopbackForWiringTest: the address table stays in force.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := newGuardedWBAClient().Get(srv.URL); err == nil {
		t.Fatal("SKIP_SSRF disabled the address guard on the directory fetch; it must not be opt-outable here")
	}
}
