package helpers

// Internal test: the SSRF guard on the built-in WBA HTTP client lives on an
// unexported constructor, so it is exercised from inside the package.

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// TestSSRFBlocked_ReservedRanges pins the reserved/non-public classification,
// including the ranges the old IsPrivate() heuristic missed (SEC-NEW-1): CGNAT,
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
func TestGuardedWBAClientSurfacesNon2xx(t *testing.T) {
	allowLoopbackForWiringTest(t)
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
func TestGuardedWBAClientRefusesRedirectScheme(t *testing.T) {
	allowLoopbackForWiringTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://ftp.internal.example/secret", http.StatusFound)
	}))
	defer srv.Close()

	_, err := newGuardedWBAClient().Get(srv.URL)
	if err == nil {
		t.Fatal("guarded client followed a redirect into a non-http(s) scheme — CheckRedirect did not fire")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("redirect refused for the wrong reason (want SSRF guard): %v", err)
	}
}
