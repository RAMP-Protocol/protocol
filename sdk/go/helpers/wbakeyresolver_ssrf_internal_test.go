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
