package helpers

// Internal test: the SSRF guard on the built-in WBA HTTP client lives on an
// unexported constructor, so it is exercised from inside the package.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
