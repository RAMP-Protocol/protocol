package resolvers

// Internal real-dial tests for the ONE env-driven best-effort SSRF-guarded HTTP
// client factory. NewGuardedClientFromEnv is the single public construction path
// the app consumes; these pin its two-flag contract:
//
//   - SKIP_SSRF toggles the dial-time ADDRESS guard (default: on).
//   - ALLOW_INSECURE toggles the SCHEME guard (default: https-only).
//
// The two dimensions are orthogonal, so each pillar sets the OTHER flag to the
// permissive value to isolate the dimension under test. These are the reference
// pillars the Python and TS SDK suites mirror 1:1.
//
// Real-dial ONLY (httptest on 127.0.0.1) — a transport mock replaces the very
// dial seam the guard runs in, so a success against a mock would prove the guard
// is absent.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGuardedClientBlocksLoopbackByDefault: with the address guard on (SKIP_SSRF
// unset) the factory client refuses a loopback target at the dial seam. ALLOW_INSECURE
// is set so the http scheme is not the refuser — the ADDRESS guard is isolated.
func TestGuardedClientBlocksLoopbackByDefault(t *testing.T) {
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, gerr := NewGuardedClientFromEnv().Get(srv.URL); gerr == nil {
		t.Fatal("guarded client dialed a loopback target — the SSRF guard did not fire")
	} else if !strings.Contains(gerr.Error(), "SSRF guard") {
		t.Fatalf("dial failed for the wrong reason (want SSRF guard): %v", gerr)
	}
}

// TestSkipSSRFReachesLoopback: with SKIP_SSRF set the address guard steps aside
// and the client reaches the loopback origin. ALLOW_INSECURE is set so the http
// scheme is permitted — proving SKIP_SSRF alone drops the address pin.
func TestSkipSSRFReachesLoopback(t *testing.T) {
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, gerr := NewGuardedClientFromEnv().Get(srv.URL) // srv.URL == http://127.0.0.1:<port>
	if gerr != nil {
		t.Fatalf("SKIP_SSRF did not take effect — loopback GET failed: %v", gerr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestRefusesHTTPByDefault: with ALLOW_INSECURE unset a plaintext http:// target
// is refused for SCHEME. SKIP_SSRF is set so the ADDRESS check cannot be the
// refuser — only the https-only scheme policy can — proving http is refused on
// its own, not merely because the target is loopback.
func TestRefusesHTTPByDefault(t *testing.T) {
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, gerr := NewGuardedClientFromEnv().Get(srv.URL); gerr == nil { // srv.URL is http://
		t.Fatal("default-posture client dialed a plaintext http:// target — the https-only scheme policy did not fire")
	} else if !strings.Contains(gerr.Error(), "SSRF guard") {
		t.Fatalf("http refused for the wrong reason (want SSRF guard): %v", gerr)
	}
}

// TestAllowInsecurePermitsHTTP: with ALLOW_INSECURE set a plaintext http:// target
// is reached. SKIP_SSRF is set so the address guard is out of the way — proving
// ALLOW_INSECURE alone permits the http scheme.
func TestAllowInsecurePermitsHTTP(t *testing.T) {
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, gerr := NewGuardedClientFromEnv().Get(srv.URL) // srv.URL is http://
	if gerr != nil {
		t.Fatalf("ALLOW_INSECURE did not take effect — http GET failed: %v", gerr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestGuardedClientNoProxyTunnel: with the address guard on and HTTP(S)_PROXY set,
// the guarded client must NOT tunnel past the dial guard — a proxied CONNECT would
// defeat the dial-time IP pin. ALLOW_INSECURE is set so the http scheme reaches the
// transport and the ADDRESS/proxy dimension is isolated; a loopback target stays refused.
func TestGuardedClientNoProxyTunnel(t *testing.T) {
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "true")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, gerr := NewGuardedClientFromEnv().Get(srv.URL); gerr == nil {
		t.Fatal("a set HTTP(S)_PROXY tunneled a loopback target past the dial guard")
	} else if !strings.Contains(gerr.Error(), "SSRF guard") {
		t.Fatalf("dial refused for the wrong reason (want SSRF guard): %v", gerr)
	}
}
