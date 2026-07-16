package helpers_test

// Structural IO-leaf guard for the pure L1 helpers tree — the Go analogue of the
// Python (test_guards_resolvers_io_leaf) and TS (resolvers-io-leaf.guard) guards,
// which fail the build on an httpx / undici import in the transport-neutral core.
//
// sdk/go/helpers is the SDK's pure, IO-FREE protocol-mechanics tier: RFC 7638
// thumbprint, signed-URL verify, RFC 9421 sign/verify + PoP, offer-acceptance,
// cross-field validation. It legitimately uses net/http REQUEST TYPES
// (http.Header, *http.Request) to canonicalize/verify signatures, but it MUST NOT
// DIAL — no HTTP client, no socket. All dialing lives one tier up, in
// sdk/go/resolvers (the fetching faces), behind the SSRF guard. A helpers file that
// pulled in http.Client / http.Get / net.Dial / an http.Transport would drag the
// pre-auth-reachable network surface into the trust core — exactly the regression
// this guard bans, matching the other two SDKs' io-leaf guards.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenDialingTokens are the DIAL/socket surfaces a pure-tier file must not
// use. Each is matched precisely so the legitimate request-TYPE surface
// (http.Header, http.Request) is NOT flagged — e.g. "http.Head(" carries the
// paren so it never matches "http.Header".
var forbiddenDialingTokens = []string{
	"http.Client",
	"http.DefaultClient",
	"http.DefaultTransport",
	"http.Transport",
	"http.RoundTripper",
	"http.Get(",
	"http.Post(",
	"http.PostForm(",
	"http.Head(",
	"http.NewRequest", // constructs a request to SEND (dialing intent)
	"net.Dial",
	"net.Listen",
	".RoundTrip(",
}

// importsDialingSurface is the pure predicate (extracted so meta-tests can
// exercise it): a pure-tier file leaks IO if it names any dialing/socket surface.
func importsDialingSurface(source string) bool {
	for _, tok := range forbiddenDialingTokens {
		if strings.Contains(source, tok) {
			return true
		}
	}
	return false
}

func pureHelperSources(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob helpers sources: %v", err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		out = append(out, m)
	}
	return out
}

func TestHelpersIoLeafGuard_NoDialingSurface(t *testing.T) {
	sources := pureHelperSources(t)
	if len(sources) == 0 {
		t.Fatal("no helpers sources found — the io-leaf guard would vacuously pass")
	}
	for _, name := range sources {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if importsDialingSurface(string(b)) {
			t.Errorf("pure helpers file %s names a DIALING/socket surface — the trust core must open no sockets; move any fetch into sdk/go/resolvers behind the SSRF guard", name)
		}
	}
}

// --- meta-tests: exercise the detector against synthetic source ---------------

func TestHelpersIoLeafGuard_MetaPositive(t *testing.T) {
	for _, src := range []string{
		"c := http.Client{}",
		"resp, _ := http.Get(url)",
		"conn, _ := net.Dial(\"tcp\", addr)",
		"t := &http.Transport{}",
		"http.DefaultClient.Do(req)",
	} {
		if !importsDialingSurface(src) {
			t.Errorf("detector missed a dialing surface: %q", src)
		}
	}
}

func TestHelpersIoLeafGuard_MetaNegative(t *testing.T) {
	// The legitimate request-TYPE surface must NOT be flagged.
	for _, src := range []string{
		"func f(h http.Header) {}",
		"func g(r *http.Request) {}",
		"h.Get(\"Signature\")", // http.Header.Get, not http.Get
	} {
		if importsDialingSurface(src) {
			t.Errorf("detector false-positived on a pure request-type use: %q", src)
		}
	}
}
