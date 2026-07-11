package resolvers

// The ONE env-driven, best-effort SSRF-guarded HTTP client factory.
//
// NewGuardedClientFromEnv is the single public construction path every RAMP
// consumer uses for ANY third-party-influenceable fetch (WBA directory, content,
// usage-report POST, well-known probe). Its behavior is driven by two orthogonal
// env flags — nothing else. There is no deployment-stack allow-list, no config
// error, and no deployment policy: an operator opts out of a guard by setting its flag.
//
//   - SKIP_SSRF toggles the dial-time ADDRESS guard. Default off: the client
//     refuses to dial reserved / non-public addresses (SSRFGuard). Set it to
//     reach a private/loopback target (tests, on-prem, compose stacks).
//   - ALLOW_INSECURE toggles the SCHEME guard. Default off: https only. Set it to
//     permit plaintext http.
//
// The two dimensions are independent, so the four flag combinations are:
//
//	SKIP_SSRF ALLOW_INSECURE  address guard  scheme
//	off       off             on            https-only   (production default)
//	off       on              on            http+https
//	on        off             off           https-only
//	on        on              off           http+https   (fully plain)

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	// envSkipSSRF, when truthy, drops the dial-time address guard.
	envSkipSSRF = "SKIP_SSRF"
	// envAllowInsecure, when truthy, permits plaintext http (else https only).
	envAllowInsecure = "ALLOW_INSECURE"
)

// envFlag reads a boolean env flag: true iff the value is "true" (any case) or
// "1". Every other value (including unset and "0") is false.
func envFlag(name string) bool {
	v := os.Getenv(name)
	return strings.EqualFold(v, "true") || v == "1"
}

// skipSSRF reports whether the dial-time address guard is disabled.
func skipSSRF() bool { return envFlag(envSkipSSRF) }

// allowInsecure reports whether plaintext http is permitted.
func allowInsecure() bool { return envFlag(envAllowInsecure) }

// NewGuardedClientFromEnv builds the single env-driven best-effort guarded HTTP
// client. SKIP_SSRF toggles the dial-time address pin; ALLOW_INSECURE toggles the
// https-only scheme guard. Both default to the guarded posture. The guarded
// (non-skip) path dials through a no-proxy transport, so a set HTTP(S)_PROXY
// cannot tunnel a private target past the dial-time address pin.
func NewGuardedClientFromEnv() *http.Client {
	var base http.RoundTripper
	if skipSSRF() {
		base = http.DefaultTransport // no address guard
	} else {
		base = SSRFGuard(nil) // dial-time address pin, no proxy
	}
	return &http.Client{
		Timeout:       defaultWBAHTTPTimeout,
		Transport:     &schemeGuardRoundTripper{base: base},
		CheckRedirect: schemeCheckRedirect,
	}
}

// schemeGuardRoundTripper enforces the scheme policy on the INITIAL request
// before any dial: https is always allowed, plaintext http only under
// ALLOW_INSECURE, every other scheme denied. A denied scheme is refused up front
// with an "SSRF guard" error, so an http target in the default posture never
// reaches the transport.
type schemeGuardRoundTripper struct {
	base http.RoundTripper
}

func (g *schemeGuardRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !schemeGuardAllows(req.URL.Scheme) {
		return nil, fmt.Errorf(
			"resolvers: refusing to dial disallowed scheme %q (SSRF guard)", req.URL.Scheme)
	}
	return g.base.RoundTrip(req)
}

// schemeGuardAllows is the two-flag scheme decision: https always, http only
// under ALLOW_INSECURE, everything else denied (a scheme denylist is unwinnable —
// ftp, ftps, telnet, gopher, file, data, dict, …). Case-insensitive per RFC 3986.
func schemeGuardAllows(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "https":
		return true
	case "http":
		return allowInsecure()
	default:
		return false
	}
}

// schemeCheckRedirect bounds redirect depth and re-vets every redirect target's
// scheme under the SAME two-flag policy (https always, http only under
// ALLOW_INSECURE); the redirect target's ADDRESS is re-pinned automatically by
// the guarded dialer when the address guard is on.
func schemeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxWBARedirects {
		return fmt.Errorf("resolvers: too many redirects (SSRF guard)")
	}
	if !schemeGuardAllows(req.URL.Scheme) {
		return fmt.Errorf(
			"resolvers: refusing redirect to disallowed scheme %q (SSRF guard)", req.URL.Scheme)
	}
	return nil
}
