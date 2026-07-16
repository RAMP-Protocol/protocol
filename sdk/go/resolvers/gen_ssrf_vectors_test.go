package resolvers

// SSRF-face golden-vector emitter. The shared adversarial address + scheme
// corpora ARE the security policy: the Go classifier (ssrfBlocked / allowedScheme)
// self-checks against the intended verdicts here at generation, and the TS/Python
// transports consume the exact same JSON and assert their classifier agrees — so
// a per-language gap (a missed prefix, an unstripped IPv6 zone, a permitted bad
// scheme) fails the parity suite instead of shipping as a single-language bypass.
//
// Verification no-op by default (asserts the committed files match a fresh emit);
// (re)writes them under RAMP_UPDATE_VECTORS=1. This is TEST INFRASTRUCTURE. It
// lives in the resolvers (L2) package because the SSRF guard it self-checks lives
// here, alongside the transport that applies it.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// ssrfAddressVector is one adversarial address-classification case: the input
// address (as it might arrive resolved) and whether the SSRF guard MUST refuse it.
type ssrfAddressVector struct {
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Blocked bool   `json:"blocked"`
}

// buildSSRFAddressVectors is the shared hostile/benign address corpus. Every
// evasion class the three transports must agree on lives here in one place;
// adding a case forces all three SDKs to handle it. The emitter self-checks that
// the Go classifier (ssrfBlocked) matches the intended verdict, so a Go bug —
// e.g. a zoned-address bypass — fails HERE, at generation.
func buildSSRFAddressVectors(t *testing.T) []ssrfAddressVector {
	cases := []struct {
		name, addr string
		blocked    bool
	}{
		// Benign public — MUST be allowed.
		{"public_v4_dns", "8.8.8.8", false},
		{"public_v4_example", "93.184.216.34", false},
		{"public_v6_cloudflare", "2606:4700:4700::1111", false},
		{"v4mapped_public", "::ffff:8.8.8.8", false}, // unwraps to a public v4
		// RFC 1918 / CGNAT / 0-net / loopback / link-local (v4).
		{"rfc1918_10", "10.0.0.1", true},
		{"rfc1918_172", "172.16.5.5", true},
		{"rfc1918_192", "192.168.1.1", true},
		{"cgnat", "100.64.0.1", true},
		{"zero_net", "0.1.2.3", true},
		{"loopback_v4", "127.0.0.1", true},
		{"link_local_v4_imds", "169.254.169.254", true},
		{"test_net_1", "192.0.2.7", true},
		{"benchmarking", "198.18.0.1", true},
		{"multicast_v4", "224.0.0.1", true},
		{"reserved_240", "240.0.0.1", true},
		{"broadcast", "255.255.255.255", true},
		// IPv6 loopback / ULA / link-local, incl. ZONED forms (SEC3-NEW-1).
		{"loopback_v6", "::1", true},
		{"ula", "fc00::1", true},
		{"link_local_v6", "fe80::1", true},
		{"link_local_v6_zoned", "fe80::1%eth0", true},
		{"ula_imds_zoned", "fd00:ec2::254%1", true},
		{"documentation_v6", "2001:db8::1", true},
		// v6 literals embedding a private v4 — must unwrap and re-check.
		{"v4mapped_private", "::ffff:10.0.0.1", true},
		{"nat64_imds", "64:ff9b::a9fe:a9fe", true}, // 169.254.169.254
		// 6to4 (2002::/16) and IPv4-compatible (::a.b.c.d) — SEC3-NEW-3.
		{"sixtofour_private", "2002:0a00:0001::1", true},
		{"v4compat_private", "::a00:1", true}, // ::10.0.0.1
	}
	out := make([]ssrfAddressVector, 0, len(cases))
	for _, c := range cases {
		a, err := netip.ParseAddr(c.addr)
		if err != nil {
			t.Fatalf("ssrf vector %s: parse %q: %v", c.name, c.addr, err)
		}
		if got := ssrfBlocked(a); got != c.blocked {
			t.Fatalf("ssrf policy drift: %s (%s) ssrfBlocked=%v want %v", c.name, c.addr, got, c.blocked)
		}
		out = append(out, ssrfAddressVector{Name: c.name, Addr: c.addr, Blocked: c.blocked})
	}
	return out
}

// ssrfSchemeVector is one URL-scheme allowlist case. `allowed` is the policy:
// deny-by-default, only http/https may be dialed (initial request AND every
// redirect). All three SDKs assert their scheme check agrees.
type ssrfSchemeVector struct {
	Name    string `json:"name"`
	Scheme  string `json:"scheme"`
	Allowed bool   `json:"allowed"`
}

// buildSSRFSchemeVectors is the shared scheme-allowlist corpus. A denylist is
// unwinnable (ftp/ftps/telnet/gopher/file/data/dict/ldap/…), so the guard is an
// allowlist; this pins it and the Go emitter self-checks allowedScheme.
func buildSSRFSchemeVectors() []ssrfSchemeVector {
	cases := []struct {
		name, scheme string
		allowed      bool
	}{
		{"http", "http", true},
		{"https", "https", true},
		{"https_upper", "HTTPS", true}, // case-insensitive (RFC 3986)
		{"ftp", "ftp", false},
		{"ftps", "ftps", false},
		{"telnet", "telnet", false},
		{"gopher", "gopher", false},
		{"file", "file", false},
		{"data", "data", false},
		{"dict", "dict", false},
		{"ldap", "ldap", false},
	}
	out := make([]ssrfSchemeVector, 0, len(cases))
	for _, c := range cases {
		if got := allowedScheme(c.scheme); got != c.allowed {
			panic(fmt.Sprintf("ssrf scheme drift: %s (%s) allowedScheme=%v want %v", c.name, c.scheme, got, c.allowed))
		}
		out = append(out, ssrfSchemeVector{Name: c.name, Scheme: c.scheme, Allowed: c.allowed})
	}
	return out
}

// ssrfRedirectVector is one redirect-depth case: a chain of `hops` redirects and
// whether the guard MUST refuse to follow it. The cap is deny-by-default and
// SHARED — no SDK may inherit its HTTP library's looser default (~20 hops). The Go
// emitter self-checks redirectChainRefused; the TS/Python transports replay the
// exact same verdicts (predicate parity) AND configure their real clients
// (undici maxRedirections / httpx max_redirects) to the same cap.
type ssrfRedirectVector struct {
	Name    string `json:"name"`
	Hops    int    `json:"hops"`
	Refused bool   `json:"refused"`
}

// buildSSRFRedirectVectors is the shared redirect-depth corpus. A chain is
// followed up to maxWBARedirects hops and refused beyond it; the boundary cases
// (exactly at, one over) are the ones a per-language default would silently get
// wrong. The emitter self-checks the Go predicate so a drift fails HERE.
func buildSSRFRedirectVectors() []ssrfRedirectVector {
	cases := []struct {
		name    string
		hops    int
		refused bool
	}{
		{"no_redirect", 0, false},
		{"one_hop", 1, false},
		{"under_cap", 4, false},
		{"at_cap", maxWBARedirects, false},          // exactly the cap: followed
		{"one_over_cap", maxWBARedirects + 1, true}, // the next hop: refused
		{"library_default_20", 20, true},            // the loose library default must be refused
	}
	out := make([]ssrfRedirectVector, 0, len(cases))
	for _, c := range cases {
		if got := redirectChainRefused(c.hops); got != c.refused {
			panic(fmt.Sprintf("ssrf redirect drift: %s (hops=%d) redirectChainRefused=%v want %v", c.name, c.hops, got, c.refused))
		}
		out = append(out, ssrfRedirectVector{Name: c.name, Hops: c.hops, Refused: c.refused})
	}
	return out
}

// ssrfHostSetVector is one MULTI-ADDRESS host case: the set of addresses a single
// hostname resolves to and whether the guard MUST refuse the WHOLE host. The
// oracle is conservative and single-rule: fail closed if ANY resolved address is
// reserved (so a rebinding / round-robin DNS answer cannot land a later connect on
// the reserved member). The Go emitter self-checks anyAddrBlocked; TS/Python replay it.
type ssrfHostSetVector struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs"`
	Blocked bool     `json:"blocked"`
}

// buildSSRFHostSetVectors is the shared multi-address corpus. The interesting
// cases are the MIXED sets: a hostname that resolves to [public, reserved] must be
// refused outright, matching the conservative single-rule oracle all three SDKs
// converge on. The emitter self-checks anyAddrBlocked against the intended verdict.
func buildSSRFHostSetVectors(t *testing.T) []ssrfHostSetVector {
	cases := []struct {
		name    string
		addrs   []string
		blocked bool
	}{
		{"all_public", []string{"8.8.8.8", "2606:4700:4700::1111"}, false},
		{"single_public", []string{"93.184.216.34"}, false},
		{"single_reserved", []string{"127.0.0.1"}, true},
		{"public_then_loopback", []string{"93.184.216.34", "127.0.0.1"}, true}, // mixed: fail closed
		{"loopback_then_public", []string{"127.0.0.1", "8.8.8.8"}, true},       // order-independent
		{"public_then_imds", []string{"8.8.8.8", "169.254.169.254"}, true},     // rebinding/round-robin evasion
		{"dual_stack_public", []string{"93.184.216.34", "2001:4860:4860::8888"}, false},
		{"public_v6_then_ula", []string{"2606:4700:4700::1111", "fc00::1"}, true},
	}
	out := make([]ssrfHostSetVector, 0, len(cases))
	for _, c := range cases {
		addrs := make([]netip.Addr, 0, len(c.addrs))
		for _, s := range c.addrs {
			a, err := netip.ParseAddr(s)
			if err != nil {
				t.Fatalf("hostset vector %s: parse %q: %v", c.name, s, err)
			}
			addrs = append(addrs, a)
		}
		if got := anyAddrBlocked(addrs); got != c.blocked {
			t.Fatalf("ssrf hostset drift: %s anyAddrBlocked=%v want %v", c.name, got, c.blocked)
		}
		out = append(out, ssrfHostSetVector{Name: c.name, Addrs: c.addrs, Blocked: c.blocked})
	}
	return out
}

// TestGenerateSSRFVectors emits the shared SSRF address + scheme + redirect +
// host-set corpora. Verification no-op by default, (re)writes under
// RAMP_UPDATE_VECTORS=1.
func TestGenerateSSRFVectors(t *testing.T) {
	docs := []struct {
		file string
		doc  any
	}{
		{"ssrf-address-vectors.json", map[string]any{"vectors": buildSSRFAddressVectors(t)}},
		{"ssrf-scheme-vectors.json", map[string]any{"vectors": buildSSRFSchemeVectors()}},
		{"ssrf-redirect-vectors.json", map[string]any{"vectors": buildSSRFRedirectVectors()}},
		{"ssrf-hostset-vectors.json", map[string]any{"vectors": buildSSRFHostSetVectors(t)}},
	}
	for _, d := range docs {
		path := filepath.Join("testdata", d.file)
		want, err := json.MarshalIndent(d.doc, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", path, err)
		}
		want = append(want, '\n')
		if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
			if err := os.WriteFile(path, want, 0o644); err != nil { //nolint:gosec // committed test vector
				t.Fatalf("write %s: %v", path, err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", path)
		}
	}
}
