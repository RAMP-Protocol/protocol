package helpers_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestHostRuleRunsUnderStrictHostColons pins the toolchain property the corpus is
// generated under, because the predicates' answers depend on it.
//
// net/url's host-colon strictness is a GODEBUG, urlstrictcolons, and it defaults on
// only for modules declaring go >= 1.26. Under an older directive
// url.Parse("https://exchange.example::443") SUCCEEDS, so IsBareHost answers true
// where the committed vector — and both ports — say the reference is not a host.
//
// This module declares 1.26, so there is no live divergence. The guard is here for
// the two ways one could arrive: a consumer building sdk/go/helpers from a module on
// an older directive gets a different rule than the corpus publishes, and a
// RAMP_UPDATE_VECTORS=1 run under such a module would quietly rewrite the goldens to
// the looser answer rather than fail. It is asserted behaviourally rather than by
// reading the GODEBUG, because the behaviour is the thing that matters and
// internal/godebug is not importable.
func TestHostRuleRunsUnderStrictHostColons(t *testing.T) {
	const doubled = "https://exchange.example::443"
	if _, err := url.Parse(doubled); err == nil {
		t.Fatalf("url.Parse(%q) succeeded: this toolchain is running with "+
			"godebug urlstrictcolons=0, under which the host predicates admit references "+
			"the committed vectors and both ports refuse. Build with a go directive of "+
			"1.26 or later, and do not regenerate the corpora from here.", doubled)
	}
}

func TestIsBareHost(t *testing.T) {
	tests := map[string]struct {
		ref     string
		want    bool
		wantErr bool
	}{
		"plain domain":             {"exchange.example", true, false},
		"subdomain":                {"eu.exchange.example", true, false},
		"host with port":           {"exchange.example:8443", true, false},
		"trailing root dot":        {"exchange.example.", true, false},
		"https scheme":             {"https://exchange.example", false, false},
		"http scheme":              {"http://exchange.example", false, false},
		"path":                     {"exchange.example/reports", false, false},
		"root path":                {"exchange.example/", false, false},
		"query":                    {"exchange.example?x=1", false, false},
		"fragment":                 {"exchange.example#frag", false, false},
		"userinfo":                 {"agent@exchange.example", false, false},
		"scheme and path":          {"https://exchange.example/v1", false, false},
		"trailing colon":           {"exchange.example:", false, false},
		"empty":                    {"", false, true},
		"whitespace":               {"   ", false, true},
		"control character in ref": {"exchange.example\n", false, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := helpers.IsBareHost(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("IsBareHost(%q) = %v, want an error", tc.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("IsBareHost(%q): %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("IsBareHost(%q) = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

func TestHostAnchored(t *testing.T) {
	tests := map[string]struct {
		anchor    string
		candidate string
		want      bool
		wantErr   bool
	}{
		"same host":                   {"a.com", "a.com", true, false},
		"subdomain":                   {"a.com", "cdn.a.com", true, false},
		"deep subdomain":              {"a.com", "x.y.a.com", true, false},
		"candidate is a url":          {"a.com", "https://cdn.a.com/v1/reports", true, false},
		"anchor is a url":             {"https://a.com", "cdn.a.com", true, false},
		"case insensitive":            {"A.com", "CDN.a.COM", true, false},
		"trailing root dot":           {"a.com.", "cdn.a.com.", true, false},
		"label boundary not a prefix": {"a.com", "evil-a.com", false, false},
		"suffix without boundary":     {"a.com", "xa.com", false, false},
		"unrelated host":              {"a.com", "b.com", false, false},
		"parent is not anchored":      {"cdn.a.com", "a.com", false, false},
		"empty anchor":                {"", "a.com", false, true},
		"empty candidate":             {"a.com", "", false, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := helpers.HostAnchored(tc.anchor, tc.candidate)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("HostAnchored(%q, %q) = %v, want an error", tc.anchor, tc.candidate, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("HostAnchored(%q, %q): %v", tc.anchor, tc.candidate, err)
			}
			if got != tc.want {
				t.Errorf("HostAnchored(%q, %q) = %v, want %v", tc.anchor, tc.candidate, got, tc.want)
			}
		})
	}
}

// The port IS part of the comparison. What is being anchored is a place a signed
// call is sent, and a different port is a different service — one the party that
// published the anchor need not control.
//
// A DEFAULT port and its omission are the same port, which is the half worth
// pinning: url.Parse does not materialize an implicit port, so a naive comparison
// would refuse an operator who merely wrote :443 out in full. The SCHEME is still
// not compared, and the default-port folding is scheme-relative precisely so it
// cannot become a scheme check by accident.
func TestHostAnchored_ComparesThePort(t *testing.T) {
	cases := map[string]struct {
		anchor, candidate string
		want              bool
	}{
		"same name, different ports":       {"a.com:8443", "a.com:9000", false},
		"bare anchor, ported endpoint":     {"a.com", "https://a.com:8443/v1", false},
		"subdomain on an unnamed port":     {"a.com", "https://cdn.a.com:8443/v1", false},
		"default written out":              {"a.com", "https://a.com:443/v1", true},
		"default written on the anchor":    {"a.com:443", "https://a.com/v1", true},
		"http default written out":         {"a.com", "http://a.com:80/v1", true},
		"scheme alone does not divide":     {"a.com", "http://a.com/v1", true},
		"same non-default port":            {"a.com:8443", "https://a.com:8443/v1", true},
		"subdomain on the same port":       {"a.com:8443", "https://cdn.a.com:8443/v1", true},
		"label boundary still holds":       {"a.com", "https://evil-a.com:8443", false},
		"port does not soften a bad label": {"a.com:8443", "https://evil-a.com:8443", false},
		// A schemeless anchor borrows the candidate's scheme to decide which port is
		// the default. Both anchors in this SDK arrive schemeless — a WBA directory's
		// authority, an Offer.exchange host — so assuming https for them made
		// "a.example:80" keep its port while "http://a.example:80" folded the same
		// port away, and the two stopped anchoring to each other.
		"plaintext anchor, port spelled both sides": {"a.example:80", "http://a.example:80/rev", true},
		"plaintext anchor, port spelled once":       {"a.example:80", "http://a.example/rev", true},
		// Borrowing decides only WHICH port is default; it never makes two different
		// ports equal. 443 is not http's default, and 80 is not https's.
		"default of one scheme is not the other's": {"a.com:443", "http://a.com:80/v1", false},
		"and not in the other direction":           {"a.com:80", "https://a.com:443/v1", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			anchored, err := helpers.HostAnchored(tc.anchor, tc.candidate)
			if err != nil {
				t.Fatalf("HostAnchored(%q, %q): %v", tc.anchor, tc.candidate, err)
			}
			if anchored != tc.want {
				t.Errorf("HostAnchored(%q, %q) = %v, want %v",
					tc.anchor, tc.candidate, anchored, tc.want)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	tests := map[string]struct{ raw, want string }{
		"strips the signed query": {
			"https://cdn.example/doc?sig=abc&kid=ex.v1&exp=1700000600&agent_id=tp",
			"https://cdn.example/doc",
		},
		"strips userinfo and fragment": {
			"https://agent:secret@cdn.example/doc?sig=abc#frag",
			"https://cdn.example/doc",
		},
		"no query is unchanged":   {"https://cdn.example/doc", "https://cdn.example/doc"},
		"unparseable yields none": {"https://cdn.example/\x7f\x00", ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := helpers.RedactURL(tc.raw); got != tc.want {
				t.Errorf("RedactURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The credential lives in the query, so the one thing this must never do is leak
// a signature into whatever reads the redacted value.
func TestRedactURL_NeverCarriesTheCredential(t *testing.T) {
	const signed = "https://cdn.example/doc?agent_id=tp&exp=1700000600&kid=ex.v1&sig=SUPERSECRETSIGNATURE"
	got := helpers.RedactURL(signed)
	for _, leak := range []string{"SUPERSECRETSIGNATURE", "sig=", "agent_id=", "kid=", "exp="} {
		if got != "" && strings.Contains(got, leak) {
			t.Errorf("redacted URL %q still carries %q", got, leak)
		}
	}
}

func TestRetrievalAuthFailureReasonFromToken(t *testing.T) {
	// Every token the map claims, resolved back to a non-zero typed reason.
	for _, token := range []string{
		"expired", "missing_exp", "signature_mismatch",
		"missing_agent_key", "keyid_mismatch", "thumbprint_mismatch",
		"pop_missing_created", "pop_missing_exp", "pop_expired", "pop_sig_invalid",
	} {
		reason, ok := helpers.RetrievalAuthFailureReasonFromToken(token)
		if !ok {
			t.Errorf("token %q is not mapped", token)
			continue
		}
		if reason == 0 {
			t.Errorf("token %q mapped to the unspecified reason", token)
		}
	}
}

// Tokens the edge can emit that are deliberately NOT promoted to a typed reason:
// "missing_sig" because both the URL check and the proof check emit it and the
// body does not say which ran, and the parse-level tokens because the enum has no
// value for them. An unmapped token still reaches the caller as a raw string.
func TestRetrievalAuthFailureReasonFromToken_RefusesTheAmbiguousAndUnknown(t *testing.T) {
	for _, token := range []string{
		"missing_sig",
		"bad_agent_key", "malformed_sig_input", "unsupported_alg",
		"bad_covered_components", "pop_future_created",
		"", "not_a_token",
	} {
		if reason, ok := helpers.RetrievalAuthFailureReasonFromToken(token); ok {
			t.Errorf("token %q must not be promoted, got %v", token, reason)
		}
	}
}
