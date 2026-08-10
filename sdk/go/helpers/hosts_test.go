package helpers_test

import (
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

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

// The port is NOT part of the comparison. The property being enforced is "not an
// unrelated host", and a service on another port of the same name is not another
// host — TLS binds hostnames, not ports. Comparing with the port would leave any
// Exchange not on 443 permanently unable to receive a usage report, for no
// security gain. Stated as its own case because it is the one place "same host"
// and "same origin" pull apart.
func TestHostAnchored_IgnoresThePort(t *testing.T) {
	cases := map[string][2]string{
		"same name, different ports":   {"a.com:8443", "a.com:9000"},
		"bare anchor, ported endpoint": {"a.com", "https://a.com:8443/v1"},
		"subdomain on a port":          {"a.com", "https://cdn.a.com:8443/v1"},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			anchored, err := helpers.HostAnchored(pair[0], pair[1])
			if err != nil {
				t.Fatalf("HostAnchored: %v", err)
			}
			if !anchored {
				t.Errorf("%q must be anchored to %q — the port is not part of the host", pair[1], pair[0])
			}
		})
	}
	// A different NAME is still refused, ported or not.
	anchored, err := helpers.HostAnchored("a.com", "https://evil-a.com:8443")
	if err != nil {
		t.Fatalf("HostAnchored: %v", err)
	}
	if anchored {
		t.Error("a port must not soften the label-boundary rule")
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
