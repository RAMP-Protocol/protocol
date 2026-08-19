package helpers

// Identity-document resolution golden-vector emitter.
//
// ResolveIdentityDocument decides whether a URL a manifest named may be fetched
// at all, and it is about to exist in three languages. A reference one SDK
// accepts and another refuses is a participant whose keys can be found by some
// consumers and not others, so the answer has to be identical everywhere. This
// emitter is the oracle: every recorded verdict is DERIVED by calling the REAL
// Go face, never hand-typed, exactly as gen_audience_vectors_test.go derives its
// verdicts.
//
// Each case still carries the verdict its AUTHOR intended — including the exact
// resolved URL for an accepted case — and the emitter refuses to write a file
// where the real face disagrees with that intent. Without that a face that
// started answering the opposite would emit a corpus asserting the opposite and
// drag both ports along with it.
//
// Like the other emitters this test is a verification no-op by default (it
// asserts the committed file matches a fresh emit) and (re)writes under
// RAMP_UPDATE_VECTORS=1. It is TEST INFRASTRUCTURE, not the code under test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// identityDocumentVector is one ResolveIdentityDocument case: the URL the
// manifest was fetched from, the reference it carried, and what the REAL face
// answered. Resolved is the absolute URL for an accepted case and "" for a
// refused one — a port that returned a URL where the oracle refuses, or refused
// where it resolves, disagrees on the field's whole point.
type identityDocumentVector struct {
	Name        string `json:"name"`
	ManifestURL string `json:"manifest_url"`
	Ref         string `json:"ref"`
	Accepted    bool   `json:"accepted"`
	Resolved    string `json:"resolved"`
}

// buildIdentityDocumentVectors enumerates what a manifest can name. The base URL
// varies per case on purpose: the four base-vetting cases at the end are the only
// ones that prove the manifest URL itself is checked, and the two homograph cases
// need a base their host would MATCH once folded, or they prove nothing.
func buildIdentityDocumentVectors(t *testing.T) []identityDocumentVector {
	t.Helper()
	const base = "https://a.example/.well-known/ramp.json"
	cases := []struct {
		name     string
		manifest string
		ref      string
		want     string // the resolved URL; "" means the case must be REFUSED
	}{
		// Accepted — every reference form RFC 3986 defines, since "relative and
		// absolute references are both supported" is the field's contract.
		{"absolute_same_origin", base, "https://a.example/.well-known/dir", "https://a.example/.well-known/dir"},
		{"root_relative", base, "/.well-known/http-message-signatures-directory", "https://a.example/.well-known/http-message-signatures-directory"},
		{"path_relative", base, "sub/card.json", "https://a.example/.well-known/sub/card.json"},
		{"path_relative_parent", base, "../card.json", "https://a.example/card.json"},
		// A network-path reference inherits the base's scheme, so it can only ever
		// be https here — and it is the one relative form that can still name
		// somebody else's host, which is why both halves are in the corpus.
		{"network_path_same_host", base, "//a.example/card.json", "https://a.example/card.json"},
		{"network_path_other_host", base, "//evil.example/card.json", ""},
		// :443 written out and :443 left implicit are the same port.
		{"default_port_spelled_out", base, "https://a.example:443/dir", "https://a.example/dir"},
		{"default_port_on_the_base", "https://a.example:443/.well-known/ramp.json", "https://a.example/dir", "https://a.example/dir"},
		{"same_non_default_port", "https://a.example:8443/.well-known/ramp.json", "https://a.example:8443/dir", "https://a.example:8443/dir"},
		// Proves the host comparison folds case rather than comparing bytes.
		{"uppercase_host", base, "https://A.EXAMPLE/dir", "https://a.example/dir"},
		{"uppercase_scheme", base, "HTTPS://a.example/dir", "https://a.example/dir"},

		// Refused — a different origin. The subdomain case is the whole delta
		// between this rule and the endpoint rule: HostAnchored would ACCEPT it,
		// and a dangling DNS record on keys.a.example is all it takes for whoever
		// answers there to publish keys as a.example.
		{"subdomain_is_a_different_origin", base, "https://keys.a.example/dir", ""},
		{"label_boundary_not_a_prefix", base, "https://evil-a.example/dir", ""},
		{"unrelated_host", base, "https://other.example/dir", ""},
		{"different_non_default_port", base, "https://a.example:8443/dir", ""},
		{"port_mismatch_other_way", "https://a.example:8443/.well-known/ramp.json", "https://a.example/dir", ""},

		// Refused — the reference is not a fetchable https URL.
		{"http_reference", base, "http://a.example/dir", ""},
		{"userinfo_in_the_reference", base, "https://u:p@a.example/x", ""},
		{"data_uri", base, "data:application/json,%7B%7D", ""},
		{"javascript_uri", base, "javascript:alert(1)", ""},
		{"empty_reference", base, "", ""},
		{"whitespace_reference", base, "   ", ""},
		// A scheme with no "//" is an absolute URI that names no authority, so it
		// resolves to a URL with no host at all rather than borrowing the base's.
		{"scheme_without_authority", base, "https:/dir", ""},
		// A padded port is a DIFFERENT STRING, not another spelling of 443 — the
		// same rule the audience corpus pins with its padded-port case.
		{"padded_default_port", base, "https://a.example:0443/dir", ""},

		// Refused — a homograph host. Each needs a base whose host it would MATCH
		// if the ASCII shape were checked after folding instead of before:
		//
		//   U+212A KELVIN SIGN case-folds to a plain ASCII "k", so EqualFold
		//   reports "mar<KELVIN>et.example" and "market.example" as the SAME name.
		//   Only the ASCII check refuses it.
		//
		//   U+FF25 FULLWIDTH LATIN CAPITAL E survives folding untouched and
		//   becomes ASCII only under NFKC, so it is the case that catches a port
		//   which normalizes width before checking the shape.
		//
		// Neither is redundant: each catches its own wrong ordering.
		{"kelvin_sign_host", "https://market.example/.well-known/ramp.json", "https://marKet.example/dir", ""},
		{"fullwidth_letter_host", "https://exchange.example/.well-known/ramp.json", "https://Ｅxchange.example/dir", ""},

		// Refused — a host that is not a plain domain. IsBareDomain decides this,
		// so an IP literal and a trailing root dot go the same way, and neither
		// output ever has to be rebuilt into an authority that would need
		// bracketing or trimming.
		{"ipv6_literal_reference", base, "https://[::1]/dir", ""},
		{"base_is_an_ipv6_literal", "https://[::1]/.well-known/ramp.json", "/dir", ""},
		{"trailing_root_dot_host", base, "https://a.example./dir", ""},

		// Refused — the BASE is not usable, checked before the reference is even
		// looked at. Nothing downstream catches these: the first two resolve to a
		// URL that is https and on the matching host, and would be accepted by an
		// implementation that only vetted the resolved side.
		{"base_is_http", "http://a.example/ramp.json", "/doc", ""},
		{"base_is_http_on_443", "http://a.example:443/ramp.json", "https://a.example/doc", ""},
		{"base_carries_userinfo", "https://u:p@a.example/ramp.json", "https://a.example/doc", ""},
		{"base_has_no_scheme", "a.example/ramp.json", "/doc", ""},
		{"base_has_no_host", "https:///ramp.json", "/doc", ""},
		{"base_is_empty", "", "/doc", ""},
	}
	out := make([]identityDocumentVector, 0, len(cases))
	for _, c := range cases {
		got, err := ResolveIdentityDocument(c.manifest, c.ref)
		accepted := err == nil
		if accepted != (c.want != "") {
			t.Fatalf("identity-document vector %s: oracle accepted=%v (%v), intended accepted=%v", c.name, accepted, err, c.want != "")
		}
		if accepted && got != c.want {
			t.Fatalf("identity-document vector %s: oracle resolved=%q, intended=%q", c.name, got, c.want)
		}
		if !accepted {
			got = ""
		}
		out = append(out, identityDocumentVector{
			Name:        c.name,
			ManifestURL: c.manifest,
			Ref:         c.ref,
			Accepted:    accepted,
			Resolved:    got,
		})
	}
	return out
}

// TestIdentityDocumentRefusalDoesNotEchoTheCredential is a Go-only assertion: the
// vectors carry a verdict, not an error string, so nothing in the shared corpus
// can catch a refusal that names the very userinfo it is refusing. A log line or
// an error surfaced to an operator is exactly where a leaked credential ends up.
func TestIdentityDocumentRefusalDoesNotEchoTheCredential(t *testing.T) {
	const secret = "s3cr3t"
	for _, c := range []struct{ name, manifest, ref string }{
		{"in the reference", "https://a.example/.well-known/ramp.json", "https://u:" + secret + "@a.example/x"},
		{"in the manifest URL", "https://u:" + secret + "@a.example/ramp.json", "/x"},
	} {
		_, err := ResolveIdentityDocument(c.manifest, c.ref)
		if err == nil {
			t.Fatalf("userinfo %s: accepted, want refused", c.name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("userinfo %s: error echoes the credential: %v", c.name, err)
		}
	}
}

// TestGenerateIdentityDocumentVectors emits the identity-document golden corpus.
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateIdentityDocumentVectors(t *testing.T) {
	doc := map[string]any{
		"identity_document": buildIdentityDocumentVectors(t),
	}
	path := filepath.Join("testdata", "identity-document-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
