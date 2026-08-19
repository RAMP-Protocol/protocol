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
		// Neither is redundant: each catches its own wrong ordering. Both are
		// now refused one step earlier, by the tame predicate, which admits no
		// non-ASCII byte at all — IsBareDomain sits behind it and would still
		// refuse them if that predicate were ever loosened.
		{"kelvin_sign_host", "https://market.example/.well-known/ramp.json", "https://marKet.example/dir", ""},
		{"fullwidth_letter_host", "https://exchange.example/.well-known/ramp.json", "https://Ｅxchange.example/dir", ""},

		// Refused — a host that is not a plain domain. IsBareDomain decides this,
		// so an IP literal and a trailing root dot go the same way, and neither
		// output ever has to be rebuilt into an authority that would need
		// bracketing or trimming.
		{"ipv6_literal_reference", base, "https://[::1]/dir", ""},
		{"base_is_an_ipv6_literal", "https://[::1]/.well-known/ramp.json", "/dir", ""},
		{"trailing_root_dot_host", base, "https://a.example./dir", ""},

		// Accepted — tame characters the coarse RFC 3986 set admits, pinned so
		// nobody "tidies" the predicate into the per-component pchar grammar.
		// pchar would refuse "[" and "]", and all three SDKs already agree on
		// them; a percent-escape that is not an encoded dot is likewise kept
		// verbatim by all three rather than decoded.
		{"square_brackets_in_the_path", base, "/a[b]c", "https://a.example/a[b]c"},
		{"percent_escape_kept_verbatim", base, "/a%41b", "https://a.example/a%41b"},

		// Accepted — the three canonical-output rules that used to split. Each
		// row is a case where two SDKs agreed and the third did not.
		//
		//   A bare trailing "?" is Go's ForceQuery, not RFC 3986 semantics.
		//   An empty path is "/" under RFC 3986 6.2.3, which is what WHATWG
		//   already returned and what this oracle now returns.
		//   Dot segments in an ABSOLUTE reference must still be removed; the
		//   relative form is the one Python already got right, so both are here.
		{"bare_trailing_question_mark", base, "/x?", "https://a.example/x"},
		{"empty_path_is_root", base, "https://a.example", "https://a.example/"},
		{"dot_segments_absolute_reference", base, "https://a.example/a/../b", "https://a.example/b"},
		{"dot_segments_relative_reference", base, "/a/../b", "https://a.example/b"},
		// A dot segment in the MANIFEST URL, on the branch that INHERITS the base
		// path. Nothing above holds one: every dot-segment case brings its own
		// through the reference, so the inherited path was never normalized in
		// the Python port while both other implementations normalized it. Same
		// origin, different document name.
		{"dot_segments_on_the_base_query_only_reference", "https://a.example/a/../ramp.json", "?q", "https://a.example/ramp.json?q"},
		{"dot_segments_on_the_base_fragment_only_reference", "https://a.example/a/../ramp.json", "#f", "https://a.example/ramp.json#f"},
		{"single_dot_segment_on_the_base", "https://a.example/a/./ramp.json", "?q", "https://a.example/a/ramp.json?q"},
		// A dot segment that pops PAST THE ROOT with an empty segment behind it.
		// RFC 3986 5.2.4 step 2C removes nothing from an empty output buffer, so
		// the empty segment survives and step 2E moves it: the answer is "//x",
		// not "/x". Go's net/url collapses it, which is why this oracle stopped
		// taking its path from ResolveReference. Both ports already answered
		// this way. The last row is the control: from a deeper base the same
		// reference pops WITHOUT underflow, and every implementation, net/url
		// included, kept the empty segment there — which is what pins the
		// trigger to the underflow rather than to empty segments in general.
		{"dot_segment_underflow_before_an_empty_segment", base, "..//x", "https://a.example//x"},
		{"rooted_dot_segment_underflow_before_an_empty_segment", base, "/..//x", "https://a.example//x"},
		{"dot_segment_underflow_leaving_a_trailing_empty_segment", base, "..//", "https://a.example//"},
		{"dot_segments_popping_without_underflow", "https://a.example/a/b/ramp.json", "../..//x", "https://a.example//x"},
		// A padded port is a different string from :443 and does not fold, so
		// it survives into the output. It is accepted on purpose: the port rule
		// bounds the VALUE, and reading it as text would flip this verdict.
		{"padded_port_on_the_base", "https://a.example:0443/.well-known/ramp.json", "/x", "https://a.example:0443/x"},

		// Accepted — a colon and a semicolon that are ordinary path characters.
		// A colon is legal in any segment but the first of a schemeless
		// reference, and a semicolon is a sub-delim. The semicolon is here
		// because Python's urljoin used to eat a trailing one as an empty
		// ";params", which is why this port resolves the path itself.
		{"colon_in_a_later_segment", base, "/a:b", "https://a.example/a:b"},
		{"semicolon_in_the_path", base, "/x;", "https://a.example/x;"},

		// Accepted — the QUERY and the FRAGMENT, which nothing above covers. No
		// vector carried a non-empty query and the hash appeared nowhere in this
		// corpus, so both components were unpinned while the three SDKs took
		// them from three different serializers. The apostrophe is the one
		// character that split them in query position: it is a sub-delim the
		// tame predicate admits, and WHATWG's special-query encode set holds it,
		// so the TypeScript port alone answered %27.
		{"apostrophe_in_the_query", base, "/x?a='b", "https://a.example/x?a='b"},
		{"apostrophe_is_the_whole_query", base, "/x?'", "https://a.example/x?'"},
		{"apostrophe_in_the_fragment", base, "/x?a=b#c'd", "https://a.example/x?a=b#c'd"},
		// A fragment is KEPT on the reference, though the manifest URL refuses
		// one. Not an inconsistency: the base is a URL a document WAS FETCHED
		// FROM, so it could never have carried a fragment, while the reference is
		// a value an author WROTE, where a fragment names an entry inside the
		// document — a verification method in a Signature Agent Card, the way a
		// DID document names one. It is inert for the fetch either way.
		{"fragment_on_the_reference", base, "/doc#frag", "https://a.example/doc#frag"},
		{"fragment_only_reference", base, "#frag", "https://a.example/.well-known/ramp.json#frag"},
		// Defined but empty, on both components: no mark on the output.
		{"bare_trailing_hash", base, "/doc#", "https://a.example/doc"},

		// Accepted — a QUERY-BEARING manifest URL, the branch RFC 3986 5.2.2
		// treats as a special case and which no vector reached. The base's query
		// is inherited ONLY by a reference with an empty path that defines no
		// query of its own. A reference carrying ANY path drops it, which is the
		// half most likely to be got wrong by an implementation reading 5.2.2
		// as "inherit when the reference defines no query".
		{"query_base_path_reference_drops_it", "https://a.example/ramp.json?bq", "/x", "https://a.example/x"},
		{"query_base_relative_reference_drops_it", "https://a.example/ramp.json?bq", "x", "https://a.example/x"},
		{"query_base_fragment_reference_inherits_it", "https://a.example/ramp.json?bq", "#f", "https://a.example/ramp.json?bq#f"},
		{"query_base_query_reference_replaces_it", "https://a.example/ramp.json?bq", "?rq", "https://a.example/ramp.json?rq"},
		{"query_base_empty_query_reference", "https://a.example/ramp.json?bq", "?", "https://a.example/ramp.json"},

		// Refused — untame input. One row per class the three URL engines split
		// on, each verified by running all three implementations. Without these
		// the whole predicate is unpinned: no case in the corpus above holds a
		// single character outside the coarse RFC 3986 set.
		//
		// The control character in the reference is the headline case. A
		// leading TAB makes the Python and TypeScript authority regexes read
		// this ABSOLUTE reference as a relative path, so the https check, the
		// userinfo check, the origin check and the port check are all skipped
		// at once. It resolved to https://a.example/x — on the right origin
		// only because the authority is rebuilt from the already-checked base.
		// That rebuild is the last line of defence, not a formatting step.
		{"control_character_in_the_reference", base, "\thttps://u:s3cr3t@evil.example:8443/x", ""},
		// Not a LEADING control character in the base: a leading one is already
		// refused, for the wrong reason, by the scheme check. The PATH is the
		// gap — two SDKs accepted this and one refused it.
		{"control_character_in_the_base_path", "https://a.example/ra\tmp.json", "/x", ""},
		{"invalid_percent_escape_in_the_reference", base, "/a%zz", ""},
		{"invalid_percent_escape_in_the_base", "https://a.example/%zz/ramp.json", "/x", ""},
		// Encoded dot segments, lower case on one side and upper on the other.
		{"encoded_dot_segments_in_the_reference", base, "/%2e%2e/x", ""},
		{"encoded_dot_segments_in_the_base", "https://a.example/x/%2E%2E/ramp.json", "/y", ""},
		{"vertical_bar_in_the_path", base, "/a|b", ""},
		{"caret_in_the_path", base, "/a^b", ""},
		{"backslash_in_the_reference", base, "\\evil.example/x", ""},
		{"space_in_the_path", base, "/a b", ""},
		{"non_ascii_in_the_path", base, "/caf\u00e9.json", ""},
		// An empty authority is no authority. Go read the first as a plain path
		// and the second as an EMPTY reference, so it returned the manifest URL
		// itself; both other SDKs refused both.
		{"empty_authority", base, "///x", ""},
		{"empty_authority_bare", base, "//", ""},
		// RFC 3986 path-noscheme: the first segment of a schemeless reference
		// may not hold a colon. Go refused the first of these and accepted the
		// second; both other SDKs accepted both as ordinary path segments.
		{"colon_opens_the_reference", base, ":/x", ""},
		{"first_segment_is_not_a_scheme", base, "1:x", ""},
		// Refused — a second hash. RFC 3986 3.5 gives a reference one fragment
		// that runs to the end of the string, so this is not a URI reference:
		// a hash inside a fragment has to be written %23. It is also the one
		// character Go re-encodes in a fragment, measured across 29 forms, so
		// refusing it removes that divergence rather than picking a winner.
		{"two_hashes_in_the_reference", base, "/doc#f#g", ""},
		{"two_hashes_with_an_empty_second_fragment", base, "/doc#f#", ""},

		// Refused — a port that is not a port. The first two reach the WHATWG
		// parser as a raw TypeError in the TypeScript port unless they are
		// refused before it runs, which is outside the error family that port
		// documents.
		{"non_numeric_port_on_the_base", "https://a.example:abc/.well-known/ramp.json", "/x", ""},
		{"out_of_range_port_on_the_base", "https://a.example:70000/.well-known/ramp.json", "/x", ""},
		{"out_of_range_port_on_the_reference", base, "https://a.example:70000/x", ""},
		{"zero_port_on_the_base", "https://a.example:0/.well-known/ramp.json", "/x", ""},
		// Two colons in one authority. Refused here for a port that is not a
		// port, which is what splitting on the FIRST colon produces. Split on the
		// LAST colon instead and the host half is "a.example:8443", which
		// IsBareDomain accepts through its optional-port branch — every origin
		// check downstream then runs against a hostname that is not one. The
		// second case is the same shape with a foldable port: fold the trailing
		// :443 away and the leftover colon disappears into the host, so the
		// output looks well-formed while being wrong.
		{"two_colons_in_the_base_authority", "https://a.example:8443:9/.well-known/ramp.json", "/x", ""},
		{"two_default_ports_in_the_base_authority", "https://a.example:443:443/.well-known/ramp.json", "/x", ""},
		{"two_colons_in_the_reference_authority", base, "https://a.example:8443:9/x", ""},

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
		// A fragment is never sent to a server, so the URL a manifest was
		// fetched from cannot carry one — and while it does, RFC 3986 5.2.2
		// asks whether a reference of "#" defines an empty fragment or none,
		// which is a question the three parsers answered differently.
		{"base_carries_a_fragment", "https://a.example/ramp.json#f", "/doc", ""},
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
//
// The cases are chosen to reach DIFFERENT refusals, because the risk is not one
// bad message but one path nobody converted. The last two carry the credential
// somewhere Go never parses as userinfo, so the userinfo checks do not fire and
// the string travels on to a much later refusal.
func TestIdentityDocumentRefusalDoesNotEchoTheCredential(t *testing.T) {
	const secret = "s3cr3t"
	for _, c := range []struct{ name, manifest, ref string }{
		{"in the reference", "https://a.example/.well-known/ramp.json", "https://u:" + secret + "@a.example/x"},
		{"in the manifest URL", "https://u:" + secret + "@a.example/ramp.json", "/x"},
		// The two above both PARSE, so neither reaches the parse-failure
		// branch. This one does not parse — an invalid percent-escape — and
		// that branch is the one that used to print the reference twice, once
		// from %q and once from the wrapped *url.Error.
		{"in a reference that does not parse", "https://a.example/.well-known/ramp.json", "https://u:" + secret + "@a.example/%zz"},
		// No "//" after the scheme, so this is an OPAQUE reference: everything
		// after "https:" is opaque data, there is no authority, and therefore
		// no userinfo component to check. It is refused for naming no host.
		{"in an opaque reference", "https://a.example/.well-known/ramp.json", "https:u:" + secret + "@a.example/x"},
		// Same shape one step further out: "u" reads as the scheme, so this is
		// an opaque reference under a scheme that is not https, and it is
		// refused for that instead.
		{"in a schemeless-looking reference", "https://a.example/.well-known/ramp.json", "u:" + secret + "@a.example/x"},
	} {
		_, err := ResolveIdentityDocument(c.manifest, c.ref)
		if err == nil {
			t.Fatalf("credential %s: accepted, want refused", c.name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("credential %s: error echoes the credential: %v", c.name, err)
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
