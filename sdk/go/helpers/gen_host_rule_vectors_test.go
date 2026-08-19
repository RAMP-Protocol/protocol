package helpers

// Host-rule golden-vector emitter (ADR-020 §5).
//
// The three routing predicates — HostOf, IsBareHost, HostAnchored — decide where
// a signed call is allowed to go, from values a network party supplied. They are
// pure string work, so they are expressible as data, and the repo's rule for a
// rule that is expressible as data is that it is corpus-locked rather than
// asserted three times (docs/design-history.md, "SSRF-guarded fetch"). The
// residual wiring — that a resolver actually calls them — stays a behavioural
// test in each language.
//
// Locking them matters more here than the shape rule next door, because the three
// languages disagree about what a reference even is before any of this code runs.
// WHATWG's URL folds a scheme's default port away at PARSE time, which is earlier
// than this rule decides which scheme is in play; Python's urlsplit strips tabs
// and newlines that Go refuses outright, lowercases its hostname accessor, and
// keeps userinfo inside netloc. A port that leans on its platform parser is
// therefore wrong in a way no amount of reading the Go source prevents. The
// crossings below are where those differences surface.
//
// Same contract as the audience emitter: every recorded verdict is DERIVED by
// calling the REAL face, each case still carries the verdict its AUTHOR intended,
// and the emitter refuses to write a file where the two disagree. Verification
// no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.

import (
	"os"
	"path/filepath"
	"testing"
)

// hostOfVector is one HostOf case. Host is the authority the face extracted —
// port included, userinfo excluded — and Error records that the reference could
// not be read as a host at all, which is a different answer from an empty one.
type hostOfVector struct {
	Name  string `json:"name"`
	Ref   string `json:"ref"`
	Host  string `json:"host"`
	Error bool   `json:"error"`
}

// isBareHostVector is one IsBareHost case: whether the reference is EXACTLY an
// authority, so a caller may concatenate it into a URL without the far side
// having chosen the path that gets fetched.
type isBareHostVector struct {
	Name  string `json:"name"`
	Ref   string `json:"ref"`
	Bare  bool   `json:"bare"`
	Error bool   `json:"error"`
}

// hostAnchoredVector is one HostAnchored case: whether a value a remote document
// supplied may be dialled, given the host that served that document.
type hostAnchoredVector struct {
	Name      string `json:"name"`
	Anchor    string `json:"anchor"`
	Candidate string `json:"candidate"`
	Anchored  bool   `json:"anchored"`
	Error     bool   `json:"error"`
}

// buildHostOfVectors enumerates what a reference can be. The stripping cases are
// the reason the face exists — a value that had to have something removed to
// reach its host was never a host — and the case-preserving one is load-bearing
// for IsBareHost below, which compares the extracted host against the original.
func buildHostOfVectors(t *testing.T) []hostOfVector {
	t.Helper()
	cases := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"plain_domain", "exchange.example", "exchange.example", false},
		{"host_with_port", "exchange.example:8443", "exchange.example:8443", false},
		{"absolute_url", "https://exchange.example/v1", "exchange.example", false},
		{"absolute_url_with_port", "https://exchange.example:8443/v1", "exchange.example:8443", false},
		{"plaintext_url", "http://exchange.example/v1", "exchange.example", false},

		// Userinfo is NOT part of the host, in either spelling. The schemeless one
		// is the shape a plain URL parse reads as a scheme rather than a host, and
		// it is why the endpoint rule reads the reference the same way this does.
		{"userinfo_is_not_part_of_the_host", "https://user:pass@exchange.example", "exchange.example", false},
		{"schemeless_userinfo", "user:pass@exchange.example", "exchange.example", false},

		// Case is PRESERVED. Lowercasing here would make IsBareHost accept a value
		// that differs from what a caller is about to concatenate.
		{"case_is_preserved", "Exchange.Example", "Exchange.Example", false},

		{"trailing_root_dot", "exchange.example.", "exchange.example.", false},
		{"ipv6_literal", "[::1]:443", "[::1]:443", false},
		{"trailing_colon", "exchange.example:", "exchange.example:", false},

		// Everything a rich reference can carry beyond the authority.
		{"path_is_stripped", "exchange.example/v1", "exchange.example", false},
		{"query_is_stripped", "exchange.example?a=1", "exchange.example", false},
		{"fragment_is_stripped", "exchange.example#frag", "exchange.example", false},

		// Refused: nothing to read a host out of.
		{"empty", "", "", true},
		{"whitespace_only", "   ", "", true},
		{"no_authority", "/v1", "", true},
		{"scheme_with_no_host", "https://", "", true},

		// A control character is an ERROR, not a stripped character. Python's
		// urlsplit and WHATWG's URL both remove tabs and newlines silently, so a
		// port that delegates here answers "host" where this answers "not a host".
		{"control_character", "exchange.example\n", "", true},
		{"tab_inside_the_host", "exchange.\texample", "", true},

		// A port that is not a number is not a port, and neither is a second colon
		// after the first one. The port is read from the FIRST colon onward, so a
		// port that merely ENDS in digits does not pass.
		{"non_numeric_port", "exchange.example:abc", "", true},
		{"double_colon_before_the_port", "exchange.example::443", "", true},
		{"two_ports", "exchange.example:44:3", "", true},
		{"signed_port", "exchange.example:-1", "", true},
		{"colon_inside_the_name", "ex:change.example", "", true},

		// A bare trailing colon is a port of zero digits, which IS a port. The
		// value survives here and is refused one level up, by IsBareHost.
		{"trailing_colon_is_an_empty_port", "exchange.example:", "exchange.example:", false},

		// A leading zero is a different string, not a different spelling of the
		// same port, and the comparison is textual.
		{"leading_zero_port", "exchange.example:080", "exchange.example:080", false},
		{"out_of_range_port", "exchange.example:99999999", "exchange.example:99999999", false},

		// Brackets are IPv6 syntax and are read as such only at the front.
		{"ipv6_without_a_port", "[::1]", "[::1]", false},
		{"ipv6_unclosed", "[::1", "", true},
		{"ipv6_trailing_garbage", "[::1]x", "", true},
		{"bracket_inside_the_name", "a[b.example", "", true},

		// Characters an authority may not contain. Not a denylist of separators —
		// the set an authority ADMITS is closed, and these are outside it.
		{"space_in_the_host", "ex ample.example", "", true},
		{"backslash_in_the_host", "a\\b.example", "", true},
		{"caret_in_the_host", "a^b.example", "", true},
		{"brace_in_the_host", "a{b.example", "", true},
		{"pipe_in_the_host", "a|b.example", "", true},

		// …and characters it does. An underscore is not a domain label the wire
		// rule admits, but it IS a usable host, which is the whole reason these two
		// predicates are separate.
		{"underscore_in_the_host", "a_b.example", "a_b.example", false},
		{"tilde_in_the_host", "a~b.example", "a~b.example", false},
		{"empty_label", "a..example", "a..example", false},
		{"non_ascii_host", "\u0434\u043e\u043c.example", "\u0434\u043e\u043c.example", false},

		// A percent-escape is refused. Every escape a host may legally carry
		// decodes to a byte no domain name contains, so refusing the lot costs
		// nothing a caller can use and removes an unescaping step the three
		// languages would each get subtly wrong.
		{"percent_escape", "%41.example", "", true},
		{"invalid_percent_escape", "a%zz.example", "", true},
		{"percent_encoded_nul", "a.example%00", "", true},

		// Userinfo is split at the LAST "@", so an "@" inside the credential does
		// not become part of the host.
		{"userinfo_containing_an_at", "user@pass@exchange.example", "exchange.example", false},

		// Scheme shapes. "://" is a separator only behind a valid scheme at the front;
		// everywhere else it is ordinary path text, and a reference carrying it is
		// malformed rather than schemeless. Each of these answered with the wrong
		// half of the string in a port that searched for the separator instead.
		{"scheme_with_plus", "ht+tp://exchange.example/v1", "exchange.example", false},
		{"scheme_with_hyphen", "ht-tp://exchange.example/v1", "exchange.example", false},
		{"scheme_with_dot", "ht.tp://exchange.example/v1", "exchange.example", false},
		{"scheme_uppercase", "HTTPS://exchange.example/v1", "exchange.example", false},
		{"separator_in_a_path_segment", "evil.example/x://exchange.example", "", true},
		{"scheme_starting_with_a_digit", "1https://exchange.example/", "", true},
		{"doubled_colon_after_the_scheme", "http:://exchange.example/", "", true},
		{"separator_with_no_scheme", "://exchange.example/", "", true},

		// Userinfo admits a NARROWER set than the host. Each of these is a character
		// the host accepts and the credential does not, so a port that validated only
		// the part after the "@" let them through. The backslash is the one that
		// mattered: WHATWG ends an authority at it, so the fetch reached a different
		// host from the one anchoring approved.
		{"backslash_in_userinfo", "http://evil.example\\@exchange.example/rev", "", true},
		{"quote_in_userinfo", "https://u" + `"` + "x@exchange.example", "", true},
		{"angle_bracket_in_userinfo", "https://u<x@exchange.example", "", true},
		{"close_bracket_in_userinfo", "https://u]x@exchange.example", "", true},

		// Escapes are read per component. A path or query escape says nothing about
		// the host, and refusing the whole reference over one refused an ordinary
		// conformant endpoint.
		{"escape_in_query", "https://exchange.example/v1?q=a%20b", "exchange.example", false},
		{"escape_in_path", "https://exchange.example/p%41th", "exchange.example", false},
		{"malformed_escape_in_path", "https://exchange.example/p%zzth", "", true},
		{"malformed_escape_in_query", "https://exchange.example/?q=%zz", "exchange.example", false},
		{"escape_in_userinfo", "https://u%41x@exchange.example", "exchange.example", false},
		{"malformed_escape_in_userinfo", "https://u%zzx@exchange.example", "", true},

		// An "@" beyond the authority is not a credential.
		{"at_sign_in_the_path", "https://exchange.example/v1@x", "exchange.example", false},
	}
	out := make([]hostOfVector, 0, len(cases))
	for _, c := range cases {
		host, err := HostOf(c.ref)
		if (err != nil) != c.wantErr {
			t.Fatalf("host_of vector %s: oracle error=%v, intended error=%v for %q", c.name, err, c.wantErr, c.ref)
		}
		if host != c.want {
			t.Fatalf("host_of vector %s: oracle host=%q, intended=%q for %q", c.name, host, c.want, c.ref)
		}
		out = append(out, hostOfVector{Name: c.name, Ref: c.ref, Host: host, Error: err != nil})
	}
	return out
}

// buildIsBareHostVectors enumerates what may be concatenated into a URL. The
// accepted list is deliberately WIDER than the wire's bare-domain shape — an
// underscore label, a leading hyphen, a root dot and a bracketed IPv6 literal are
// all usable hosts and none is a value the contract admits as a recipient. The
// two predicates answer different questions and audience_test pins them as
// diverging on purpose; this corpus carries the routing half of that pair.
func buildIsBareHostVectors(t *testing.T) []isBareHostVector {
	t.Helper()
	cases := []struct {
		name    string
		ref     string
		want    bool
		wantErr bool
	}{
		{"plain_domain", "exchange.example", true, false},
		{"host_with_port", "exchange.example:8443", true, false},
		{"case_is_not_a_strip", "Exchange.Example", true, false},

		// Usable hosts the wire rule refuses. Their presence here IS the divergence.
		{"trailing_root_dot", "exchange.example.", true, false},
		{"leading_hyphen", "-x.example", true, false},
		{"trailing_hyphen", "x-.example", true, false},
		{"underscore_label", "_acme.example", true, false},
		{"ipv6_literal", "[::1]:443", true, false},

		// Refused: something had to be stripped to reach the host, so the far side
		// chose more than where the fetch goes.
		{"scheme", "https://exchange.example", false, false},
		{"path", "exchange.example/v1", false, false},
		{"query", "exchange.example?a=1", false, false},
		{"fragment", "exchange.example#frag", false, false},
		{"userinfo", "user:pass@exchange.example", false, false},
		{"scheme_and_path", "https://exchange.example/v1", false, false},

		// A trailing colon round-trips to itself and would otherwise pass. It is
		// refused rather than normalized away: nobody meant to write it, and the
		// value is about to be concatenated.
		{"trailing_colon", "exchange.example:", false, false},

		// Accepted: usable hosts that are not domain names at all.
		{"non_ascii_host", "\u0434\u043e\u043c.example", true, false},
		{"empty_label", "a..example", true, false},
		{"leading_zero_port", "exchange.example:080", true, false},
		{"ipv6_without_a_port", "[::1]", true, false},

		{"empty", "", false, true},
		{"whitespace_only", "   ", false, true},
		{"control_character", "exchange.example\n", false, true},
		{"non_numeric_port", "exchange.example:abc", false, true},
		{"double_colon_before_the_port", "exchange.example::443", false, true},
		{"no_authority", "/v1", false, true},
		{"space_in_the_host", "ex ample.example", false, true},
		{"backslash_in_the_host", "a\\b.example", false, true},
		{"percent_escape", "%41.example", false, true},
		{"ipv6_unclosed", "[::1", false, true},
		{"separator_in_a_path_segment", "evil.example/x://exchange.example", false, true},
		{"scheme_starting_with_a_digit", "1https://exchange.example/", false, true},
		{"backslash_in_userinfo", "http://evil.example\\@exchange.example/rev", false, true},
		{"malformed_escape_in_path", "https://exchange.example/p%zzth", false, true},
	}
	out := make([]isBareHostVector, 0, len(cases))
	for _, c := range cases {
		bare, err := IsBareHost(c.ref)
		if (err != nil) != c.wantErr {
			t.Fatalf("is_bare_host vector %s: oracle error=%v, intended error=%v for %q", c.name, err, c.wantErr, c.ref)
		}
		if bare != c.want {
			t.Fatalf("is_bare_host vector %s: oracle verdict=%v, intended=%v for %q", c.name, bare, c.want, c.ref)
		}
		out = append(out, isBareHostVector{Name: c.name, Ref: c.ref, Bare: bare, Error: err != nil})
	}
	return out
}

// buildHostAnchoredVectors enumerates the anchor rule. Three families have to
// CROSS here rather than sit beside each other, because each crossing is where an
// independent port diverges while passing every single-family case:
//
//   - scheme borrowing × port. A side that named no scheme borrows the other's,
//     so which port counts as default is decided per pair, not per value. A port
//     that assumes https for a schemeless anchor un-anchors every plaintext
//     directory that spelled :80 in full.
//   - default-port folding × scheme. http://x and https://x both reduce to no
//     port, but x:443 does NOT equal http://x:80 — the folding is what keeps the
//     port rule from quietly becoming a scheme check, and reversing that reading
//     turns two different services into one.
//   - label boundary × port. The hostname and the port are compared as two
//     values; joined into one string, a legitimate subdomain on a port would be
//     refused for having the port.
func buildHostAnchoredVectors(t *testing.T) []hostAnchoredVector {
	t.Helper()
	cases := []struct {
		name      string
		anchor    string
		candidate string
		want      bool
		wantErr   bool
	}{
		// The ordinary shapes.
		{"same_host", "exchange.example", "https://exchange.example/v1", true, false},
		{"subdomain", "exchange.example", "https://api.exchange.example/v1", true, false},
		{"both_bare", "exchange.example", "exchange.example", true, false},
		{"unrelated_host", "exchange.example", "https://cdn.other.example/v1", false, false},

		// A parent is not anchored to its own child: the rule admits a set that
		// grows downward, never upward.
		{"parent_is_not_anchored_to_child", "api.exchange.example", "https://exchange.example/v1", false, false},

		// The mistake an attacker registers a domain to exploit.
		{"label_boundary_trick", "a.com", "https://evil-a.com/v1", false, false},
		{"suffix_without_a_label_boundary", "a.com", "https://xa.com/v1", false, false},

		// Spelling, not identity.
		{"case_is_folded", "Exchange.Example", "https://EXCHANGE.example/v1", true, false},
		{"trailing_root_dot_on_the_anchor", "exchange.example.", "https://exchange.example/v1", true, false},
		{"trailing_root_dot_on_the_candidate", "exchange.example", "https://exchange.example./v1", true, false},

		// ONE trailing dot is trimmed, not every trailing dot. Python's rstrip
		// removes them all, which would make a doubled root dot compare equal to a
		// name that never carried one.
		{"doubled_root_dot_is_not_the_same_name", "exchange.example..", "https://exchange.example/v1", false, false},
		{"doubled_root_dot_on_both_sides", "exchange.example..", "https://exchange.example../v1", true, false},

		// Default port folding. Writing :443 out is not a refusal.
		{"default_port_written_out_on_the_candidate", "exchange.example", "https://exchange.example:443/v1", true, false},
		{"default_port_written_out_on_the_anchor", "exchange.example:443", "https://exchange.example/v1", true, false},
		{"scheme_is_not_compared", "http://x.example", "https://x.example", true, false},
		{"each_scheme_folds_its_own_default", "http://x.example:80", "https://x.example:443", true, false},

		// Scheme borrowing. The anchors in this SDK arrive schemeless, so which
		// port is the default is the other side's scheme, not an assumed https.
		{"schemeless_anchor_borrows_plaintext", "a.example:80", "http://a.example:80/rev", true, false},
		{"schemeless_anchor_does_not_assume_https", "a.example:80", "https://a.example/v1", false, false},
		{"borrowing_decides_the_default_not_equality", "x.example:443", "http://x.example:80/v1", false, false},
		{"default_of_the_other_scheme_is_not_folded", "https://x.example:80", "http://x.example:80", false, false},

		// Port × label boundary.
		{"different_port", "exchange.example:8443", "https://exchange.example:9443/v1", false, false},
		{"subdomain_on_the_same_port", "exchange.example:8443", "https://api.exchange.example:8443/v1", true, false},
		{"subdomain_on_another_port", "exchange.example", "https://api.exchange.example:8443/v1", false, false},

		// Case × non-default port: neither family alone catches a port that folds
		// case only in the portless branch.
		{"case_folded_with_a_non_default_port", "Exchange.Example:8443", "https://EXCHANGE.example:8443/v1", true, false},

		// An unknown scheme has no default to fold, so its port is kept verbatim.
		{"unknown_scheme_keeps_its_port", "x.example:443", "ftp://x.example:443/v1", true, false},

		// Userinfo is IGNORED here, deliberately. Anchoring answers "is this the
		// same party", and a credential is a separate refusal with a separate
		// reason — the endpoint rule makes it, over this same reading.
		{"candidate_userinfo_is_ignored", "exchange.example", "https://user:pass@exchange.example/v1", true, false},
		{"schemeless_candidate_userinfo_is_ignored", "exchange.example", "user:pass@exchange.example", true, false},

		// IPv6 literals compare with their brackets stripped.
		{"ipv6_same_host_and_port", "[::1]:8443", "https://[::1]:8443/v1", true, false},
		{"ipv6_default_port_folds", "[::1]", "https://[::1]:443/v1", true, false},

		// Neither side can be unreadable.
		{"empty_anchor", "", "https://exchange.example", false, true},
		{"empty_candidate", "exchange.example", "", false, true},
		{"candidate_has_no_authority", "exchange.example", "/v1", false, true},
		{"candidate_control_character", "exchange.example", "https://exchange.example\n/v1", false, true},
		{"anchor_control_character", "exchange.example\n", "https://exchange.example", false, true},

		// The candidate half of the three fixes, at the surface a caller reaches for.
		// Each answered TRUE in a port before it read the reference the way the
		// oracle does — the first while the fetch would have gone somewhere else
		// entirely.
		{"candidate_backslash_in_userinfo", "exchange.example", "http://evil.example\\@exchange.example/rev", false, true},
		{"candidate_separator_in_a_path_segment", "exchange.example", "evil.example/x://exchange.example", false, true},
		{"candidate_scheme_starting_with_a_digit", "exchange.example", "1https://exchange.example/", false, true},
		{"candidate_doubled_colon_after_the_scheme", "exchange.example", "http:://exchange.example/", false, true},
		{"candidate_escape_in_query", "exchange.example", "https://exchange.example/v1?q=a%20b", true, false},
		{"candidate_escape_in_path", "exchange.example", "https://exchange.example/p%41th", true, false},
		{"candidate_malformed_escape_in_path", "exchange.example", "https://exchange.example/p%zzth", false, true},
		{"candidate_at_sign_in_the_path", "exchange.example", "https://exchange.example/v1@x", true, false},
	}
	out := make([]hostAnchoredVector, 0, len(cases))
	for _, c := range cases {
		anchored, err := HostAnchored(c.anchor, c.candidate)
		if (err != nil) != c.wantErr {
			t.Fatalf("host_anchored vector %s: oracle error=%v, intended error=%v", c.name, err, c.wantErr)
		}
		if anchored != c.want {
			t.Fatalf("host_anchored vector %s: oracle verdict=%v, intended=%v", c.name, anchored, c.want)
		}
		out = append(out, hostAnchoredVector{
			Name:      c.name,
			Anchor:    c.anchor,
			Candidate: c.candidate,
			Anchored:  anchored,
			Error:     err != nil,
		})
	}
	return out
}

// TestGenerateHostRuleVectors emits the host-rule golden corpus (host extraction,
// the plain-hostname predicate, and the anchor rule). Verification no-op by
// default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateHostRuleVectors(t *testing.T) {
	doc := map[string]any{
		"host_of":       buildHostOfVectors(t),
		"is_bare_host":  buildIsBareHostVectors(t),
		"host_anchored": buildHostAnchoredVectors(t),
	}
	path := filepath.Join("testdata", "host-rule-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
