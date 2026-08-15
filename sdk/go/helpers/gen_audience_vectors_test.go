package helpers

// Audience-face golden-vector emitter.
//
// The bare-domain shape and the audience check are the two halves of "is this
// request addressed to me". Both are pure, both are about to exist in three
// languages, and both have to answer identically or a request one SDK accepts
// is one another refuses. This emitter is the oracle: every recorded verdict is
// DERIVED by calling the REAL Go face, never hand-typed, exactly as
// gen_util_vectors_test.go derives its canonical money strings.
//
// Each case still carries the verdict its AUTHOR intended, and the emitter
// refuses to write a file where the real face disagrees with that intent. That
// is what keeps a self-derived corpus honest: without it, a face that started
// answering the opposite would happily emit a corpus asserting the opposite,
// and every port would be dragged along.
//
// The pattern and the length bound are recorded in the document itself, beside
// the cases. That is deliberate: they are the values the protovalidate rule on
// the wire fields must carry, and a guard in the conformance tier reads them
// from here as data — the conformance package cannot import sdk/go, so a
// committed file is the only channel between the two tiers.
//
// Like TestGenerateVectors this test is a verification no-op by default (it
// asserts the committed file matches a fresh emit) and (re)writes under
// RAMP_UPDATE_VECTORS=1 — the emitter is both generator and drift gate. It is
// TEST INFRASTRUCTURE, not the code under test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bareDomainVector is one IsBareDomain case: a candidate value and whether the
// REAL face admits it as the shape the wire rule accepts.
type bareDomainVector struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

// audienceVector is one CheckAudience case: the recipient's own identity, the
// recipient values a request claimed, and the verdict the REAL face returns as
// its stable token. IdentityError records the other half of the face's answer —
// whether the call reported a fault in the recipient's own configuration rather
// than in the request — because a port that collapsed the two would otherwise
// pass on the token alone.
type audienceVector struct {
	Name          string   `json:"name"`
	Self          string   `json:"self"`
	Claimed       []string `json:"claimed"`
	Verdict       string   `json:"expected_verdict"`
	IdentityError bool     `json:"identity_error"`
}

// maxLenDomain is a value exactly MaxBareDomainLen long and otherwise valid, so
// the boundary case tests the bound rather than the alphabet.
func maxLenDomain() string { return "a." + strings.Repeat("b", MaxBareDomainLen-2) }

// buildBareDomainVectors enumerates the shapes the wire rule admits and the ones
// it refuses, including every separator a rich reference could smuggle in, both
// ends of the length bound, and the two values whose answer depends on how a
// port anchors its regex: a trailing newline is refused, and Python's `$` would
// accept it unless the port matches the WHOLE string.
func buildBareDomainVectors(t *testing.T) []bareDomainVector {
	t.Helper()
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		// Accepted.
		{"plain_domain", "exchange.example", true},
		{"subdomain", "eu.exchange.example", true},
		{"deep_subdomain", "a.b.c.exchange.example", true},
		{"single_label", "exchange", true},
		{"single_label_with_port", "exchange:8081", true},
		{"host_with_port", "exchange.example:8443", true},
		{"host_with_default_port", "exchange.example:443", true},
		{"hyphen_inside_label", "ex-change.example", true},
		{"digits_in_label", "ex1.exchange2.example", true},
		{"all_digit_label", "1.2.3.4", true},
		{"uppercase", "Exchange.Example", true},
		{"max_length", maxLenDomain(), true},
		{"port_one_digit", "exchange.example:8", true},
		{"port_max", "exchange.example:65535", true},

		// Refused — not a domain at all.
		{"empty", "", false},
		{"whitespace_only", "   ", false},
		{"leading_space", " exchange.example", false},
		{"trailing_space", "exchange.example ", false},
		{"trailing_newline", "exchange.example\n", false},
		{"embedded_newline", "exchange\n.example", false},

		// Refused — a reference richer than a domain.
		{"https_scheme", "https://exchange.example", false},
		{"http_scheme", "http://exchange.example", false},
		{"scheme_relative", "//exchange.example", false},
		{"path_suffix", "exchange.example/v1", false},
		{"root_path", "exchange.example/", false},
		{"query", "exchange.example?x=1", false},
		{"fragment", "exchange.example#frag", false},
		{"userinfo", "agent@exchange.example", false},
		{"scheme_and_path", "https://exchange.example/v1", false},

		// Refused — a bad port. The rule is a real 1-65535 range, not a digit
		// count, so the cases that separate the two belong here: a port outside
		// the range names nothing, and a leading zero makes a different string
		// rather than another spelling of the same port.
		{"trailing_colon", "exchange.example:", false},
		{"non_numeric_port", "exchange.example:https", false},
		{"port_too_long", "exchange.example:123456", false},
		{"two_ports", "exchange.example:80:443", false},
		{"port_zero", "exchange.example:0", false},
		{"port_above_max", "exchange.example:65536", false},
		{"port_five_digits_out_of_range", "exchange.example:99999", false},
		{"port_leading_zero", "exchange.example:0443", false},
		{"port_leading_zeros", "exchange.example:00443", false},
		{"port_leading_zero_short", "exchange.example:012", false},

		// Refused — a bad label.
		{"leading_hyphen", "-exchange.example", false},
		{"trailing_hyphen", "exchange-.example", false},
		{"underscore", "_acme.example", false},
		{"empty_label", "exchange..example", false},
		{"leading_dot", ".exchange.example", false},
		{"trailing_root_dot", "exchange.example.", false},
		{"ipv6_literal", "[::1]", false},
		{"ipv6_literal_with_port", "[::1]:443", false},
		{"wildcard", "*.exchange.example", false},
		// The wire alphabet is ASCII, so an internationalized name is carried in
		// its punycode form — the same name, and accepted.
		{"non_ascii", "exchänge.example", false},
		{"punycode_of_the_same_name", "xn--exchnge-8wa.example", true},
		// Two homographs that look like ASCII labels and are not. They are here
		// because the ONLY thing that refuses them is running this shape check
		// before any case or width normalization, and they fail differently:
		//
		//   U+212A KELVIN SIGN lowercases to a plain ASCII "k" — so lowercasing
		//   first turns this value INTO a valid domain, and an implementation
		//   that folds case before checking the shape would admit it.
		//
		//   U+FF25 FULLWIDTH LATIN CAPITAL E lowercases to fullwidth "ｅ", which
		//   is still outside the alphabet, so it survives the case mutant
		//   untouched. It becomes ASCII only under NFKC.
		//
		// Neither is redundant: each is the only case in the corpus that catches
		// its own wrong ordering. Deleting either re-opens a homograph bypass.
		{"kelvin_sign_label", "mar\u212Aet.example", false},
		{"fullwidth_letter", "\uFF25xchange.example", false},

		// Refused — over the length bound.
		{"over_max_length", maxLenDomain() + "b", false},
	}
	out := make([]bareDomainVector, 0, len(cases))
	for _, c := range cases {
		got := IsBareDomain(c.value)
		if got != c.want {
			t.Fatalf("bare-domain vector %s: oracle verdict=%v, intended=%v for %q", c.name, got, c.want, c.value)
		}
		out = append(out, bareDomainVector{Name: c.name, Value: c.value, Valid: got})
	}
	return out
}

// buildAudienceVectors enumerates what an addressed request can claim. The
// per-item shape is here in full — a TransactionRequest states its audience once
// per item, so a many-valued claim where exactly one item names somebody else,
// or carries nothing at all, is the case that decides whether the check reads
// every item or only the first.
func buildAudienceVectors(t *testing.T) []audienceVector {
	t.Helper()
	const self = "exchange.example"
	cases := []struct {
		name        string
		self        string
		claimed     []string
		want        string
		wantIDError bool
	}{
		// Accepted.
		{"exact_match", self, []string{self}, "accepted", false},
		{"case_folded_claim", self, []string{"Exchange.Example"}, "accepted", false},
		{"case_folded_identity", "Exchange.Example", []string{self}, "accepted", false},
		{"default_port_on_claim", self, []string{"exchange.example:443"}, "accepted", false},
		{"default_port_on_identity", "exchange.example:443", []string{self}, "accepted", false},
		{"default_port_on_both", "exchange.example:443", []string{"exchange.example:443"}, "accepted", false},
		{"same_non_default_port", "exchange:8081", []string{"exchange:8081"}, "accepted", false},
		{"many_all_match", self, []string{self, "Exchange.Example", "exchange.example:443"}, "accepted", false},
		// Case folding CROSSED with a port that is not the folded one. Every other
		// accepted case folds case on a bare name or folds :443 on a lowercase
		// name, so an implementation that lowercased only inside its "no port or
		// :443" branch would pass all of them and answer mismatch here.
		{"case_folded_on_a_non_default_port", "exchange:8081", []string{"Exchange:8081"}, "accepted", false},
		{"case_folded_identity_on_a_non_default_port", "Exchange.Example:8443", []string{"exchange.example:8443"}, "accepted", false},

		// Refused — names somebody else.
		{"unrelated_host", self, []string{"other.example"}, "mismatch", false},
		{"subdomain_is_not_this_exchange", self, []string{"eu.exchange.example"}, "mismatch", false},
		{"parent_is_not_this_exchange", "eu.exchange.example", []string{self}, "mismatch", false},
		{"label_boundary_not_a_prefix", self, []string{"evil-exchange.example"}, "mismatch", false},
		{"suffix_without_boundary", "a.example", []string{"xa.example"}, "mismatch", false},
		{"port_is_part_of_the_identity", "exchange:8081", []string{"exchange"}, "mismatch", false},
		{"different_non_default_port", "exchange:8081", []string{"exchange:9000"}, "mismatch", false},
		{"port_80_is_not_folded", self, []string{"exchange.example:80"}, "mismatch", false},
		{"many_one_mismatch", self, []string{self, "other.example"}, "mismatch", false},
		{"many_last_mismatch", self, []string{self, self, "other.example"}, "mismatch", false},

		// Two values that fail DIFFERENTLY, in both orders, for every pair of
		// fault kinds. Each case is decided by its FIRST element, which is the
		// property under test: without these, an implementation that scanned for
		// empties across the whole list before comparing any of them would agree
		// with the oracle on every other case in this corpus and disagree here.
		{"first_fault_mismatch_before_empty", self, []string{"other.example", ""}, "mismatch", false},
		{"first_fault_empty_before_mismatch", self, []string{"", "other.example"}, "empty", false},
		{"first_fault_malformed_before_mismatch", self, []string{"https://other.example", "other.example"}, "malformed", false},
		{"first_fault_mismatch_before_malformed", self, []string{"other.example", "https://other.example"}, "mismatch", false},
		{"first_fault_empty_before_malformed", self, []string{"", "https://other.example"}, "empty", false},
		{"first_fault_malformed_before_empty", self, []string{"https://other.example", ""}, "malformed", false},

		// Refused — claimed nobody.
		{"no_values", self, nil, "empty", false},
		{"empty_value", self, []string{""}, "empty", false},
		{"many_one_empty", self, []string{self, ""}, "empty", false},

		// Refused — the claim is not a domain.
		{"claim_carries_a_scheme", self, []string{"https://exchange.example"}, "malformed", false},
		{"claim_carries_a_path", self, []string{"exchange.example/v1"}, "malformed", false},
		{"claim_carries_userinfo", self, []string{"agent@exchange.example"}, "malformed", false},
		{"claim_has_a_root_dot", self, []string{"exchange.example."}, "malformed", false},
		{"claim_has_a_bad_port", self, []string{"exchange.example:123456"}, "malformed", false},
		// A padded 443 is refused for its SHAPE, before folding is even reached.
		// Folding turns ":443" into no port at all, so were the shape rule looser
		// this would have had to be caught as a mismatch instead — the two rules
		// have to be read together to see that neither lets it through.
		{"claim_has_a_padded_port", self, []string{"exchange.example:0443"}, "malformed", false},
		// A claim that becomes the identity if it is normalized before its shape
		// is checked. Both are refused for their shape and never reach the
		// comparison — which is the whole reason the shape check runs first, and
		// the only place in this corpus where getting that order wrong is visible
		// as an ACCEPTANCE rather than as a differently-worded refusal.
		{"claim_is_a_kelvin_homograph", "market.example", []string{"mar\u212Aet.example"}, "malformed", false},
		{"claim_is_a_fullwidth_homograph", self, []string{"\uFF25xchange.example"}, "malformed", false},
		{"many_one_malformed", self, []string{self, "https://other.example"}, "malformed", false},
		// A malformed claim is refused for its shape, before it is compared — so
		// a value that would have matched had it been spelled properly is still
		// malformed and not a mismatch.
		{"malformed_claim_outranks_a_mismatch", self, []string{"https://other.example"}, "malformed", false},

		// The recipient's own configuration is unusable: no verdict, and a fault
		// in this deployment rather than in the request.
		{"identity_empty", "", []string{self}, "no_verdict", true},
		{"identity_carries_a_scheme", "https://exchange.example", []string{self}, "no_verdict", true},
		{"identity_carries_a_path", "exchange.example/v1", []string{self}, "no_verdict", true},
		{"identity_has_a_root_dot", "exchange.example.", []string{self}, "no_verdict", true},
		// Checked before the claims are read, so an unusable identity is reported
		// even when the request itself is also wrong.
		{"identity_unusable_and_claim_empty", "", []string{""}, "no_verdict", true},
	}
	out := make([]audienceVector, 0, len(cases))
	for _, c := range cases {
		verdict, err := CheckAudience(c.self, c.claimed...)
		if verdict.String() != c.want {
			t.Fatalf("audience vector %s: oracle verdict=%s, intended=%s", c.name, verdict, c.want)
		}
		if (err != nil) != c.wantIDError {
			t.Fatalf("audience vector %s: oracle identity error=%v, intended=%v", c.name, err, c.wantIDError)
		}
		claimed := c.claimed
		if claimed == nil {
			claimed = []string{}
		}
		out = append(out, audienceVector{
			Name:          c.name,
			Self:          c.self,
			Claimed:       claimed,
			Verdict:       verdict.String(),
			IdentityError: err != nil,
		})
	}
	return out
}

// TestGenerateAudienceVectors emits the audience golden corpus (the bare-domain
// shape and the audience check). Verification no-op by default, (re)writes under
// RAMP_UPDATE_VECTORS=1.
func TestGenerateAudienceVectors(t *testing.T) {
	doc := map[string]any{
		"bare_domain_pattern": BareDomainPattern,
		"bare_domain_max_len": MaxBareDomainLen,
		"bare_domain":         buildBareDomainVectors(t),
		"audience":            buildAudienceVectors(t),
	}
	path := filepath.Join("testdata", "audience-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
