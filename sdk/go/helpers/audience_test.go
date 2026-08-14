package helpers_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// The case-by-case verdict table lives in the shared conformance vectors, which
// the emitter derives from this same face and the Python and TypeScript ports
// replay. What is tested here is what a vector cannot carry: that the error path
// is an error rather than a verdict, that the zero value is not an acceptance,
// and that the two host predicates keep disagreeing on purpose.

// A caller who ignores the error must not read the zero value as a pass. That is
// the whole reason AudienceAccepted is not the zero value, so it is pinned here
// rather than left to the declaration order.
func TestCheckAudience_UnusableIdentityIsAnErrorAndNeverAnAcceptance(t *testing.T) {
	for _, self := range []string{"", "https://exchange.example", "exchange.example/v1", "-bad.example", "exchange.example."} {
		verdict, err := helpers.CheckAudience(self, "exchange.example")
		if !errors.Is(err, helpers.ErrAudienceIdentity) {
			t.Errorf("CheckAudience(%q, ...) error = %v, want ErrAudienceIdentity", self, err)
		}
		if verdict != helpers.AudienceNoVerdict {
			t.Errorf("CheckAudience(%q, ...) verdict = %v, want AudienceNoVerdict", self, verdict)
		}
		if verdict == helpers.AudienceAccepted {
			t.Errorf("CheckAudience(%q, ...) accepted on an unusable identity", self)
		}
	}
	var zero helpers.AudienceVerdict
	if zero == helpers.AudienceAccepted {
		t.Error("the zero AudienceVerdict is an acceptance; a caller ignoring the error would pass the request")
	}
}

// Everything the REQUEST can get wrong is a verdict, so a caller can map request
// faults and deployment faults onto different status codes without reading text.
func TestCheckAudience_RequestFaultsAreVerdictsNotErrors(t *testing.T) {
	cases := map[string][]string{
		"no values":       {},
		"empty value":     {""},
		"malformed value": {"https://exchange.example"},
		"other Exchange":  {"other.example"},
		"one bad of many": {"exchange.example", "other.example"},
	}
	for name, claimed := range cases {
		t.Run(name, func(t *testing.T) {
			verdict, err := helpers.CheckAudience("exchange.example", claimed...)
			if err != nil {
				t.Fatalf("CheckAudience(...) error = %v, want a verdict", err)
			}
			if verdict == helpers.AudienceAccepted {
				t.Errorf("CheckAudience(%q, %q) = accepted", "exchange.example", claimed)
			}
		})
	}
}

// The vectors record the token, not the number, so the token is what must stay
// put. A verdict rendering as its integer would silently un-assert every port.
func TestAudienceVerdict_Tokens(t *testing.T) {
	want := map[helpers.AudienceVerdict]string{
		helpers.AudienceNoVerdict: "no_verdict",
		helpers.AudienceAccepted:  "accepted",
		helpers.AudienceEmpty:     "empty",
		helpers.AudienceMalformed: "malformed",
		helpers.AudienceMismatch:  "mismatch",
	}
	seen := map[string]bool{}
	for verdict, token := range want {
		if got := verdict.String(); got != token {
			t.Errorf("AudienceVerdict(%d).String() = %q, want %q", int(verdict), got, token)
		}
		if seen[token] {
			t.Errorf("token %q is shared by two verdicts", token)
		}
		seen[token] = true
	}
}

// IsBareDomain and IsBareHost answer different questions, and every value below
// is one both would be asked about. Pinned so a later change that "unifies" them
// has to delete a test that says why they are not the same predicate: the first
// asks whether a value is safe to build a URL from, the second whether it is the
// shape the wire admits.
func TestIsBareDomain_DivergesFromIsBareHostOnPurpose(t *testing.T) {
	for _, ref := range []string{
		"exchange.example.", // a usable host; the wire rule has no trailing root dot
		"-exchange.example", // a usable host; a label may not start with a hyphen
		"exchange-.example", // a usable host; a label may not end with one either
		"_acme.example",     // a usable host; underscores are not in the wire alphabet
		"[::1]:443",         // a usable host; the wire rule takes no bracketed literal
		"exchange.example:", // refused by both, for different reasons
	} {
		bareHost, err := helpers.IsBareHost(ref)
		if err != nil {
			t.Fatalf("IsBareHost(%q): %v", ref, err)
		}
		if helpers.IsBareDomain(ref) {
			t.Errorf("IsBareDomain(%q) = true, want false (IsBareHost says %v)", ref, bareHost)
		}
	}
	// The far side of the same claim: what both accept, so the divergence above
	// reads as narrowing rather than as two unrelated predicates.
	for _, ref := range []string{"exchange.example", "eu.exchange.example", "exchange:8081", "1.2.3.4"} {
		bareHost, err := helpers.IsBareHost(ref)
		if err != nil || !bareHost {
			t.Fatalf("IsBareHost(%q) = %v, %v; want true", ref, bareHost, err)
		}
		if !helpers.IsBareDomain(ref) {
			t.Errorf("IsBareDomain(%q) = false, want true", ref)
		}
	}
}

// The length bound is the protovalidate max_len. It is checked before the
// pattern so no unbounded input reaches a backtracking engine in the ports.
func TestIsBareDomain_LengthBoundary(t *testing.T) {
	at := "a." + strings.Repeat("b", helpers.MaxBareDomainLen-2)
	if len(at) != helpers.MaxBareDomainLen {
		t.Fatalf("test fixture is %d long, want %d", len(at), helpers.MaxBareDomainLen)
	}
	if !helpers.IsBareDomain(at) {
		t.Errorf("IsBareDomain(<%d chars>) = false, want true", len(at))
	}
	over := at + "b"
	if helpers.IsBareDomain(over) {
		t.Errorf("IsBareDomain(<%d chars>) = true, want false", len(over))
	}
}
