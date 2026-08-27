package conformance

// Drift guard: the endpoint rule the SDKs enforce IS the rule the contract states.
//
// WellKnownManifest.endpoint carries a normative MUST, and it exists nowhere else.
// The field is a plain optional string: no protovalidate rule can say "on the host
// that served this document", because the rule is about a relationship between the
// value and where the value came from, which a field constraint cannot see. So the
// contract's whole statement of the rule is prose in that field's comment, and the
// enforcement is code in three SDKs.
//
// Between them sits the shared corpus, which pins the three implementations to each
// other. Nothing pinned any of them to the prose. That is the gap this file closes,
// and it is the gap that matters most for a rule with no descriptor to compare
// against: an implementor reading the proto and an implementor replaying the
// vectors could be reading two different rules, and every gate in the repo would
// stay green.
//
// Same construction as regschema_rule_test.go, and for the same reason. Both halves
// are DATA READS: the comment is scanned out of the .proto source, and the SDK's
// verdicts are read out of the committed vectors. Nothing here imports sdk/go —
// conformance is the guard tier BELOW the SDKs, and a guard that linked against the
// thing it guards would agree with it by construction.

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

// endpointVetVectors is the SDK's committed verdict set for the rule, read as data.
const endpointVetVectors = "../sdk/go/resolvers/testdata/endpoint-vet-vectors.json"

// endpointDecl is the field whose comment carries the rule.
const endpointDecl = "optional string endpoint = 12"

type endpointVetCase struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	Refused  bool   `json:"refused"`
}

var errNoEndpointVectors = errors.New(
	"the endpoint-vet corpus is missing or empty — regenerate it with " +
		"RAMP_UPDATE_VECTORS=1 go test ./sdk/go/resolvers/ -run TestGenerateEndpointVetVectors")

var sdkEndpointCases = sync.OnceValues(func() (map[string]endpointVetCase, error) {
	b, err := os.ReadFile(endpointVetVectors)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Cases []endpointVetCase `json:"endpoint_vet"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Cases) == 0 {
		return nil, errNoEndpointVectors
	}
	out := make(map[string]endpointVetCase, len(doc.Cases))
	for _, c := range doc.Cases {
		out[c.Name] = c
	}
	return out, nil
})

func mustEndpointCases(t *testing.T) map[string]endpointVetCase {
	t.Helper()
	cases, err := sdkEndpointCases()
	if err != nil {
		t.Fatalf("read %s: %v", endpointVetVectors, err)
	}
	return cases
}

// TestEndpointCommentStatesEveryClauseTheSDKEnforces reads the rule out of the
// contract and holds it to the clauses the SDK actually applies.
//
// The phrases are the load-bearing halves of each clause rather than whole
// sentences: a sentence pinned verbatim turns every rewording into a failure and
// teaches the next author to edit the test instead of thinking about the rule.
func TestEndpointCommentStatesEveryClauseTheSDKEnforces(t *testing.T) {
	comment := fieldComment(t, endpointDecl)

	// Guard the guard: pin the extraction to the block it is supposed to have read.
	// A reader that over-reached — returning the whole file, or the banner above the
	// enclosing message — would satisfy every phrase below while checking nothing,
	// and the failure would look like a pass.
	const opening = "Exchange-only. ExchangeService endpoint URL."
	if !strings.HasPrefix(comment, opening) {
		t.Fatalf("the extracted comment does not begin with endpoint's own first line "+
			"(%q) — this guard is reading the wrong block and would assert nothing.\n  read: %.120s…",
			opening, comment)
	}

	for _, clause := range []struct {
		name   string
		phrase string
		why    string
	}{
		{"same host", "MUST be on the same host",
			"the anchor is the host that SERVED the manifest"},
		{"same port", "PORT that serve this manifest",
			"another port is another service the publisher need not control"},
		{"subdomain admitted", "or on a subdomain of that host on that port",
			"an Exchange may front itself from its own subdomain"},
		{"no userinfo", "MUST NOT carry userinfo",
			"credentials would have the client stamp an Authorization header the SDK never chose"},
		{"label boundary", "full dot-delimited label boundary",
			"a bare suffix match is the mistake an attacker registers a domain to exploit"},
		{"default port folds", "and an omitted port\n// are the SAME port",
			"refusing an operator who wrote :443 out in full is a spelling check, not a security check"},
	} {
		if !strings.Contains(comment, strings.ReplaceAll(clause.phrase, "\n// ", " ")) {
			t.Errorf("the endpoint comment no longer states %q (%s).\n"+
				"The SDKs still enforce it and the corpus still pins it, so the contract and the "+
				"implementations have drifted — restore the clause or change all four together.",
				clause.name, clause.why)
		}
	}
}

// TestEndpointCorpusCoversEveryStatedClause holds the other direction. A clause the
// contract states and no vector exercises is a clause three SDKs could quietly stop
// enforcing, and the comment above would still read correctly.
func TestEndpointCorpusCoversEveryStatedClause(t *testing.T) {
	cases := mustEndpointCases(t)

	for _, want := range []struct {
		name    string
		refused bool
		clause  string
	}{
		{"self", false, "an Exchange may advertise itself"},
		{"subdomain", false, "…or a subdomain of itself"},
		{"default_port_written_out", false, "a written-out default port is the same port"},
		{"unrelated_host", true, "same host"},
		{"another_port", true, "same port"},
		{"label_boundary_trick", true, "full label boundary"},
		{"userinfo", true, "no userinfo"},
		{"schemeless_userinfo", true, "no userinfo, in the spelling a second parse misses"},
	} {
		got, ok := cases[want.name]
		if !ok {
			t.Errorf("the endpoint-vet corpus has no case %q, which is what pins %q",
				want.name, want.clause)
			continue
		}
		if got.Refused != want.refused {
			t.Errorf("corpus case %q refused=%v, want %v — the SDK's verdict for %q moved",
				want.name, got.Refused, want.refused, want.clause)
		}
	}
}

// TestEndpointCorpusIsNotVacuous keeps both partitions populated. A corpus that lost
// one of them would let the assertions above pass while proving half the rule.
func TestEndpointCorpusIsNotVacuous(t *testing.T) {
	cases := mustEndpointCases(t)
	var refused, accepted int
	for _, c := range cases {
		if c.Refused {
			refused++
		} else {
			accepted++
		}
	}
	if refused == 0 || accepted == 0 {
		t.Fatalf("endpoint-vet corpus has %d refused and %d accepted cases — a rule that only "+
			"ever refuses, or only ever accepts, is not the rule the contract states",
			refused, accepted)
	}
}

// catalogEndpointDecl is the second field whose comment carries the same rule.
// A publisher's push is a signed call to the address this field names, so it
// binds exactly as `endpoint` does; stating the rule on one field and not the
// other would leave the catalog leg redirectable by a manifest.
const catalogEndpointDecl = "optional string catalog_endpoint = 14"

// TestCatalogEndpointCommentStatesTheSameClauses holds the catalog endpoint's
// comment to the identical clause set, so a clause present on one comment and
// absent from the other cannot make the contract say two different things about
// one rule.
//
// Note precisely what this guards, and what it does not. It compares two COMMENTS.
// No SDK reads catalog_endpoint at all today — the catalog client takes its address
// as configuration and the endpoint predicate is reachable only from the agent
// endpoint's resolver — so nothing here proves any code obeys the rule the comment
// states. The rule is a consumer obligation a deployment that reads the field from
// a manifest must honour itself; a resolver that would make it callable is the
// recorded follow-up, and this guard is what keeps the two statements of it aligned
// until then.
func TestCatalogEndpointCommentStatesTheSameClauses(t *testing.T) {
	comment := fieldComment(t, catalogEndpointDecl)

	// Guard the guard, as above: pin the extraction to this field's own block.
	const opening = "Exchange-only. CatalogService endpoint URL"
	if !strings.HasPrefix(comment, opening) {
		t.Fatalf("the extracted comment does not begin with catalog_endpoint's own first line "+
			"(%q) — this guard is reading the wrong block and would assert nothing.\n  read: %.120s…",
			opening, comment)
	}

	for _, clause := range []struct {
		name   string
		phrase string
	}{
		{"same host", "MUST be on the same host"},
		{"same port", "PORT that serve this manifest"},
		{"subdomain admitted", "or on a subdomain of that host on that port"},
		{"no userinfo", "MUST NOT carry userinfo"},
		{"label boundary", "full dot-delimited label boundary"},
		{"default port folds", "and an omitted port are the SAME port"},
		{"no fallback", "does not fall back to endpoint"},
	} {
		if !strings.Contains(comment, clause.phrase) {
			t.Errorf("the catalog_endpoint comment no longer states %q — the catalog leg is vetted "+
				"by the same predicate as the exchange endpoint, so the two comments must state "+
				"the same rule; restore the clause on both or change the predicate everywhere.",
				clause.name)
		}
	}
}
