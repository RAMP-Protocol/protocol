package helpers

import (
	"encoding/json"
	"testing"
)

// Properties of the two counters behind the registration-schema bounds.
//
// The shared corpus pins what a given document ANSWERS. These are about the counters
// themselves: that the reference bound measures the document rather than the walk that
// read it, and that the two depth counters — one over a schema's bytes, one over a
// decoded payload — count the same thing. Both were silently untrue, and neither is
// expressible as a vector: the first needs one graph written two ways, and the second
// compares two functions against each other rather than against an expected verdict.

// A payload and a schema are different documents asked the same question, and the
// contract says so: the payload's depth cap is "the same number and the same counting
// rule" as the schema's. rawNestingDepth counts a document's opening braces and
// brackets, so registrationDataDepth has to agree with it on every shape — including
// the ones where a value sits at the leaf, which is what every real payload looks like.
func TestTheTwoDepthCountersCountTheSameThing(t *testing.T) {
	for _, doc := range []string{
		`{}`,
		`{"a":"x"}`,
		`{"a":{}}`,
		`{"a":{"a":"x"}}`,
		`{"a":[1,2]}`,
		`{"a":[[1],[2]]}`,
		`{"a":[{"b":"x"}]}`,
		`{"a":"x","b":{"c":{"d":1}}}`,
		`{"legal_name":"Acme GmbH","address":{"city":"Berlin","postal_code":"10115"}}`,
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		schemaSide := rawNestingDepth([]byte(doc))
		payloadSide := registrationDataDepth(m)
		if schemaSide != payloadSide {
			t.Errorf("%s: schema side counts %d containers, payload side counts %d",
				doc, schemaSide, payloadSide)
		}
	}
}

// A scalar is a value, not a container. Spelled out separately from the agreement test
// above so a change that breaks BOTH counters the same way still fails something.
func TestRegistrationDataDepthCountsContainersOnly(t *testing.T) {
	for _, tc := range []struct {
		doc  string
		want int
	}{
		{`{}`, 1},
		{`{"a":"x"}`, 1},
		{`{"a":null}`, 1},
		{`{"a":{}}`, 2},
		{`{"a":{"a":"x"}}`, 2},
		{`{"a":[1,2]}`, 2},
		{`{"a":[{"b":1}]}`, 3},
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(tc.doc), &m); err != nil {
			t.Fatalf("%s: %v", tc.doc, err)
		}
		if got := registrationDataDepth(m); got != tc.want {
			t.Errorf("%s: nests %d containers, counted %d", tc.doc, tc.want, got)
		}
	}
}

// The reference bound is over a graph, and a graph does not have an order. Writing the
// same definitions and the same links in two orders has to reach the same verdict: the
// two ends of one registration read the same schema, and neither has any say in how its
// members happen to be arranged.
func TestTheReferenceBoundDoesNotDependOnDocumentOrder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		head, tail int
		want       SchemaVerdict
	}{
		{"over the cap", 95, 50, SchemaRefChainTooLong},
		{"at the cap", 60, 40, SchemaAccepted},
		{"one hop over", 60, 41, SchemaRefChainTooLong},
	} {
		// Three writings of one graph: the branches listed either way, and the tail
		// named so it sorts before the head. Listing order is what a walk following the
		// document sees; naming order is what a walk draining pending references sees.
		// Neither is a property of the graph, so neither may change the answer.
		got := map[string]SchemaVerdict{
			"long branch first":  checkEvaluationCost(mustDecode(t, sharedTailRefChain(tc.head, tc.tail, false, "h", "t"))),
			"short branch first": checkEvaluationCost(mustDecode(t, sharedTailRefChain(tc.head, tc.tail, true, "h", "t"))),
			"tail sorts first":   checkEvaluationCost(mustDecode(t, sharedTailRefChain(tc.head, tc.tail, false, "z", "a"))),
		}
		for writing, verdict := range got {
			if verdict != tc.want {
				t.Errorf("%s, %s: got %v, want %v", tc.name, writing, verdict, tc.want)
			}
		}
	}
}

// Entering one chain at several points does not make it several chains. Every segment
// between two seeds is under the cap and the chain is not, so a count that remembers
// only how far the walk has come lets the whole document through.
func TestTheReferenceBoundMeasuresTheChainNotTheSegment(t *testing.T) {
	const links = 150 // against a cap of 100
	for _, every := range []int{80, 50, 25, 10} {
		if got := checkEvaluationCost(mustDecode(t, seededRefChain(links, every))); got != SchemaRefChainTooLong {
			t.Errorf("a %d-link chain seeded every %d links: got %v, want %v",
				links, every, got, SchemaRefChainTooLong)
		}
	}
}

func mustDecode(t *testing.T, raw string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decoding a generated schema: %v", err)
	}
	return doc
}
