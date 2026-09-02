package conformance

// Drift guard: the post-fold disjointness rule the SDKs enforce IS a rule the
// contract publishes.
//
// Disjointness is asserted twice, at two tiers, over two different readings of
// the same field. The wire tier's half is a protovalidate rule and needs no
// guard — it is IN the descriptor. The ingest tier's half is SDK code, and it
// cannot be a CEL rule for the reason the neighbouring ingest-tier checks give:
// the fold resolves aliases out of a generated vocabulary, and a CEL expression
// that re-listed that vocabulary would drift from it.
//
// So the rule exists twice — as SDK code, which is what the reference
// implementations run, and as prose in ramp.proto, which is what a third-party
// implementor reads. An implementor who read only the contract would otherwise
// build an Exchange that stores the term this rule exists to refuse, and every
// suite in every language would stay green. Nothing made the two agree; this
// file does.
//
// The halves work differently, as in regschema_rule_test.go. That the rule
// FIRES is read out of the committed vectors — conformance imports nothing from
// sdk/, so the ids arrive as data. That the contract STATES it is checked by
// reading the .proto SOURCE, because a comment does not survive into the
// descriptor and the comment is the thing an implementor actually reads.
//
// The phrases below are clauses only this rule's sentences can produce. A guard
// that matched a bare word would pass on text that never states the rule: the
// word "canonicalised" already occurs in several unrelated paragraphs of this
// file, and "disjoint" occurs in the wire rule's own id.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	rampProtoSource = "../proto/ramp/v1/ramp.proto"

	// The two ids. They are deliberately different strings: one name per rule, which
	// licenseterm_rule_ids_test.go enforces across the whole ingest-tier id set.
	canonicalDisjointRuleID = "restriction.canonical_disjoint"
	wireDisjointRuleID      = "restriction.permitted_prohibited_disjoint"
)

// canonicalDisjointFires reports whether the committed license-term vectors record
// the ingest-tier rule at all. Read as data: this package is the guard tier BELOW
// the SDKs and imports none of them.
func canonicalDisjointFires(t *testing.T) bool {
	t.Helper()
	b, err := os.ReadFile(licenseTermVectors)
	if err != nil {
		t.Fatalf("read %s: %v", licenseTermVectors, err)
	}
	var doc struct {
		Validate []struct {
			Violation *struct {
				Rule string `json:"rule"`
			} `json:"violation"`
		} `json:"validate"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode %s: %v", licenseTermVectors, err)
	}
	for _, v := range doc.Validate {
		if v.Violation != nil && v.Violation.Rule == canonicalDisjointRuleID {
			return true
		}
	}
	return false
}

// messageBody returns the source text between a declaration's opening brace and the
// first closing brace in column 1 — the whole body of a top-level message or service,
// including the comments inside it.
func messageBody(t *testing.T, src, decl string) string {
	t.Helper()
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("%s: %q not found — the guard is reading the wrong file or the declaration was renamed", rampProtoSource, decl)
	}
	rest := src[start:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("%s: %q is never closed in column 1", rampProtoSource, decl)
	}
	return rest[:end]
}

// docComment returns the run of // lines immediately above a declaration.
func docComment(t *testing.T, src, decl string) string {
	t.Helper()
	at := strings.Index(src, decl)
	if at < 0 {
		t.Fatalf("%s: %q not found", rampProtoSource, decl)
	}
	lines := strings.Split(src[:at], "\n")
	// The declaration starts a line, so the split ends with the empty string before it.
	// Dropping it is what makes the walk below start on the last comment line rather
	// than stopping instantly on a non-comment.
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	var out []string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "//") {
			break
		}
		out = append([]string{line}, out...)
	}
	return strings.Join(out, "\n")
}

func TestCanonicalDisjointRuleIsStatedByTheContract(t *testing.T) {
	if !canonicalDisjointFires(t) {
		t.Fatalf("no vector records %q — either the rule is gone or the corpus stopped covering it, "+
			"and this guard would be holding the contract to a rule nothing runs", canonicalDisjointRuleID)
	}

	b, err := os.ReadFile(rampProtoSource)
	if err != nil {
		t.Fatalf("read %s: %v", rampProtoSource, err)
	}
	src := string(b)

	// Where the rule is declared, the contract must say that the declared rule reads
	// the tokens as written and that the property is asserted again after the fold.
	// Both halves are load-bearing: an implementor who takes the CEL rule for the
	// whole rule builds the gap this exists to close.
	restriction := messageBody(t, src, "message Restriction {")
	for _, want := range []string{
		canonicalDisjointRuleID,
		"compares the tokens AS WRITTEN",
		"two spellings of ONE token pass this rule",
	} {
		if !strings.Contains(restriction, want) {
			t.Errorf("message Restriction does not state %q — the SDK refuses a term the contract does not say it refuses", want)
		}
	}

	// And the service comment, which is where a publisher reads what the Exchange
	// will run, must carry the rule in its ingest-tier list.
	catalog := docComment(t, src, "service CatalogService {")
	for _, want := range []string{
		canonicalDisjointRuleID,
		"BOTH tiers assert",
	} {
		if !strings.Contains(catalog, want) {
			t.Errorf("the CatalogService comment does not state %q — its two-tier description is incomplete", want)
		}
	}
}

// The two rules must keep two names. The ingest-tier id set is held to that as a
// whole elsewhere; this pins the specific pair, because these two are the ones a
// reader is most likely to collapse into one.
func TestCanonicalDisjointDoesNotDisplaceTheWireRule(t *testing.T) {
	if canonicalDisjointRuleID == wireDisjointRuleID {
		t.Fatal("the ingest-tier and wire-tier ids are the same string — one name for two rules")
	}
	var found bool
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if string(md.Name()) != "Restriction" {
			return
		}
		mr, err := protovalidate.ResolveMessageRules(md)
		if err != nil || mr == nil {
			return
		}
		for _, r := range mr.GetCel() {
			if r.GetId() == wireDisjointRuleID {
				found = true
			}
		}
	})
	if !found {
		t.Errorf("Restriction no longer declares %q — the ingest-tier rule reads the canonicalised tokens "+
			"and was never a replacement for the boundary check over the tokens as received", wireDisjointRuleID)
	}
}
