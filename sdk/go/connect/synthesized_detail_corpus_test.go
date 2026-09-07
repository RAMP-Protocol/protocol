package connect_test

// The oracle's own replay of the synthesized-detail corpus.
//
// The emitter beside this file already fails when the committed bytes drift from what the
// client produces, so equality is not what this adds. What it adds is the OBLIGATIONS the
// corpus has to keep to be worth replaying at all: that both member shapes are exercised,
// that a recorded typed reason really is the one the SDK's own token table names, and
// that the untyped rows stay untyped. A corpus can be regenerated into agreeing with a
// regression; it cannot be regenerated into satisfying these.

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func loadSynthesizedDetailCorpus(t *testing.T) ([]precheckVector, []edgeRefusalVector) {
	t.Helper()
	b, err := os.ReadFile(synthesizedDetailVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", synthesizedDetailVectorsPath, err)
	}
	var doc struct {
		Precheck []precheckVector    `json:"registration_precheck"`
		Edge     []edgeRefusalVector `json:"edge_refusal"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", synthesizedDetailVectorsPath, err)
	}
	if len(doc.Precheck) == 0 || len(doc.Edge) == 0 {
		t.Fatalf("%s carries an empty case list; this replay would assert nothing",
			synthesizedDetailVectorsPath)
	}
	return doc.Precheck, doc.Edge
}

// The pre-check rows have to carry BOTH member shapes somewhere, because they are
// rendered differently and one of them was rendered wrong: an empty pointer addresses the
// whole object, and writing "path: error" for it produced a member with no name. A corpus
// that only ever recorded named members would have pinned the bug.
func TestSynthesizedDetailCorpus_CarriesBothMemberShapes(t *testing.T) {
	precheck, _ := loadSynthesizedDetailCorpus(t)

	var sawRoot, sawMember bool
	for _, v := range precheck {
		if len(v.FieldErrorPaths) == 0 {
			t.Errorf("%s: a refusal row names no offending member", v.Name)
		}
		for _, p := range v.FieldErrorPaths {
			if p == "" {
				sawRoot = true
			} else {
				sawMember = true
			}
		}
		if v.Domain == "" || v.Message == "" || v.ReasonField == "" {
			t.Errorf("%s: a refusal row records no failing surface, sentence or reason", v.Name)
		}
	}
	if !sawRoot {
		t.Error("no row carries the empty pointer, so nothing pins how a whole-object " +
			"failure is reported")
	}
	if !sawMember {
		t.Error("no row carries a member pointer, so nothing pins the ordinary case")
	}
}

// A recorded reason is the one the SDK's own token table names, and a row recorded as
// untyped is one the table deliberately does not name. Read against the table rather than
// restated, so a token that gains or loses a mapping cannot leave the corpus asserting the
// old answer.
func TestSynthesizedDetailCorpus_EdgeRowsAgreeWithTheTokenTable(t *testing.T) {
	_, edge := loadSynthesizedDetailCorpus(t)

	var typed int
	for _, v := range edge {
		reason, mapped := helpers.RetrievalAuthFailureReasonFromToken(v.ReasonToken)
		switch {
		case mapped && v.ReasonEnum != reason.String():
			t.Errorf("%s: recorded %q, table names %q", v.Name, v.ReasonEnum, reason)
		case mapped && v.ReasonField != "retrieval_auth_failure":
			t.Errorf("%s: a mapped token recorded reason field %q", v.Name, v.ReasonField)
		case mapped && v.Domain == "":
			t.Errorf("%s: a mapped token recorded no failing surface", v.Name)
		case !mapped && (v.ReasonEnum != "" || v.Domain != ""):
			t.Errorf("%s: %q is not in the token table, so no detail may be recorded for it",
				v.Name, v.ReasonToken)
		}
		if mapped {
			typed++
		}
	}

	// Both verdicts have to be present. Rows that are all typed prove nothing about
	// over-promotion, and a token no edge emits must not acquire a reason from the shape
	// of its own spelling.
	if typed == 0 || typed == len(edge) {
		t.Errorf("edge rows record only one verdict (%d typed of %d); the corpus must "+
			"carry both what is promoted and what deliberately is not", typed, len(edge))
	}
	if !slices.ContainsFunc(edge, func(v edgeRefusalVector) bool {
		return v.ReasonToken == "missing_sig"
	}) {
		t.Error("no row for the token the protocol records against TWO values; that is the " +
			"case where guessing is the failure, so it is the one a corpus must hold")
	}
}
