package ramphelpers_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

type corpusCase struct {
	ID      string          `json:"id"`
	Message string          `json:"message"`
	Valid   bool            `json:"valid"`
	Rules   []string        `json:"rules"`
	JSON    json.RawMessage `json:"json"`
}

func loadCorpusFile(t *testing.T, path string) []corpusCase {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (run 'go run ./conformance/corpusgen'): %v", path, err)
	}
	var cs []corpusCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(cs) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return cs
}

func unmarshalCase(t *testing.T, c corpusCase) protoreflect.ProtoMessage {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName("ramp.v1." + c.Message))
	if err != nil {
		t.Fatalf("unknown message ramp.v1.%s: %v", c.Message, err)
	}
	m := mt.New().Interface()
	if err := protojson.Unmarshal(c.JSON, m); err != nil {
		t.Fatalf("unmarshal proto-JSON for %s: %v", c.ID, err)
	}
	return m
}

// TestValidate_matchesCorpusVerdict proves the Go L1 validator reaches the SAME
// verdict as the protovalidate oracle on every field-level corpus case — i.e.
// ramphelpers.Validate IS the requirement's executable form, no drift.
func TestValidate_matchesCorpusVerdict(t *testing.T) {
	for _, c := range loadCorpusFile(t, "../../../conformance/corpus/cases.json") {
		t.Run(c.ID, func(t *testing.T) {
			err := ramphelpers.Validate(unmarshalCase(t, c))
			if c.Valid && err != nil {
				t.Errorf("corpus VALID but Validate rejects: %v", err)
			}
			if !c.Valid && err == nil {
				t.Errorf("corpus INVALID but Validate accepts")
			}
		})
	}
}

// TestValidate_enforcesCrossFieldCEL is the cross-field guardrail: every mutant
// in crossfield.json must be rejected by the L1 validator, with the recorded
// message-CEL rule id present. This is the gap field-level Zod/Pydantic miss; the
// Go L1 closes it via protovalidate, and this pins it to the oracle.
func TestValidate_enforcesCrossFieldCEL(t *testing.T) {
	cases := loadCorpusFile(t, "../../../conformance/corpus/crossfield.json")
	if len(cases) < 7 {
		t.Fatalf("expected >=7 cross-field mutants, got %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.Valid {
				t.Fatalf("crossfield case %s should be invalid", c.ID)
			}
			err := ramphelpers.Validate(unmarshalCase(t, c))
			if err == nil {
				t.Fatalf("cross-field mutant %s was accepted (rule %v not enforced)", c.ID, c.Rules)
			}
			got := ramphelpers.ValidationRuleIDs(err)
			for _, want := range c.Rules {
				if !contains(got, want) {
					t.Errorf("%s: expected rule %q in %v", c.ID, want, got)
				}
			}
		})
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
