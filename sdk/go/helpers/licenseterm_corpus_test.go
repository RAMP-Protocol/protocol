package helpers_test

// Go replay of testdata/licenseterm-vectors.json through the PUBLIC faces.
//
// The emitter derives the corpus from the same faces, so this file is not what
// catches a Go regression — the emitter's drift gate is. It exists so the Go
// side reads the corpus the way the two ports do: by name, column by column,
// through the exported API, which is what the completeness gate holds all three
// languages to.

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type corpusFinding struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Token   string `json:"token"`
	Message string `json:"message"`
}

type licenseTermCorpus struct {
	Fold []struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Token     string `json:"token"`
		Canonical string `json:"canonical"`
	} `json:"fold"`
	Normalize []struct {
		Name       string          `json:"name"`
		Term       json.RawMessage `json:"term"`
		Normalized json.RawMessage `json:"normalized"`
	} `json:"normalize"`
	Known []struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Token string `json:"token"`
		Known bool   `json:"known"`
	} `json:"known"`
	Validate []struct {
		Name      string          `json:"name"`
		Term      json.RawMessage `json:"term"`
		Violation *corpusFinding  `json:"violation"`
		Warnings  []corpusFinding `json:"warnings"`
	} `json:"validate"`
	Entry []struct {
		Name            string          `json:"name"`
		Entry           json.RawMessage `json:"entry"`
		OK              bool            `json:"ok"`
		Structural      bool            `json:"structural"`
		CrossFieldRules []string        `json:"cross_field_rules"`
		TermRules       []corpusFinding `json:"term_rules"`
		Warnings        []corpusFinding `json:"warnings"`
	} `json:"entry"`
}

func loadLicenseTermCorpus(t *testing.T) licenseTermCorpus {
	t.Helper()
	raw, err := os.ReadFile("testdata/licenseterm-vectors.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c licenseTermCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	if len(c.Fold) == 0 || len(c.Normalize) == 0 || len(c.Known) == 0 || len(c.Validate) == 0 || len(c.Entry) == 0 {
		t.Fatal("corpus has an empty list — a replay over nothing passes vacuously")
	}
	return c
}

func kindOf(t *testing.T, name string) rampv1.RestrictionKind {
	t.Helper()
	n, ok := rampv1.RestrictionKind_value[name]
	if !ok {
		t.Fatalf("unknown RestrictionKind %q in corpus", name)
	}
	return rampv1.RestrictionKind(n)
}

func findingsOf(ws []helpers.RuleWarning) []corpusFinding {
	out := make([]corpusFinding, 0, len(ws))
	for _, w := range ws {
		out = append(out, corpusFinding{Rule: w.Rule, Path: w.Path, Token: w.Token, Message: w.Message})
	}
	return out
}

func sameFindings(a, b []corpusFinding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// corpusCrossFieldRuleIDs mirrors the emitter: the message-CEL id set comes from
// the generated descriptor, never a list here, so the replay classifies a violation
// exactly as the oracle that recorded it did.
func corpusCrossFieldRuleIDs(t *testing.T) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			if opts, ok := md.Options().(proto.Message); ok && proto.HasExtension(opts, validate.E_Message) {
				rules, _ := proto.GetExtension(opts, validate.E_Message).(*validate.MessageRules)
				for _, c := range rules.GetCel() {
					ids[c.GetId()] = true
				}
			}
			walk(md.Messages())
		}
	}
	walk(rampv1.File_ramp_v1_ramp_proto.Messages())
	if len(ids) == 0 {
		t.Fatal("no message-level CEL ids in the descriptor — every cross-field violation " +
			"would be misclassified as field-level and the comparison would be vacuous")
	}
	return ids
}

func TestLicenseTermCorpus_Fold(t *testing.T) {
	for _, v := range loadLicenseTermCorpus(t).Fold {
		if got := helpers.CanonicalRestrictionToken(kindOf(t, v.Kind), v.Token); got != v.Canonical {
			t.Errorf("%s: CanonicalRestrictionToken(%s, %q) = %q, want %q", v.Name, v.Kind, v.Token, got, v.Canonical)
		}
	}
}

func TestLicenseTermCorpus_Normalize(t *testing.T) {
	for _, v := range loadLicenseTermCorpus(t).Normalize {
		var term, want rampv1.LicenseTerm
		if err := protojson.Unmarshal(v.Term, &term); err != nil {
			t.Fatalf("%s: decode term: %v", v.Name, err)
		}
		if err := protojson.Unmarshal(v.Normalized, &want); err != nil {
			t.Fatalf("%s: decode normalized: %v", v.Name, err)
		}
		helpers.NormalizeLicenseTerm(&term)
		got, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&term)
		wantJSON, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&want)
		if string(got) != string(wantJSON) {
			t.Errorf("%s: normalized = %s, want %s", v.Name, got, wantJSON)
		}
	}
}

func TestLicenseTermCorpus_Known(t *testing.T) {
	for _, v := range loadLicenseTermCorpus(t).Known {
		if got := helpers.KnownRestrictionToken(kindOf(t, v.Kind), v.Token); got != v.Known {
			t.Errorf("%s: KnownRestrictionToken(%s, %q) = %v, want %v", v.Name, v.Kind, v.Token, got, v.Known)
		}
	}
}

func TestLicenseTermCorpus_Validate(t *testing.T) {
	for _, v := range loadLicenseTermCorpus(t).Validate {
		var term rampv1.LicenseTerm
		if err := protojson.Unmarshal(v.Term, &term); err != nil {
			t.Fatalf("%s: decode term: %v", v.Name, err)
		}
		warnings, err := helpers.ValidateLicenseTerm(&term)
		if v.Violation == nil {
			if err != nil {
				t.Errorf("%s: unexpected violation %v", v.Name, err)
			}
		} else {
			var rv *helpers.RuleViolation
			if !errors.As(err, &rv) {
				t.Errorf("%s: want violation %+v, got err=%v", v.Name, *v.Violation, err)
				continue
			}
			got := corpusFinding{Rule: rv.Rule, Path: rv.Path, Token: rv.Token, Message: rv.Message}
			if got != *v.Violation {
				t.Errorf("%s: violation = %+v, want %+v", v.Name, got, *v.Violation)
			}
		}
		if got := findingsOf(warnings); !sameFindings(got, v.Warnings) {
			t.Errorf("%s: warnings = %+v, want %+v", v.Name, got, v.Warnings)
		}
	}
}

func TestLicenseTermCorpus_Entry(t *testing.T) {
	celIDs := corpusCrossFieldRuleIDs(t)
	for _, v := range loadLicenseTermCorpus(t).Entry {
		var entry rampv1.ResourceEntry
		if err := protojson.Unmarshal(v.Entry, &entry); err != nil {
			t.Fatalf("%s: decode entry: %v", v.Name, err)
		}
		verdict := helpers.ValidateResourceEntry(&entry)
		if verdict.OK() != v.OK {
			t.Errorf("%s: ok = %v, want %v (violations %+v)", v.Name, verdict.OK(), v.OK, verdict.Violations)
		}
		// Classify the way the emitter does, at the three strengths the corpus
		// records: cross-field ids come from the descriptor, term rules are whole
		// findings, and what is left is field-level and only counted.
		var structural bool
		crossField := []string{}
		termRules := []corpusFinding{}
		for _, viol := range verdict.Violations {
			switch {
			case viol.Rule == helpers.RulePricingUnitRegistered || viol.Rule == helpers.RuleQuotaMetricRegistered:
				termRules = append(termRules, corpusFinding{Rule: viol.Rule, Path: viol.Path, Token: viol.Token, Message: viol.Message})
			case celIDs[viol.Rule]:
				crossField = append(crossField, viol.Rule)
			default:
				structural = true
			}
		}
		if structural != v.Structural {
			t.Errorf("%s: structural = %v, want %v", v.Name, structural, v.Structural)
		}
		if !sameStrings(crossField, v.CrossFieldRules) {
			t.Errorf("%s: cross_field_rules = %v, want %v", v.Name, crossField, v.CrossFieldRules)
		}
		if !sameFindings(termRules, v.TermRules) {
			t.Errorf("%s: term_rules = %+v, want %+v", v.Name, termRules, v.TermRules)
		}
		if got := findingsOf(verdict.Warnings); !sameFindings(got, v.Warnings) {
			t.Errorf("%s: warnings = %+v, want %+v", v.Name, got, v.Warnings)
		}
	}
}
