// Package conformance — corpus_coverage_test.go is a coverage guard over the
// GENERATED validation corpus (conformance/corpus/cases.json). It does NOT
// re-validate cases (that is corpus_test.go's job); it asserts the corpus
// EXERCISES specific field-level rule classes that the parity harness must cover.
//
// These four classes were the blind spots that let H1/M3-class bugs ship green
// (see agentic-content-access-kb1s0.9): money's divergent value space, the H1
// positive ” accept, repeated-item length bounds, and pattern-derived
// required-presence. Each is asserted over the corpus JSON — the behavioral
// artifact the clients consume — not over corpusgen source. When corpusgen is
// updated to emit these mutants, each assertion flips to green.
package conformance

import (
	"encoding/json"
	"strings"
	"testing"
)

// moneyJSONKeys are the proto-JSON (camelCase) field names of every money-typed
// string field in the schema: Cost.amount/unit_cost, Pricing.rate/unit_cost,
// RequestConstraints.max_unit_cost. Money carries a value space (negatives, NaN,
// Infinity, scientific notation, and the accepted-empty edge) distinct from the
// generic token/hash patterns, so its coverage must be checked on these keys.
var moneyJSONKeys = map[string]bool{
	"amount":      true,
	"unitCost":    true,
	"rate":        true,
	"maxUnitCost": true,
}

// moneyKillers are values that fail ONLY the money pattern ^([0-9]+([.][0-9]+)?)?$
// (they MATCH the token/hash patterns, so they are money-selective). A parity
// corpus that never feeds these to a money field cannot prove the clients reject
// what Go rejects for money specifically.
var moneyKillers = map[string]bool{
	"-5":       true,
	"NaN":      true,
	"Infinity": true,
	"1E3":      true,
}

// moneyFieldValues walks a decoded proto-JSON value and returns every string
// value found under a money-typed key, at any nesting depth.
func moneyFieldValues(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if s, ok := val.(string); ok && moneyJSONKeys[k] {
					out = append(out, s)
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// containsArrayOfStrings reports whether the decoded JSON has any array holding a
// string element (i.e. a repeated string field is materialized) at any depth.
func containsArrayOfStrings(v any) bool {
	found := false
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, e := range t {
				if _, ok := e.(string); ok {
					found = true
				}
				walk(e)
			}
		}
	}
	walk(v)
	return found
}

func decodeCaseJSON(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode case json: %v", err)
	}
	return v
}

func ruleMatches(rules []string, substr string) bool {
	for _, r := range rules {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

// TestCorpusCoverage guards that the generated corpus exercises the four
// field-level rule classes M5 identified as missing. Each subtest is an
// independent coverage assertion whose failure names exactly which mutant class
// the corpus lacks. It fails NOW (corpus has 86 cases, none of these classes) and
// passes once corpusgen emits them.
func TestCorpusCoverage(t *testing.T) {
	cases := loadCorpus(t)

	// Class 1 — money-specific killer values must be exercised as INVALID.
	t.Run("invalid_money_killer_values", func(t *testing.T) {
		for _, c := range cases {
			if c.Valid {
				continue
			}
			for _, val := range moneyFieldValues(decodeCaseJSON(t, c.JSON)) {
				if moneyKillers[val] {
					return // found a killer money case
				}
			}
		}
		t.Errorf("MISSING CLASS 1 (money killers): no INVALID case feeds a money field "+
			"(amount/unitCost/rate/maxUnitCost) one of -5/NaN/Infinity/1E3; the corpus "+
			"proves the clients reject 'two words' but never the money-specific value space (%d cases scanned)", len(cases))
	})

	// Class 2 — the H1 positive blind spot: '' must be VALID on a money field.
	t.Run("valid_empty_money_value", func(t *testing.T) {
		for _, c := range cases {
			if !c.Valid {
				continue
			}
			for _, val := range moneyFieldValues(decodeCaseJSON(t, c.JSON)) {
				if val == "" {
					return // found a valid empty-money case
				}
			}
		}
		t.Errorf("MISSING CLASS 2 (positive empty money): no VALID case has a money field "+
			"equal to \"\"; the H1 blind spot (clients wrongly rejecting accepted-empty money) "+
			"is unguarded — baselines use \"0\", never \"\" (%d cases scanned)", len(cases))
	})

	// Class 3 — repeated string items length bounds (min_len/max_len).
	t.Run("invalid_repeated_item_length", func(t *testing.T) {
		for _, c := range cases {
			if c.Valid {
				continue
			}
			if !ruleMatches(c.Rules, "min_len") && !ruleMatches(c.Rules, "max_len") {
				continue
			}
			if containsArrayOfStrings(decodeCaseJSON(t, c.JSON)) {
				return // found a too_short/too_long list case
			}
		}
		t.Errorf("MISSING CLASS 3 (repeated item length): no INVALID case pairs a "+
			"string.min_len/max_len rule with an array-of-strings value; repeated.items "+
			"min_len=1/max_len=64 (values/permitted/prohibited) are enforced in clients but "+
			"never exercised as too_short/too_long list mutants (%d cases scanned)", len(cases))
	})

	// Class 4 — pattern-derived required-presence: Quota.metric omitted must be
	// INVALID (its pattern rejects '', so omission is a violation) — beyond the
	// single explicit `required` field the current 'missing' edge covers.
	t.Run("invalid_pattern_required_presence", func(t *testing.T) {
		for _, c := range cases {
			if c.Message != "Quota" || c.Valid {
				continue
			}
			obj, ok := decodeCaseJSON(t, c.JSON).(map[string]any)
			if !ok {
				continue
			}
			if _, present := obj["metric"]; present {
				continue
			}
			if ruleMatches(c.Rules, "string.pattern") {
				return // found Quota with metric omitted, rejected by its pattern
			}
		}
		t.Errorf("MISSING CLASS 4 (pattern-derived required presence): no INVALID Quota case "+
			"OMITS 'metric' and trips string.pattern; the 'missing' edge fires only for the one "+
			"explicit required field, so pattern-required presence (Quota.metric) is untested (%d cases scanned)", len(cases))
	})
}
