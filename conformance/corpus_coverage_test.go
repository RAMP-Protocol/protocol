// Package conformance — corpus_coverage_test.go is a coverage guard over the
// GENERATED validation corpus (conformance/corpus/cases.json). It does NOT
// re-validate cases (that is corpus_test.go's job); it asserts the corpus
// EXERCISES specific field-level rule classes that the parity harness must cover.
//
// These classes were the blind spots that let money/validation bugs ship
// green: money's divergent value space, the empty-money
// positive ” accept, repeated-item length bounds, pattern-derived
// required-presence, presence-tracked-enum omitted-is-valid, and the bytes /
// max_bytes rule shapes corpusgen once skipped silently. Each is
// asserted over the corpus JSON — the behavioral
// artifact the clients consume — not over corpusgen source. When corpusgen is
// updated to emit these mutants, each assertion flips to green.
package conformance

import (
	"encoding/json"
	"strings"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// moneyJSONKeys are the proto-JSON (snake_case) field names of every money-typed
// string field in the schema: Cost.amount/unit_cost, Pricing.rate/unit_cost,
// RequestConstraints.max_unit_cost. Money carries a value space (negatives, NaN,
// Infinity, scientific notation, and the accepted-empty edge) distinct from the
// generic token/hash patterns, so its coverage must be checked on these keys.
var moneyJSONKeys = map[string]bool{
	"amount":        true,
	"unit_cost":     true,
	"rate":          true,
	"max_unit_cost": true,
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

// TestCorpusCoverage guards that the generated corpus exercises the six
// field-level rule classes that shipped bugs (or would have) while every other
// gate stayed green: (1) money-specific killer values, (2) the accepted-empty
// money edge, (3) repeated-item length bounds, (4) pattern-derived required
// presence, (5) presence-tracked-enum omitted-is-valid, and (6) the
// bytes.len / bytes.min_len / string.max_bytes rule shapes. Each subtest is an
// independent coverage assertion whose failure names exactly which mutant
// class the corpus lacks; a class fails RED until corpusgen emits its mutants
// and turns red again if a regeneration drops them.
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
			"(amount/unit_cost/rate/max_unit_cost) one of -5/NaN/Infinity/1E3; the corpus "+
			"proves the clients reject 'two words' but never the money-specific value space (%d cases scanned)", len(cases))
	})

	// Class 2 — the positive empty-money blind spot: '' must be VALID on a money field.
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
			"equal to \"\"; the empty-money blind spot (clients wrongly rejecting accepted-empty money) "+
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

	// Class 5 — presence-tracked-enum omitted-is-valid: a proto3 optional enum
	// that rejects its zero (not_in:[0]) must still ACCEPT omission. This is the
	// property the optional-field design rests on — a publisher that omits the
	// hint is the common case — and it lives on ResourceEntry.resource_mutability.
	// If a regenerated client drops the optional keyword, omitted feeds start
	// being rejected while every other gate stays green; this class fails loudly.
	t.Run("valid_presence_tracked_enum_omitted", func(t *testing.T) {
		for _, c := range cases {
			if c.Message != "ResourceEntry" || !c.Valid {
				continue
			}
			obj, ok := decodeCaseJSON(t, c.JSON).(map[string]any)
			if !ok {
				continue
			}
			if _, present := obj["resource_mutability"]; present {
				continue
			}
			return // found a VALID ResourceEntry that OMITS resource_mutability
		}
		t.Errorf("MISSING CLASS 5 (presence-tracked enum, omitted-is-valid): no VALID ResourceEntry "+
			"case OMITS 'resource_mutability'; the property that an optional not_in:[0] enum accepts "+
			"omission (the common ingest case) is unguarded, so dropping the 'optional' keyword would "+
			"reject every omitting feed with all gates green (%d cases scanned)", len(cases))
	})

	// Class 6 — bytes.len / bytes.min_len / string.max_bytes. These rule shapes
	// (the evidence rows' Ed25519 keys, canonical-bytes fields, signed_url_hash)
	// once reached ZERO corpus cases because corpusgen skipped unknown rule
	// shapes silently. Each shape is required only while the SCHEMA carries it
	// (derived from the contract descriptors, not hardcoded), so dropping a rule
	// from the contract does not strand the guard, and reintroducing one arms it
	// again. For string.max_bytes, additionally require a multibyte mutant —
	// over the limit in BYTES while under it in characters — so a client that
	// counts characters cannot pass.
	t.Run("invalid_bytes_and_max_bytes_rules", func(t *testing.T) {
		bytesLen, bytesMinLen, stringMaxBytes := schemaRuleShapes()
		needRules := map[string]bool{
			"bytes.len":        bytesLen,
			"bytes.min_len":    bytesMinLen,
			"string.max_bytes": stringMaxBytes,
		}
		for rule, need := range needRules {
			if !need {
				continue
			}
			found := false
			for _, c := range cases {
				if !c.Valid && ruleMatches(c.Rules, rule) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("MISSING CLASS 6 (%s): the schema carries a %s rule but no INVALID "+
					"case trips it; corpusgen is silently skipping this rule shape again (%d cases scanned)",
					rule, rule, len(cases))
			}
		}
		if !stringMaxBytes {
			return // no max_bytes rule in the schema — nothing to pin
		}
		for _, c := range cases {
			if c.Valid || !ruleMatches(c.Rules, "string.max_bytes") {
				continue
			}
			// Anchored to the MUTATED field (the case id's second segment):
			// an unanchored whole-JSON scan would be satisfied by a multibyte
			// value in an unrelated auto-filled field, proving nothing about
			// the byte-vs-character counting of the field under test.
			for _, s := range fieldStringValues(decodeCaseJSON(t, c.JSON), mutatedField(c.ID)) {
				if len(s) > len([]rune(s)) {
					return // found a multibyte max_bytes mutant on the mutated field
				}
			}
		}
		t.Errorf("MISSING CLASS 6 (multibyte max_bytes): every string.max_bytes mutant is "+
			"ASCII, where byte count == character count; a client that counts characters "+
			"instead of bytes stays green (%d cases scanned)", len(cases))
	})
}

// schemaRuleShapes reports which of the once-skipped rule shapes the contract
// schema currently carries (top-level field rules, matching corpusgen's edge
// scope). The class 6 guard requires corpus coverage only for shapes that are
// actually in the schema.
func schemaRuleShapes() (bytesLen, bytesMinLen, stringMaxBytes bool) {
	EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fr, err := protovalidate.ResolveFieldRules(md.Fields().Get(i))
			if err != nil || fr == nil {
				continue
			}
			if b := fr.GetBytes(); b != nil {
				if b.Len != nil {
					bytesLen = true
				}
				if b.GetMinLen() > 0 {
					bytesMinLen = true
				}
			}
			if s := fr.GetString(); s != nil && s.GetMaxBytes() > 0 {
				stringMaxBytes = true
			}
		}
	})
	return
}

// mutatedField extracts the mutated field's JSON name from a corpus case id,
// which corpusgen shapes as "Message/field/edge".
func mutatedField(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// fieldStringValues walks a decoded proto-JSON value and returns every string
// found under the given key — directly, or as elements of an array under that
// key — at any nesting depth (the mutated field may sit inside an auto-filled
// sub-message).
func fieldStringValues(v any, field string) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if k == field {
					switch fv := val.(type) {
					case string:
						out = append(out, fv)
					case []any:
						for _, e := range fv {
							if s, ok := e.(string); ok {
								out = append(out, s)
							}
						}
					}
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
