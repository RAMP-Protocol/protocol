package helpers

// Registration-schema golden-vector emitter (ADR-020 §5).
//
// A published data_schema is read by two parties that must agree — the Exchange
// enforcing it and a client pre-checking against it — and soon by three languages.
// This emitter is the oracle for that agreement: every recorded verdict is DERIVED
// by calling the REAL Go face, never hand-typed, exactly as gen_audience_vectors_test.go
// derives its verdicts and gen_util_vectors_test.go its canonical money strings.
//
// Each case still carries the verdict its AUTHOR intended, and the emitter refuses
// to write a file where the real face disagrees with that intent. Without it a face
// that started answering the opposite would happily emit a corpus asserting the
// opposite, and every port would be dragged along.
//
// What the corpus pins on the failure side is the (pointer, keyword) SET, never the
// prose. RegistrationFieldError.error is documented as validator-defined and
// non-authoritative, so pinning its wording would fail a port for a difference the
// contract explicitly permits; the failed keyword, by contrast, is the same word in
// every JSON Schema library. The prose is held to a different standard instead — it
// must never carry the submitted value — and that is a behavioural test, not a
// vector, because it is a property of every possible payload rather than of these.
//
// The caps are recorded in the document beside the cases, deliberately: they are the
// numbers the proto's data_schema comment states, and a guard in the conformance
// tier reads them from here as data — the conformance package cannot import sdk/go,
// so a committed file is the only channel between the two tiers.
//
// Like TestGenerateVectors this test is a verification no-op by default (it asserts
// the committed file matches a fresh emit) and (re)writes under
// RAMP_UPDATE_VECTORS=1 — the emitter is both generator and drift gate. It is TEST
// INFRASTRUCTURE, not the code under test.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/structpb"
)

// compileVector is one CompileRegistrationSchema case. The schema is carried as the
// RAW JSON TEXT rather than as a nested object, for two reasons: the size cap is
// defined over the bytes as served, so a corpus that re-encoded the schema could not
// state the boundary case at all; and a port reads the same bytes this face read.
type compileVector struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
	// SchemaB64 carries the input as base64 when it is not expressible as a JSON
	// string — invalid UTF-8. Exactly one of Schema and SchemaB64 is set; a replay
	// prefers SchemaB64 when present and UTF-8-encodes Schema otherwise.
	SchemaB64 string `json:"schema_b64,omitempty"`
	Verdict   string `json:"expected_verdict"`
}

// validateVector is one Validate case. Paths and Keywords run in parallel: entry i
// of one belongs with entry i of the other, in the deterministic order the face
// emits. An empty Paths list means the payload conforms.
type validateVector struct {
	Name     string         `json:"name"`
	Schema   string         `json:"schema"`
	Data     map[string]any `json:"data"`
	Paths    []string       `json:"expected_paths"`
	Keywords []string       `json:"expected_keywords"`
}

// patternVector is one IsSafeSchemaPattern case, recorded separately from the
// compile cases so the alphabet rule is testable on its own. A port that only
// replayed whole schemas would have to guess which construct tripped a refusal.
type patternVector struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Safe    bool   `json:"safe"`
}

// regDataVector is one CheckRegistrationData case: a submitted payload and the bound
// it does or does not break. The payload is carried as decoded JSON rather than as
// text, because the rule is defined over the payload's CANONICAL encoding and a port
// that replayed raw text would be testing its own JSON parser instead.
type regDataVector struct {
	Name    string         `json:"name"`
	Data    map[string]any `json:"data"`
	Verdict string         `json:"expected_verdict"`
}

// objectSchema wraps a property schema in the object shape a registration schema
// actually has, so the cases read like documents an Exchange would publish.
func objectSchema(inner string) string {
	return `{"type":"object","properties":{"vat_id":` + inner + `}}`
}

// schemaOfBytes builds a valid schema whose raw length is exactly n bytes, by
// padding a description. It is how both sides of the size bound are stated as
// boundary cases rather than as "something big".
func schemaOfBytes(t *testing.T, n int) string {
	t.Helper()
	const prefix = `{"type":"object","description":"`
	const suffix = `"}`
	pad := n - len(prefix) - len(suffix)
	if pad < 0 {
		t.Fatalf("cannot build a %d-byte schema: the envelope alone is %d", n, len(prefix)+len(suffix))
	}
	return prefix + strings.Repeat("x", pad) + suffix
}

// nestedSchema builds a valid schema whose document nests to EXACTLY depth JSON
// containers. `not` is used because it takes a subschema directly, so each level is
// one container and the boundary can be hit on the nose — `allOf` would add an
// array per level and could only produce odd depths, leaving the "exactly at the
// cap" case a level short of the cap it claims to test.
func nestedSchema(depth int) string {
	var b strings.Builder
	for i := 0; i < depth-1; i++ {
		b.WriteString(`{"not":`)
	}
	b.WriteString(`{}`)
	for i := 0; i < depth-1; i++ {
		b.WriteString(`}`)
	}
	return b.String()
}

// branchBlowupSchema builds a schema whose DOCUMENT is small and shallow and whose
// evaluation cost is 2^n. It is the shape the size and depth caps do not see: at
// n=24 it is 1,675 bytes, five containers deep, and took 27 seconds to check a
// two-member payload before the work bound existed.
func branchBlowupSchema(n int) string {
	var b strings.Builder
	b.WriteString(`{"$defs":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		next := `{"type":"string"}`
		if i+1 < n {
			next = `{"$ref":"#/$defs/d` + strconv.Itoa(i+1) + `"}`
		}
		b.WriteString(`"d` + strconv.Itoa(i) + `":{"anyOf":[` + next + `,` + next + `]}`)
	}
	b.WriteString(`},"$ref":"#/$defs/d0"}`)
	return b.String()
}

// matchVector is one MATCHING case: does this pattern accept this string?
//
// This dimension exists because its absence is what let a whole class of divergence
// ship. The other three record which schemas are ADMITTED; none of them records what
// an admitted schema then MATCHES, and that is precisely where the three engines
// disagreed — silently, with every suite green. `^abc$` against "abc\n" and `^\d+$`
// against Arabic-Indic digits both conformed in one port and violated in the other
// two, including the VAT pattern this corpus itself publishes as realistic.
type matchVector struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
	Matches bool   `json:"matches"`
}

// buildRegDataVectors pins the bounds on a SUBMITTED payload, which are the other half
// of the resource story: the schema's own caps bound the schema, and validation cost is
// the schema's cost multiplied by the elements in the payload.
//
// The measurement is the point of most of these cases. registration_data is not served
// as bytes — it arrives decoded — so the rule names an encoding, and a port that
// measured its own language's rendering instead would agree on the easy cases and part
// on the interesting ones.
func buildRegDataVectors(t *testing.T) []regDataVector {
	t.Helper()

	// A payload whose canonical form lands exactly on the cap, and its neighbour one
	// byte over. Built by padding one string value, the same way schemaOfBytes states
	// the schema cap's boundary rather than "something big".
	// The envelope is DERIVED rather than counted by hand: the canonical form of
	// {"pad":""} is measured through the real face, so a boundary case cannot drift
	// into the wrong side of the cap because somebody miscounted the punctuation.
	envelope, err := registrationDataBytes(map[string]any{"pad": ""})
	if err != nil {
		t.Fatalf("measuring the padding envelope: %v", err)
	}
	atCap := func(total int) map[string]any {
		return map[string]any{"pad": strings.Repeat("x", total-envelope)}
	}

	wide := func(n int) map[string]any {
		out := make(map[string]any, n)
		for i := 0; i < n; i++ {
			out["k"+pad2(i)] = "v"
		}
		return out
	}

	cases := []struct {
		name string
		data map[string]any
		want RegistrationDataVerdict
	}{
		{"an_empty_payload", map[string]any{}, RegistrationDataAccepted},
		{"a_nil_payload", nil, RegistrationDataAccepted},
		// The depth boundary, stated as a pair the way the byte and member caps are.
		// It bounds an axis neither of those sees: a deeply nested payload is small and
		// has few top-level members. Canonicalising walks it recursively, so before this
		// bound existed the verdict came from the reader's runtime — one implementation
		// refused past about five hundred containers on one release of its language and
		// accepted nine hundred on the next.
		{"nesting_at_the_depth_cap", nestedPayload(MaxRegistrationDataDepth), RegistrationDataAccepted},
		{"nesting_one_over_the_depth_cap", nestedPayload(MaxRegistrationDataDepth + 1), RegistrationDataTooDeep},
		// The same boundary on the shape a payload actually takes. The pair above bottoms
		// out in an empty object, which is the one shape where a count of containers and a
		// count of every value agree — so it cannot tell the two rules apart, and a leaf
		// that is a value is what every real payload has.
		{
			"nesting_at_the_depth_cap_with_a_scalar_leaf",
			nestedPayloadScalarLeaf(MaxRegistrationDataDepth),
			RegistrationDataAccepted,
		},
		{
			"nesting_one_over_the_depth_cap_with_a_scalar_leaf",
			nestedPayloadScalarLeaf(MaxRegistrationDataDepth + 1),
			RegistrationDataTooDeep,
		},
		// An array is a container and the scalars inside it are not, so this sits exactly
		// at the cap rather than one over.
		{
			"nesting_at_the_depth_cap_ending_in_an_array_of_scalars",
			nestedPayloadAround(MaxRegistrationDataDepth-1, []any{float64(1), float64(2), float64(3)}),
			RegistrationDataAccepted,
		},
		{
			"a_realistic_registration",
			map[string]any{
				"legal_name":           "Acme GmbH",
				"vat_id":               "DE12345",
				"jurisdiction_country": "DE",
				"address": map[string]any{
					"street": "Hauptstrasse 1", "postal_code": "10115", "city": "Berlin",
				},
			},
			RegistrationDataAccepted,
		},
		// The member cap, on the nose and one over.
		{"members_at_the_cap", wide(MaxRegistrationDataMembers), RegistrationDataAccepted},
		{"members_over_the_cap", wide(MaxRegistrationDataMembers + 1), RegistrationDataTooManyMembers},
		// BOTH bounds broken at once, and the answer names the FIRST check in the proto's
		// order. Every other case here breaks exactly one bound, so the order between the
		// two counts is a thing all three ports could disagree about while every vector
		// passed: swapping them still refuses this payload, just under the other name, and
		// an agent that switches on the verdict is told the wrong thing about its payload.
		// The pair is a vector rather than three separate language tests because the order
		// is the contract's, not one implementation's.
		{
			"members_over_the_cap_and_nesting_over_the_depth_cap",
			func() map[string]any {
				out := wide(MaxRegistrationDataMembers + 1)
				out["deep"] = nestedPayload(MaxRegistrationDataDepth + 1)
				return out
			}(),
			RegistrationDataTooManyMembers,
		},
		// The byte cap, on the nose and one over.
		{"bytes_at_the_cap", atCap(MaxRegistrationDataBytes), RegistrationDataAccepted},
		{"bytes_over_the_cap", atCap(MaxRegistrationDataBytes + 1), RegistrationDataTooLarge},
		// ONE top-level member, far over the byte cap. The member count alone would
		// admit this, and so would a flattened count — the bulk is nested.
		{
			"one_member_holding_bulk",
			map[string]any{"contacts": func() []any {
				out := make([]any, 4000)
				for i := range out {
					out[i] = map[string]any{"email": "a@b.example"}
				}
				return out
			}()},
			RegistrationDataTooLarge,
		},
		// The cases that pin the UNIT, and they have to be boundary cases to do it.
		//
		// 1e16 is where a language's ordinary JSON rendering and the canonical one
		// part: JCS spells it 10000000000000000, seventeen characters, because it
		// follows ECMAScript number-to-string, while an ordinary compact dump emits
		// 1e+16, five. A payload sitting one byte over the cap under the canonical
		// spelling therefore sits eleven bytes UNDER it when measured any other way —
		// so a port that reached for its own serializer answers "accepted" here and
		// the vector catches it. Without the boundary the difference is invisible,
		// because both spellings are far below the cap.
		{"a_float_that_only_the_canonical_form_pushes_over", overCapWithFloat(t), RegistrationDataTooLarge},
		{"a_float_the_canonical_form_keeps_under", map[string]any{"n": 1e16}, RegistrationDataAccepted},
	}

	// The depth boundary is stated as a pair rather than as "something deep", the way
	// the byte and member caps are. It bounds an axis nothing else did: a deeply nested
	// payload is small and has few top-level members, so neither of the other two caps
	// sees it, and canonicalising it recurses — which made the verdict a property of the
	// reader's runtime until this bound existed.
	//
	// RegistrationDataUncanonicalizable has no vector, and cannot have one: the input
	// that produces it is a non-finite number, which JSON has no way to write down —
	// which is the very reason the verdict exists. Each language asserts it directly
	// instead, the same way the never-echo-a-value rule is a behavioural test rather
	// than a vector.
	out := make([]regDataVector, 0, len(cases))
	for _, c := range cases {
		got := CheckRegistrationData(c.data)
		if got != c.want {
			t.Fatalf("registration_data vector %s: oracle verdict=%s, intended=%s", c.name, got, c.want)
		}
		data := c.data
		if data == nil {
			// JSON has no way to say "the caller passed nil"; the rule treats an absent
			// payload and an empty one alike, which is what this records.
			data = map[string]any{}
		}
		// Every case is replayed through the RAW entry point too, because that is the one
		// an Exchange calls. The two faces may differ on exactly one input — a non-finite
		// number — and no vector can carry one, since JSON cannot write it down. So on
		// this corpus they must agree case for case, and a difference here is a real
		// divergence rather than the documented one.
		//
		// How high this floor actually is, measured by loosening the code under it:
		// breaking the byte bound in a CheckRegistrationDataStruct that computes its own
		// tail fails here, but breaking its raw member bound does NOT — the delegation to
		// CheckRegistrationData answers too_many_members either way. That is the honest
		// height. The raw member and depth guards exist to keep AsMap from recursing over
		// an unmeasured payload, not to decide a verdict, so no corpus can see them; what
		// this catches is the day the two faces stop sharing a tail.
		raw, err := structpb.NewStruct(data)
		if err != nil {
			t.Fatalf("registration_data vector %s: structpb.NewStruct: %v", c.name, err)
		}
		if rawGot := CheckRegistrationDataStruct(raw); rawGot != got {
			t.Fatalf("registration_data vector %s: CheckRegistrationDataStruct=%s, CheckRegistrationData=%s",
				c.name, rawGot, got)
		}
		out = append(out, regDataVector{Name: c.name, Data: data, Verdict: got.String()})
	}
	return out
}

// overCapWithFloat builds a payload that exceeds the byte cap by exactly one byte
// under the CANONICAL encoding, carrying a float whose canonical spelling is longer
// than an ordinary JSON dump would produce. Measured through the real face rather than
// counted by hand, so the case cannot drift onto the wrong side of the cap.
func overCapWithFloat(t *testing.T) map[string]any {
	t.Helper()
	base, err := registrationDataBytes(map[string]any{"n": 1e16, "pad": ""})
	if err != nil {
		t.Fatalf("measuring the float payload envelope: %v", err)
	}
	data := map[string]any{"n": 1e16, "pad": strings.Repeat("x", MaxRegistrationDataBytes+1-base)}
	got, err := registrationDataBytes(data)
	if err != nil {
		t.Fatalf("measuring the float payload: %v", err)
	}
	if got != MaxRegistrationDataBytes+1 {
		t.Fatalf("float payload measures %d bytes, intended exactly %d",
			got, MaxRegistrationDataBytes+1)
	}
	return data
}

// nestedPayload builds a payload nesting exactly depth JSON containers, counting the
// payload object itself as the first.
func nestedPayload(depth int) map[string]any {
	inner := map[string]any{}
	for i := 1; i < depth; i++ {
		inner = map[string]any{"a": inner}
	}
	return inner
}

// nestedPayloadAround wraps leaf in `maps` objects. The payload nests that many
// containers plus however many leaf is worth: a scalar is a value and adds none, an
// array adds one.
func nestedPayloadAround(maps int, leaf any) map[string]any {
	var cur any = leaf
	for i := 0; i < maps; i++ {
		cur = map[string]any{"a": cur}
	}
	return cur.(map[string]any)
}

// nestedPayloadScalarLeaf nests containers objects deep and bottoms out in a string,
// which is the shape of every payload that carries data rather than structure.
func nestedPayloadScalarLeaf(containers int) map[string]any {
	return nestedPayloadAround(containers, "x")
}

// regDataVerdictVocabulary is every token the payload check can answer with, recorded
// for the same reason as the schema vocabulary: a port that grew or lost one is caught
// by comparing the list rather than by whichever cases happen to exercise each token.
func regDataVerdictVocabulary() []string {
	all := []RegistrationDataVerdict{
		RegistrationDataNoVerdict, RegistrationDataAccepted, RegistrationDataTooLarge,
		RegistrationDataTooManyMembers, RegistrationDataTooDeep,
		RegistrationDataUncanonicalizable,
	}
	out := make([]string, 0, len(all))
	for _, v := range all {
		out = append(out, v.String())
	}
	return out
}

// buildRegSchemaMatchVectors pins the SEMANTICS of the admitted alphabet: for a fixed
// pattern and a fixed string, does the pattern accept it?
//
// Every case here is a pattern the alphabet admits — the point is not which schemas
// are refused but that two conformant validators agree about what an accepted one
// means. The verdict is derived by validating through the real face rather than by
// calling a regex directly, so the corpus records what a PAYLOAD experiences.
func buildRegSchemaMatchVectors(t *testing.T) []matchVector {
	t.Helper()
	cases := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// The trailing-newline family. Python's "$" also matches just before a final
		// newline where RE2 and ECMA-262 match only at the very end, so every one of
		// these conformed in one port and violated in the other two.
		{"anchored_literal_exact", "^abc$", "abc", true},
		{"anchored_literal_trailing_newline", "^abc$", "abc\n", false},
		{"vat_pattern_exact", "^[A-Z]{2}[0-9]+$", "DE12345", true},
		{"vat_pattern_trailing_newline", "^[A-Z]{2}[0-9]+$", "DE12345\n", false},
		{"vat_pattern_embedded_newline", "^[A-Z]{2}[0-9]+$", "DE123\n45", false},
		{"vat_pattern_wrong_shape", "^[A-Z]{2}[0-9]+$", "not-a-vat", false},

		// The character-class family. \d, \w and \s are Unicode-aware in Python and
		// ASCII in the other two, so a non-ASCII digit or letter conformed in one port
		// alone.
		{"digits_ascii", `^\d+$`, "12345", true},
		{"digits_arabic_indic", `^\d+$`, "١٢٣", false},
		{"digits_fullwidth", `^\d+$`, "１２３", false},
		{"word_ascii", `^\w+$`, "abc_123", true},
		{"word_latin_supplement", `^\w+$`, "Ä", false},
		{"explicit_space_matches", `^a[ \t]b$`, "a b", true},
		{"explicit_space_refuses_nbsp", `^a[ \t]b$`, "a\u00a0b", false},
		// \xHH is the one escape admitted by shape rather than by letter, so its
		// meaning is pinned here as well as its acceptance.
		{"hex_escape_matches", `^\x41$`, "A", true},
		// The dot's line-terminator set. RE2 and Python exclude only "\n"; ECMA-262
		// excludes all four terminators, so "^.$" against a carriage return conformed in
		// two SDKs and violated in the third until the odd one out was corrected.
		{"dot_matches_a_carriage_return", `^.$`, "\r", true},
		{"dot_refuses_a_newline", `^.$`, "\n", false},
		{"dot_matches_an_ordinary_character", `^.$`, "a", true},
		{"hex_escape_refuses_another_letter", `^\x41$`, "B", false},

		// Ordinary matching, so the dimension is not only about the edge cases.
		{"class_range", "^[a-z0-9-]+$", "acme-gmbh", true},
		{"class_range_refuses_uppercase", "^[a-z0-9-]+$", "Acme", false},
		{"alternation_first", "^(cat|dog)$", "cat", true},
		{"alternation_second", "^(cat|dog)$", "dog", true},
		{"alternation_neither", "^(cat|dog)$", "fox", false},
		{"non_capturing_repeat", "^(?:ab)+$", "ababab", true},
		{"non_capturing_repeat_partial", "^(?:ab)+$", "aba", false},
		{"counted_repeat_exact", `^\d{5}$`, "12345", true},
		{"counted_repeat_too_few", `^\d{5}$`, "1234", false},
		{"unanchored_substring", "[0-9]+", "abc123def", true},
		{"empty_value_against_plus", "^[a-z]+$", "", false},
	}
	out := make([]matchVector, 0, len(cases))
	for _, c := range cases {
		schema := objectSchema(`{"type":"string","pattern":` + strconv.Quote(c.pattern) + `}`)
		sch, v := CompileRegistrationSchema([]byte(schema))
		if v != SchemaAccepted {
			t.Fatalf("match vector %s: its pattern is not admitted by the alphabet (%s)", c.name, v)
		}
		got := len(sch.Validate(map[string]any{"vat_id": c.value})) == 0
		if got != c.want {
			t.Fatalf("match vector %s: oracle matches=%v, intended=%v for pattern %q value %q",
				c.name, got, c.want, c.pattern, c.value)
		}
		out = append(out, matchVector{Name: c.name, Pattern: c.pattern, Value: c.value, Matches: got})
	}
	return out
}

// buildRegSchemaCompileVectors enumerates what a published schema may and may not
// be. Every compile rule gets at least one acceptance and one refusal, and the
// caps get both sides of their boundary, so a port that implemented "> " as ">="
// fails here rather than in production.
func buildRegSchemaCompileVectors(t *testing.T) []compileVector {
	t.Helper()
	cases := []struct {
		name   string
		schema string
		want   SchemaVerdict
	}{
		// Accepted — the shapes an Exchange really publishes.
		{"minimal_object", `{"type":"object"}`, SchemaAccepted},
		{"declares_the_dialect", `{"$schema":"` + RegistrationSchemaDialect + `","type":"object"}`, SchemaAccepted},
		{"dialect_with_empty_fragment", `{"$schema":"` + RegistrationSchemaDialect + `#","type":"object"}`, SchemaAccepted},
		{"omits_the_dialect", `{"type":"object","required":["vat_id"]}`, SchemaAccepted},
		{"realistic_registration_schema", `{"$schema":"` + RegistrationSchemaDialect + `","type":"object","required":["legal_name","vat_id"],"properties":{"legal_name":{"type":"string","minLength":1},"vat_id":{"type":"string","pattern":"^[A-Z]{2}[0-9]+$"},"address":{"type":"object","properties":{"postal_code":{"type":"string"}}}},"additionalProperties":false}`, SchemaAccepted},

		// Accepted — references that stay inside the document, in both spellings.
		{"local_ref_by_pointer", `{"$defs":{"vat":{"type":"string"}},"type":"object","properties":{"vat_id":{"$ref":"#/$defs/vat"}}}`, SchemaAccepted},
		{"local_ref_by_anchor", `{"$defs":{"vat":{"$anchor":"vat","type":"string"}},"type":"object","properties":{"vat_id":{"$ref":"#vat"}}}`, SchemaAccepted},
		// A property literally NAMED "$ref". The scan must read it as a property name,
		// not as a reference, or a schema describing a payload with a "$ref" member
		// becomes unpublishable.
		{"a_property_named_ref", `{"type":"object","properties":{"$ref":{"type":"string"}}}`, SchemaAccepted},
		// The same trap one level further in: a const VALUE carrying a remote-looking
		// reference is data, and data is not resolved.
		{"a_const_carrying_a_ref_member", `{"type":"object","properties":{"vat_id":{"const":{"$ref":"https://evil.example/s.json"}}}}`, SchemaAccepted},
		// And the dialect trap: an enumerated value that happens to name another draft
		// is a string the payload may equal, not a dialect declaration.
		{"an_enum_value_naming_another_draft", `{"type":"object","properties":{"vat_id":{"enum":["http://json-schema.org/draft-07/schema#"]}}}`, SchemaAccepted},

		// Refused — the dialect is pinned.
		{"draft_07_dialect", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`, SchemaWrongDialect},
		{"draft_2019_dialect", `{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object"}`, SchemaWrongDialect},
		{"unknown_dialect", `{"$schema":"https://example.com/my-dialect","type":"object"}`, SchemaWrongDialect},
		// Nested, because a document may only declare a dialect at its root in
		// practice — and an implementation that checked only the root would miss this.
		{"nested_subschema_declares_another_dialect", `{"type":"object","properties":{"vat_id":{"$schema":"http://json-schema.org/draft-07/schema#","type":"string"}}}`, SchemaWrongDialect},

		// Refused — the reference leaves the document. Each spelling is here because
		// each is a different way to write the same fetch.
		{"remote_ref_https", objectSchema(`{"$ref":"https://evil.example/schema.json"}`), SchemaRemoteRef},
		{"remote_ref_http", objectSchema(`{"$ref":"http://evil.example/schema.json"}`), SchemaRemoteRef},
		{"remote_ref_scheme_relative", objectSchema(`{"$ref":"//evil.example/schema.json"}`), SchemaRemoteRef},
		{"remote_ref_relative_path", objectSchema(`{"$ref":"other.json"}`), SchemaRemoteRef},
		{"remote_ref_absolute_path", objectSchema(`{"$ref":"/schemas/other.json"}`), SchemaRemoteRef},
		{"remote_ref_file_url", objectSchema(`{"$ref":"file:///etc/passwd"}`), SchemaRemoteRef},
		// A remote target reached through a fragment on ANOTHER document still leaves
		// this one — the "#" that makes a reference local has to be the FIRST byte.
		{"remote_ref_with_a_fragment", objectSchema(`{"$ref":"https://evil.example/s.json#/$defs/x"}`), SchemaRemoteRef},
		{"remote_dynamic_ref", objectSchema(`{"$dynamicRef":"https://evil.example/s.json#x"}`), SchemaRemoteRef},
		{"remote_recursive_ref", objectSchema(`{"$recursiveRef":"https://evil.example/s.json"}`), SchemaRemoteRef},
		{"remote_ref_inside_defs", `{"$defs":{"vat":{"$ref":"https://evil.example/s.json"}},"type":"object"}`, SchemaRemoteRef},
		// A property NAMED like a data keyword, carrying a remote reference in its
		// subschema. These pin the interaction between the two keyword sets: the child
		// of `properties` is a map of NAMES, so a member called "enum" or "const" is a
		// property whose subschema must still be scanned — not data to skip. Dropping
		// `properties` from the schema-map set makes the generic walk treat that map as
		// a schema, whose "enum" member it then skips as data, and the reference inside
		// is never seen. Nothing else in this corpus reaches that combination.
		{"a_property_named_enum_carrying_a_remote_ref", `{"type":"object","properties":{"enum":{"$ref":"https://evil.example/s.json"}}}`, SchemaRemoteRef},
		{"a_property_named_const_carrying_a_remote_ref", `{"type":"object","properties":{"const":{"$ref":"https://evil.example/s.json"}}}`, SchemaRemoteRef},
		{"a_definition_named_default_carrying_a_remote_ref", `{"$defs":{"default":{"$ref":"https://evil.example/s.json"}},"type":"object","properties":{"v":{"$ref":"#/$defs/default"}}}`, SchemaRemoteRef},

		// Refused — resource caps, stated as boundaries.
		{"exactly_at_the_size_cap", schemaOfBytes(t, MaxRegistrationSchemaBytes), SchemaAccepted},
		{"one_byte_over_the_size_cap", schemaOfBytes(t, MaxRegistrationSchemaBytes+1), SchemaTooLarge},
		{"exactly_at_the_depth_cap", nestedSchema(MaxRegistrationSchemaDepth), SchemaAccepted},
		{"one_level_over_the_depth_cap", nestedSchema(MaxRegistrationSchemaDepth + 1), SchemaTooDeep},
		// Deep enough to break a recursive-descent PARSER, not merely the cap. This
		// is the case that pins WHERE the depth check runs: a port that decoded first
		// and measured the decoded document afterwards agrees with the oracle on
		// every other case in this corpus and dies on this one — Python's json raises
		// RecursionError here, which is not the exception a malformed document
		// raises, so it escapes as a crash rather than arriving as a verdict.
		{"deep_enough_to_break_a_parser", nestedSchema(1000), SchemaTooDeep},
		// A brace inside a STRING is text, not a container. Without this a port whose
		// lexical depth counter ignored string literals would refuse a schema every
		// other implementation accepts — and the pattern below is exactly the kind of
		// value a real registration schema carries.
		{"braces_inside_a_string_are_not_containers", objectSchema(`{"type":"string","pattern":"^[{[]+$","description":"` + strings.Repeat("{", 40) + `"}`), SchemaAccepted},
		// Deep DATA is bounded too: a const carrying a deeply nested value is as
		// expensive to parse as a deeply nested schema, and skipping the keyword scan
		// inside it must not mean skipping the depth count.
		{"deep_data_inside_a_const", `{"type":"object","properties":{"vat_id":{"const":` + strings.Repeat("[", 40) + `1` + strings.Repeat("]", 40) + `}}}`, SchemaTooDeep},

		// Refused — the work of CHECKING a payload, which the caps above do not bound.
		// Each is small and shallow: the cost is in how the branches multiply.
		{"branch_product_just_over_the_cap", branchBlowupSchema(12), SchemaTooComplex},
		{"branch_product_far_over_the_cap", branchBlowupSchema(24), SchemaTooComplex},
		{"branch_product_under_the_cap", branchBlowupSchema(11), SchemaAccepted},
		// Reference topology. A cycle is legal JSON Schema and has no finite
		// evaluation cost; it is also what made two of the three ports abort instead
		// of answering, so it is refused rather than handed to a compiler.
		{"self_reference_at_the_root", `{"$ref":"#"}`, SchemaRefCycle},
		{"reference_cycle_through_defs", `{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`, SchemaRefCycle},
		{"self_reference_through_defs", `{"$defs":{"a":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`, SchemaRefCycle},
		// A same-document reference that resolves to nothing. Left to the libraries
		// this was accepted by one and refused by two, and the one that accepted it
		// then threw on every payload.
		{"local_ref_to_a_missing_pointer", objectSchema(`{"$ref":"#/$defs/nope"}`), SchemaUncompilable},
		{"local_ref_to_a_missing_anchor", objectSchema(`{"$ref":"#nope"}`), SchemaUncompilable},
		// A definition that is declared and never referenced costs nothing, so a
		// document may carry a large library of them.
		{"unreferenced_defs_are_free", `{"$defs":{"big":` + branchBlowupSchema(24) + `},"type":"object"}`, SchemaAccepted},

		// Refused — a pattern outside the shared alphabet.
		{"pattern_with_lookahead", objectSchema(`{"type":"string","pattern":"^(?=.*[0-9]).+$"}`), SchemaUnsafePattern},
		{"pattern_with_backreference", objectSchema(`{"type":"string","pattern":"^(a)\\1$"}`), SchemaUnsafePattern},
		{"pattern_properties_key_with_lookahead", `{"type":"object","patternProperties":{"^(?!x).*$":{"type":"string"}}}`, SchemaUnsafePattern},
		{"property_names_pattern_with_lookbehind", `{"type":"object","propertyNames":{"pattern":"(?<=a)b"}}`, SchemaUnsafePattern},
		// A POSIX class anywhere but the first position. Checking only the start of
		// the bracket expression let this through, and the three engines then read it
		// three different ways with no error on any of them.
		{"pattern_with_a_posix_class_mid_bracket", objectSchema(`{"type":"string","pattern":"^[a[:alpha:]]+$"}`), SchemaUnsafePattern},
		// Nested quantifiers: catastrophic backtracking needs neither lookaround nor
		// backreferences, so excluding those does not cover it.
		{"pattern_with_nested_quantifiers", objectSchema(`{"type":"string","pattern":"^(a+)+$"}`), SchemaUnsafePattern},
		{"pattern_with_quantified_alternation", objectSchema(`{"type":"string","pattern":"^(a|a)*$"}`), SchemaUnsafePattern},

		// Refused — not a schema at all.
		{"not_json", `{"type":`, SchemaMalformed},
		// No schema at all is the contract's ordinary case — an Exchange that
		// publishes none accepts registration_data uninspected — so it is its own
		// verdict rather than a refusal a caller has to special-case.
		{"empty_input", ``, SchemaNotPublished},
		{"whitespace_only", "  \n\t ", SchemaNotPublished},
		// A boolean IS a schema in 2020-12, but data_schema is a google.protobuf.Struct,
		// which carries a JSON OBJECT and nothing else — so a bare true/false cannot
		// reach this face over the wire at all, and admitting it would pin behaviour
		// for a document the contract cannot transport.
		{"boolean_true_schema", `true`, SchemaMalformed},
		{"boolean_false_schema", `false`, SchemaMalformed},
		{"json_array_at_the_top_level", `[{"type":"object"}]`, SchemaMalformed},
		{"json_string_at_the_top_level", `"a schema"`, SchemaMalformed},
		{"trailing_content_after_the_document", `{"type":"object"} {}`, SchemaMalformed},
		// Well-formed JSON, past every rule above, and still not a 2020-12 schema.
		{"type_names_a_type_that_does_not_exist", `{"type":"objekt"}`, SchemaUncompilable},
		{"required_is_not_a_list", `{"type":"object","required":"vat_id"}`, SchemaUncompilable},

		// A FLAT reference chain: every definition is a sibling, so the document is three
		// containers deep and the lexical depth cap never sees it, while the walk that
		// follows references sees one link per definition. Ordinary JSON, well under the
		// size cap, and costing one evaluation per link — so neither of the other two
		// caps sees it either. It is bounded on its own axis because the libraries the
		// three SDKs hand an accepted schema to resolve such a chain RECURSIVELY, and one
		// of them exhausted its interpreter stack at 495 links, raising out of a face
		// documented as returning a verdict on a document every SDK had just accepted.
		//
		// flatRefChain(n) is n+1 hops: the document's own $ref, then one per definition.
		{"a_reference_chain_at_the_hop_cap", flatRefChain(MaxRegistrationSchemaRefHops - 1), SchemaAccepted},
		{"a_reference_chain_one_hop_over", flatRefChain(MaxRegistrationSchemaRefHops), SchemaRefChainTooLong},
		{"a_long_flat_reference_chain", flatRefChain(500), SchemaRefChainTooLong},

		// The same chain, entered in pieces. A count that watches only how far the walk
		// has come measures the walk rather than the document: a target counted once at a
		// low hop count answers every later arrival with what it already knows, so a
		// chain reached through seeds spaced under the cap passes every segment and the
		// whole is never measured. The chain here is 150 links against a cap of 100.
		{"a_seeded_reference_chain_over_the_hop_cap", seededRefChain(150, 80), SchemaRefChainTooLong},

		// One graph, two orders. Same definitions, same links, same longest path of 145 —
		// only the order the root lists its two branches in differs. Both must refuse, and
		// they must refuse alike: a bound over a graph that answers by visit order is not
		// a property of the document, and the two ends of one registration do not agree on
		// how a schema's members happen to be ordered.
		{
			"a_shared_reference_tail_with_the_long_branch_first",
			sharedTailRefChain(95, 50, false, "h", "t"),
			SchemaRefChainTooLong,
		},
		{
			"a_shared_reference_tail_with_the_short_branch_first",
			sharedTailRefChain(95, 50, true, "h", "t"),
			SchemaRefChainTooLong,
		},
		// The same graph again, with the tail named so it SORTS before the head. A walk
		// that drains its pending references in name order counts the tail first, so the
		// head's arrival at it finds a target already counted and is measured only if
		// arriving at a known target is measured at all. The two above cannot show that:
		// their head sorts first either way.
		{
			"a_shared_reference_tail_that_sorts_before_its_head",
			sharedTailRefChain(95, 50, false, "z", "a"),
			SchemaRefChainTooLong,
		},
		// And the boundary on that shape, so an exact count is not mistaken for a blanket
		// refusal of shared tails: two branches into one tail are ordinary reuse, and a
		// document whose longest path fits is still a document that fits.
		{"a_shared_reference_tail_at_the_hop_cap", sharedTailRefChain(60, 40, false, "h", "t"), SchemaAccepted},
		{"a_shared_reference_tail_one_hop_over", sharedTailRefChain(60, 41, false, "h", "t"), SchemaRefChainTooLong},

		// Refused — the ENCODING, which decides WHICH document the rules above are
		// read against. Each of these got three different answers from the three SDKs
		// before it was pinned here, and none of it was the JSON grammar's doing: it
		// was the byte decode in front of it.
		//
		// NaN and Infinity are not JSON (RFC 8259 §6 excludes them from the grammar),
		// but Python's json.loads accepts all three as an extension.
		{"nan_literal", `{"type":"object","properties":{"k":{"const":NaN}}}`, SchemaMalformed},
		{"infinity_literal", `{"type":"object","properties":{"k":{"const":Infinity}}}`, SchemaMalformed},
		{"negative_infinity_literal", `{"type":"object","properties":{"k":{"const":-Infinity}}}`, SchemaMalformed},
		// A byte order mark. RFC 8259 forbids adding one and permits a parser to
		// ignore one, so both policies conform and the choice had to be made once for
		// all three — Python and JavaScript strip it during the byte decode, Go does
		// not. It is refused: a stripped mark would make the size cap count three
		// bytes the schema does not contain, and a mark is only valid at the start of
		// a JSON text, never inside ramp.json where this member lives.
		{"byte_order_mark_before_the_document", "\ufeff" + `{"type":"object"}`, SchemaMalformed},
	}

	out := make([]compileVector, 0, len(cases)+len(rawByteCompileCases))
	for _, c := range cases {
		_, got := CompileRegistrationSchema([]byte(c.schema))
		if got != c.want {
			t.Fatalf("compile vector %s: oracle verdict=%s, intended=%s", c.name, got, c.want)
		}
		out = append(out, compileVector{Name: c.name, Schema: c.schema, Verdict: got.String()})
	}
	// The byte-valued cases, carried as base64 because they are not expressible as a
	// JSON string at all. The size cap and the encoding rule are both defined over
	// the bytes AS SERVED, so a corpus that could only state well-formed UTF-8 could
	// not state the rule that decides what well-formed means.
	for _, c := range rawByteCompileCases {
		_, got := CompileRegistrationSchema(c.raw)
		if got != c.want {
			t.Fatalf("compile vector %s: oracle verdict=%s, intended=%s", c.name, got, c.want)
		}
		out = append(out, compileVector{
			Name:      c.name,
			SchemaB64: base64.StdEncoding.EncodeToString(c.raw),
			Verdict:   got.String(),
		})
	}
	return out
}

// rawByteCompileCases are compile cases whose input is a byte sequence rather than
// text. Invalid UTF-8 is the reason this exists: Go's encoding/json silently repairs
// an ill-formed byte to U+FFFD, so without an explicit validity check the document
// enforced is not the document served — a `pattern` or `const` carrying one bad byte
// would be enforced with a different character inside it, silently, while the two
// ports refuse the same bytes outright.
var rawByteCompileCases = []struct {
	name string
	raw  []byte
	want SchemaVerdict
}{
	{
		name: "invalid_utf8_inside_a_string",
		raw:  []byte(`{"type":"object","title":"` + "\xff\xfe" + `"}`),
		want: SchemaMalformed,
	},
	{
		name: "invalid_utf8_inside_a_pattern",
		raw:  []byte(`{"type":"object","properties":{"k":{"type":"string","pattern":"^a` + "\xff" + `$"}}}`),
		want: SchemaMalformed,
	},
	{
		name: "a_lone_continuation_byte_at_the_head",
		raw:  []byte("\x80" + `{"type":"object"}`),
		want: SchemaMalformed,
	},

	// What counts as "no schema published", which is the ENFORCEMENT SWITCH: reading
	// a document as blank reads it as "publishes none", and validation is then off.
	// Each language's own idea of whitespace is a different set, so the question is
	// asked over the bytes with RFC 8259's four and nothing else.
	//
	// The byte order mark cases are the ones that motivated this. Decoding before
	// testing for blankness made "mark, then a space" look empty in the TypeScript
	// port, because TextDecoder strips the mark — so the document never reached the
	// rule that refuses a mark, and an Exchange whose configured schema was an empty
	// file saved with one would have run with enforcement silently off while the other
	// two called it malformed.
	{name: "a_byte_order_mark_alone", raw: []byte("\ufeff"), want: SchemaMalformed},
	{name: "a_byte_order_mark_then_only_spaces", raw: []byte("\ufeff  "), want: SchemaMalformed},
	// Whitespace the languages disagree about: U+00A0, U+2028 and U+3000 are space to
	// two of the three and not to the other. None of them is JSON whitespace, so the
	// document is not blank — it is a document that is not JSON.
	{name: "a_no_break_space_alone", raw: []byte("\u00a0"), want: SchemaMalformed},
	{name: "a_line_separator_alone", raw: []byte("\u2028"), want: SchemaMalformed},
	{name: "an_ideographic_space_alone", raw: []byte("\u3000"), want: SchemaMalformed},
	// A vertical tab and a form feed are whitespace to all three languages and to
	// none of JSON. They agreed on the wrong answer before, which no parity test could
	// have caught — only the grammar decides this one.
	{name: "a_vertical_tab_alone", raw: []byte("\v"), want: SchemaMalformed},
	{name: "a_form_feed_alone", raw: []byte("\f"), want: SchemaMalformed},
	// The four that ARE JSON whitespace still read as "publishes none", which is the
	// contract's ordinary case and must keep working.
	{name: "only_json_whitespace", raw: []byte(" \t\r\n"), want: SchemaNotPublished},
}

// flatRefChain builds a document whose definitions form a chain of n links, each one
// referring to the next. Every definition is a sibling of the others, so the document
// nests only three containers deep however long the chain is — which is exactly why the
// depth cap cannot stand in for a bound on reference following.
func flatRefChain(n int) string {
	var b strings.Builder
	b.WriteString(`{"$defs":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + strconv.Itoa(i) + `":{"$ref":"#/$defs/` + strconv.Itoa(i+1) + `"}`)
	}
	b.WriteString(`,"` + strconv.Itoa(n) + `":{"type":"string"}},"$ref":"#/$defs/0"}`)
	return b.String()
}

// seededRefChain is a chain of `links` definitions the root enters at several points at
// once, seeds spaced `every` links apart and the deepest listed first. Every segment
// between two seeds is shorter than the cap while the chain as a whole is `links` hops,
// so it is refused only by a count that measures the document rather than the walk.
func seededRefChain(links, every int) string {
	var b strings.Builder
	b.WriteString(`{"allOf":[`)
	for i, seed := ((links-1)/every)*every, 0; i >= 0; i, seed = i-every, seed+1 {
		if seed > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"$ref":"#/$defs/` + strconv.Itoa(i) + `"}`)
	}
	b.WriteString(`],"$defs":{`)
	for i := 0; i < links; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + strconv.Itoa(i) + `":`)
		if i == links-1 {
			b.WriteString(`{"type":"string"}`)
			continue
		}
		b.WriteString(`{"$ref":"#/$defs/` + strconv.Itoa(i+1) + `"}`)
	}
	b.WriteString(`}}`)
	return b.String()
}

// sharedTailRefChain is a head chain of `head` definitions running into a tail chain of
// `tail`, with the root referencing both the head and the tail directly. The longest
// path is head+tail hops and the short branch straight to the tail is `tail`.
//
// Two things vary that must not change the answer, because neither is a property of the
// graph. shortBranchFirst swaps the order the root LISTS the two branches, which is what
// a walk following the document sees. headName and tailName set how the definitions
// SORT, which is what a walk draining a set of pending references sees — name the tail
// before the head and such a walk counts the tail first, so every later arrival finds it
// already known and measures nothing.
func sharedTailRefChain(head, tail int, shortBranchFirst bool, headName, tailName string) string {
	longBranch := `{"$ref":"#/$defs/` + headName + `0"}`
	shortBranch := `{"$ref":"#/$defs/` + tailName + `0"}`
	branches := longBranch + "," + shortBranch
	if shortBranchFirst {
		branches = shortBranch + "," + longBranch
	}
	var b strings.Builder
	b.WriteString(`{"allOf":[` + branches + `],"$defs":{`)
	for i := 0; i < head; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		next := headName + strconv.Itoa(i+1)
		if i == head-1 {
			next = tailName + "0"
		}
		b.WriteString(`"` + headName + strconv.Itoa(i) + `":{"$ref":"#/$defs/` + next + `"}`)
	}
	for i := 0; i < tail; i++ {
		b.WriteString(`,"` + tailName + strconv.Itoa(i) + `":`)
		if i == tail-1 {
			b.WriteString(`{"type":"string"}`)
			continue
		}
		b.WriteString(`{"$ref":"#/$defs/` + tailName + strconv.Itoa(i+1) + `"}`)
	}
	b.WriteString(`}}`)
	return b.String()
}

// buildRegSchemaValidateVectors enumerates what a refusal has to SAY. The pointer
// shape is the contract's (RFC 6901, relative to registration_data, empty for the
// whole object), and the ordering and the cap are pinned here because three
// validators walk a failing document in three different orders.
func buildRegSchemaValidateVectors(t *testing.T) []validateVector {
	t.Helper()

	const basic = `{"type":"object","required":["legal_name","vat_id"],` +
		`"properties":{"legal_name":{"type":"string","minLength":1},` +
		`"vat_id":{"type":"string","pattern":"^[A-Z]{2}[0-9]+$"},` +
		`"address":{"type":"object","required":["postal_code"],` +
		`"properties":{"postal_code":{"type":"string","minLength":4}}}}}`

	cases := []struct {
		name         string
		schema       string
		data         map[string]any
		wantPaths    []string
		wantKeywords []string
	}{
		{
			name:   "a_conforming_payload",
			schema: basic,
			data:   map[string]any{"legal_name": "Acme GmbH", "vat_id": "DE12345"},
		},
		{
			// A missing member is reported at the OBJECT that requires it, not at the
			// member that is not there — there is no pointer to something absent.
			name:         "a_missing_required_member",
			schema:       basic,
			data:         map[string]any{"legal_name": "Acme GmbH"},
			wantPaths:    []string{""},
			wantKeywords: []string{"required"},
		},
		{
			name:         "a_member_of_the_wrong_type",
			schema:       basic,
			data:         map[string]any{"legal_name": "Acme GmbH", "vat_id": 42.0},
			wantPaths:    []string{"/vat_id"},
			wantKeywords: []string{"type"},
		},
		{
			name:         "a_member_failing_its_pattern",
			schema:       basic,
			data:         map[string]any{"legal_name": "Acme GmbH", "vat_id": "not-a-vat"},
			wantPaths:    []string{"/vat_id"},
			wantKeywords: []string{"pattern"},
		},
		{
			// The nested pointer the field comment gives as its own example.
			name:         "a_nested_member",
			schema:       basic,
			data:         map[string]any{"legal_name": "Acme GmbH", "vat_id": "DE12345", "address": map[string]any{"postal_code": "1"}},
			wantPaths:    []string{"/address/postal_code"},
			wantKeywords: []string{"minLength"},
		},
		{
			name:         "a_nested_missing_member",
			schema:       basic,
			data:         map[string]any{"legal_name": "Acme GmbH", "vat_id": "DE12345", "address": map[string]any{}},
			wantPaths:    []string{"/address"},
			wantKeywords: []string{"required"},
		},
		{
			// Two failures at once, which is what pins the ORDER: sorted by pointer,
			// so /legal_name precedes /vat_id no matter which the validator saw first.
			name:         "two_members_failing_at_once",
			schema:       basic,
			data:         map[string]any{"legal_name": "", "vat_id": "nope"},
			wantPaths:    []string{"/legal_name", "/vat_id"},
			wantKeywords: []string{"minLength", "pattern"},
		},
		{
			// A whole-object failure belonging to no single member: the empty pointer.
			name:         "a_whole_object_failure",
			schema:       `{"type":"object","minProperties":2}`,
			data:         map[string]any{"legal_name": "Acme GmbH"},
			wantPaths:    []string{""},
			wantKeywords: []string{"minProperties"},
		},
		{
			// patternProperties states its regexes as KEYS, so a port that corrects
			// matching by overriding the `pattern` KEYWORD does not reach them. The
			// match dimension cannot catch this — it drives patterns directly — so the
			// route is pinned here instead. A non-ASCII digit must fail the key test in
			// every port, leaving the member unmatched and additionalProperties to
			// refuse it.
			name:         "a_pattern_properties_key_against_a_non_ascii_digit",
			schema:       `{"type":"object","patternProperties":{"^\\d+$":{"type":"string"}},"additionalProperties":false}`,
			data:         map[string]any{"١٢٣": "x"},
			wantPaths:    []string{""},
			wantKeywords: []string{"additionalProperties"},
		},
		{
			// The same route, against the trailing-newline divergence rather than the
			// character-class one.
			name:         "a_pattern_properties_key_against_a_trailing_newline",
			schema:       `{"type":"object","patternProperties":{"^a$":{"type":"string"}},"additionalProperties":false}`,
			data:         map[string]any{"a\n": "x"},
			wantPaths:    []string{""},
			wantKeywords: []string{"additionalProperties"},
		},
		{
			// A key the pattern DOES match, so the vector above is pinning a refusal
			// rather than a schema nothing can satisfy.
			name:         "a_pattern_properties_key_that_matches",
			schema:       `{"type":"object","patternProperties":{"^\\d+$":{"type":"string"}},"additionalProperties":false}`,
			data:         map[string]any{"123": 7},
			wantPaths:    []string{"/123"},
			wantKeywords: []string{"type"},
		},
		{
			// Every branch of the composite is a $ref. A leaf filter keyed on schema
			// path nesting does not recognise the hop — the leaf reports under $defs,
			// not under the anyOf — and the composite's own failure survives as an
			// extra, less specific error beside the real one. Naming one of several
			// defined formats is an ordinary registration shape, so this is reachable.
			name: "a_composite_whose_branches_are_all_refs",
			schema: `{"type":"object","$defs":{"i":{"type":"integer"},"b":{"type":"boolean"}},` +
				`"properties":{"k":{"anyOf":[{"$ref":"#/$defs/i"},{"$ref":"#/$defs/b"}]}}}`,
			data:         map[string]any{"k": "x"},
			wantPaths:    []string{"/k"},
			wantKeywords: []string{"type"},
		},
		{
			// Both branches fail the same keyword at the same pointer, so the answer
			// is ONE entry: the report is the set of distinct constraints that failed,
			// not a list with one row per branch the validator happened to walk. The
			// three libraries surface a different number of rows here, and this case
			// is where a port that passed them through unfiltered goes red.
			name:         "a_oneOf_where_every_branch_failed_the_same_way",
			schema:       `{"type":"object","oneOf":[{"required":["vat_id"]},{"required":["tax_id"]}]}`,
			data:         map[string]any{"legal_name": "Acme GmbH"},
			wantPaths:    []string{""},
			wantKeywords: []string{"required"},
		},
		{
			// The same composite, failing DIFFERENTLY per branch, so the two entries
			// are genuinely distinct and both survive.
			name:         "a_oneOf_whose_branches_failed_differently",
			schema:       `{"type":"object","oneOf":[{"required":["vat_id"]},{"minProperties":3}]}`,
			data:         map[string]any{"legal_name": "Acme GmbH"},
			wantPaths:    []string{"", ""},
			wantKeywords: []string{"minProperties", "required"},
		},
		{
			name:         "an_unknown_member_where_none_are_allowed",
			schema:       `{"type":"object","properties":{"vat_id":{"type":"string"}},"additionalProperties":false}`,
			data:         map[string]any{"vat_id": "DE1", "smuggled": "x"},
			wantPaths:    []string{""},
			wantKeywords: []string{"additionalProperties"},
		},
		{
			// A pointer token carrying the two characters RFC 6901 escapes. Without
			// this an implementation that concatenated tokens raw would agree with the
			// oracle everywhere else and name the wrong member here.
			name:         "a_member_whose_name_needs_pointer_escaping",
			schema:       `{"type":"object","properties":{"a/b~c":{"type":"string"}}}`,
			data:         map[string]any{"a/b~c": 1.0},
			wantPaths:    []string{"/a~1b~0c"},
			wantKeywords: []string{"type"},
		},
		{
			// format is an ANNOTATION, never an assertion: a value that is not an
			// email conforms to a schema that says format: email. The three libraries
			// default differently, so this case is the one that stops a port from
			// quietly turning assertion on.
			name:   "format_is_annotation_only",
			schema: `{"type":"object","properties":{"email":{"type":"string","format":"email"}}}`,
			data:   map[string]any{"email": "not-an-email"},
		},
		{
			// An empty payload against a schema demanding members: the check runs
			// rather than short-circuiting into "nothing to validate".
			name:         "an_empty_payload",
			schema:       basic,
			data:         map[string]any{},
			wantPaths:    []string{""},
			wantKeywords: []string{"required"},
		},
	}

	out := make([]validateVector, 0, len(cases)+1)
	for _, c := range cases {
		sch, v := CompileRegistrationSchema([]byte(c.schema))
		if v != SchemaAccepted {
			t.Fatalf("validate vector %s: its schema does not compile (%s)", c.name, v)
		}
		paths, keywords := oracleViolations(sch, c.data)
		assertStringsEqual(t, c.name, "paths", paths, c.wantPaths)
		assertStringsEqual(t, c.name, "keywords", keywords, c.wantKeywords)
		out = append(out, validateVector{
			Name: c.name, Schema: c.schema, Data: c.data,
			Paths: paths, Keywords: keywords,
		})
	}
	out = append(out, buildTruncationVector(t), buildAstralPointerVector(t))
	return out
}

// buildTruncationVector states the cap on the failure list itself. It is built
// rather than written out because it needs more members than the cap allows, and a
// hand-typed 70-property schema would be unreadable and unmaintainable.
func buildTruncationVector(t *testing.T) validateVector {
	t.Helper()
	const members = MaxRegistrationFieldErrors + 6

	var props, req []string
	data := map[string]any{}
	for i := 0; i < members; i++ {
		name := "f" + pad2(i)
		props = append(props, `"`+name+`":{"type":"string"}`)
		req = append(req, `"`+name+`"`)
		// Every member present and every one the wrong type, so the payload produces
		// one failure per member and the list has to be cut.
		data[name] = float64(i)
	}
	schema := `{"type":"object","required":[` + strings.Join(req, ",") + `],"properties":{` + strings.Join(props, ",") + `}}`

	sch, v := CompileRegistrationSchema([]byte(schema))
	if v != SchemaAccepted {
		t.Fatalf("truncation vector: its schema does not compile (%s)", v)
	}
	paths, keywords := oracleViolations(sch, data)
	if len(paths) != MaxRegistrationFieldErrors {
		t.Fatalf("truncation vector: oracle returned %d entries, intended exactly %d",
			len(paths), MaxRegistrationFieldErrors)
	}
	// The SURVIVORS are the lexicographically first ones, which is the property that
	// makes the cut reproducible: any order-dependent implementation keeps a
	// different 64 and fails here.
	if paths[0] != "/f00" || paths[len(paths)-1] != "/f63" {
		t.Fatalf("truncation vector: oracle kept %s..%s, intended /f00../f63", paths[0], paths[len(paths)-1])
	}
	return validateVector{
		Name: "more_failures_than_the_wire_carries", Schema: schema, Data: data,
		Paths: paths, Keywords: keywords,
	}
}

// buildAstralPointerVector pins the UNIT the pointer bound is counted in.
//
// protovalidate's string.max_len counts CHARACTERS, and the three languages reach for
// three different lengths: bytes in Go, code points in Python, UTF-16 code units in
// JavaScript. A member name of astral characters separates all three — 200 of them are
// 200 characters, 800 bytes and 400 code units — so a port measuring the wrong one
// either clamps a pointer the others leave whole, naming a DIFFERENT member, or cuts
// through a character and emits a string proto.Marshal rejects. Nothing in the corpus
// distinguished them until this case existed.
func buildAstralPointerVector(t *testing.T) validateVector {
	t.Helper()
	// Comfortably inside the 255-character bound and comfortably outside it in UTF-16
	// code units, which is the whole point of the case.
	name := strings.Repeat("😀", 200)
	schema := `{"type":"object","properties":{"` + name + `":{"type":"string"}}}`
	data := map[string]any{name: float64(1)}

	sch, v := CompileRegistrationSchema([]byte(schema))
	if v != SchemaAccepted {
		t.Fatalf("astral pointer vector: its schema does not compile (%s)", v)
	}
	paths, keywords := oracleViolations(sch, data)
	want := "/" + name
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("astral pointer vector: oracle returned %q, intended the whole pointer "+
			"(%d characters, under the %d-character bound)",
			paths, utf8.RuneCountInString(want), MaxRegistrationFieldErrorPathLen)
	}
	return validateVector{
		Name: "a_member_named_in_astral_characters", Schema: schema, Data: data,
		Paths: paths, Keywords: keywords,
	}
}

// pad2 keeps the generated member names the same width, so the lexicographic order
// the cut relies on is also the numeric one — "f9" would otherwise sort after "f63"
// and make the surviving set read as arbitrary.
func pad2(i int) string {
	s := strconv.Itoa(i)
	if len(s) < 2 {
		return "0" + s
	}
	return s
}

// oracleViolations runs the REAL faces and returns the two parallel lists. Paths
// come from the public Validate — the shape a caller actually sends — while the
// keywords come from the internal projection, because the wire carries prose the
// corpus deliberately does not pin.
func oracleViolations(s *RegistrationSchema, data map[string]any) (paths, keywords []string) {
	fes := s.Validate(data)
	vs := s.violations(anyOrEmpty(data))
	if len(fes) != len(vs) {
		panic("Validate and violations disagree about how many constraints failed")
	}
	paths = make([]string, 0, len(fes))
	keywords = make([]string, 0, len(vs))
	for i := range fes {
		if fes[i].GetPath() != vs[i].Path {
			panic("Validate and violations disagree about a pointer")
		}
		paths = append(paths, fes[i].GetPath())
		keywords = append(keywords, vs[i].Keyword)
	}
	return paths, keywords
}

func anyOrEmpty(data map[string]any) any {
	if data == nil {
		return map[string]any{}
	}
	return data
}

func assertStringsEqual(t *testing.T, caseName, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("validate vector %s: oracle %s=%v, intended %v", caseName, what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("validate vector %s: oracle %s=%v, intended %v", caseName, what, got, want)
		}
	}
}

// buildRegSchemaPatternVectors enumerates the pattern alphabet on its own. Both
// directions of the cross-engine gap are represented: constructs RE2 refuses and
// the other two take, and constructs RE2 (or Python) takes and JavaScript does not
// — the second kind being the dangerous one, because nothing errors and the two
// engines simply match different strings.
func buildRegSchemaPatternVectors(t *testing.T) []patternVector {
	t.Helper()
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		// Accepted — the alphabet all three engines share.
		{"empty", "", true},
		{"literal", "abc", true},
		{"anchored_class", "^[A-Z]{2}[0-9]+$", true},
		{"alternation", "^(cat|dog)$", true},
		{"capturing_group", "^(ab)+$", true},
		{"non_capturing_group", "^(?:ab)+$", true},
		// Refused by the nested-quantifier rule, not by the alphabet: the body of the
		// quantified group can itself vary in length, which is the shape a backtracking
		// engine explores exponentially. A safe rewrite exists ("^(?:abc|a)+$" is not
		// one — it branches; "^a(?:bc)?$" without the outer repeat is).
		{"quantified_group_with_optional_body", "^(?:a(?:bc)?)+$", false},
		{"shared_escape_classes", `^\d+\w+$`, true},
		// \s is NOT shared: three engines, three whitespace sets, and the difference is
		// silent — every one of them compiles the pattern.
		{"whitespace_class", `^a\sb$`, false},
		{"negated_whitespace_class", `^a\Sb$`, false},
		// An explicit class says what was meant, and means it everywhere.
		{"explicit_space_class", `^a[ \t]b$`, true},
		{"escaped_metacharacters", `^\.\+\*\?\[\]\{\}$`, true},
		// An escaped paren followed by "?=" is a LITERAL "(?=", not a lookahead. The
		// scan has to consume the escape or it refuses a pattern every engine accepts.
		{"escaped_paren_before_a_question_mark", `^\(\?=x\)$`, true},
		// The inverse trap: a backslash that is itself escaped leaves the next
		// character as syntax. Without this case an implementation that skipped one
		// character per backslash unconditionally would agree everywhere else.
		{"escaped_backslash_then_a_group", `^\\(?:ab)$`, true},
		// "[]" straight after the opening bracket is a literal in POSIX and an empty
		// class in ECMA, and the engines disagree about whether the whole thing even
		// compiles — so the shape is refused rather than left to them.
		{"class_opening_with_a_bracket", `^[][]$`, false},

		// Refused — legal ECMA-262, no RE2 equivalent.
		{"lookahead", "^(?=.*x).+$", false},
		{"negative_lookahead", "^(?!x).*$", false},
		{"lookbehind", "(?<=a)b", false},
		{"negative_lookbehind", "(?<!a)b", false},
		{"ecma_named_group", "(?<year>[0-9]{4})", false},
		{"atomic_group", "(?>a+)b", false},
		{"backreference", `^(a)\1$`, false},
		{"named_backreference", `^(?<x>a)\k<x>$`, false},

		// Refused — taken by RE2 or Python and NOT by JavaScript, or taken by both
		// with different meanings. These are the silent ones.
		{"inline_flags", "(?i)abc", false},
		{"go_named_group", "(?P<year>[0-9]{4})", false},
		{"unicode_property_class", `^\p{L}+$`, false},
		{"negated_unicode_property_class", `^\P{L}+$`, false},
		{"text_start_anchor", `\Aabc`, false},
		{"text_end_anchor", `abc\z`, false},
		{"absolute_end_anchor", `abc\Z`, false},
		{"literal_span", `\Qa.b\E`, false},
		{"posix_class", "^[[:alpha:]]+$", false},

		// Refused by the ALLOWLIST rather than by a named exclusion. Each of these was
		// admitted while the rule enumerated the divergent escapes instead of the
		// portable ones, and each was found by trying rather than by reasoning — which
		// is the argument for stating the rule from this side.
		//
		// \B is the one that matters most: all three engines compile it and then
		// disagree about the empty string, where RE2 and ECMA-262 find no word boundary
		// and Python does. Nothing errors, so only a match test could ever have caught
		// it. \b agrees on its own and is refused with it, because it is near-useless
		// in an anchored field matcher and [\b] is a different construct that RE2
		// rejects outright.
		{"word_boundary", `\bword\b`, false},
		{"non_word_boundary", `a\Bb`, false},
		{"backspace_in_class", `[\b]`, false},
		// A control escape, a JavaScript-only unicode escape, and an alert: each
		// compiles somewhere and fails somewhere else.
		{"control_escape", `\cA`, false},
		{"js_unicode_escape", "\\u0041", false},
		{"alert_escape", `\a`, false},
		// An identity escape — a backslash before a character that is not a regex
		// metacharacter. RE2 and Python allow it; ECMA-262 under the `u` flag refuses
		// it, and the TypeScript validator compiles every pattern with that flag. The
		// character itself is always admitted, so the rewrite is to delete a backslash.
		{"identity_escape_hyphen", `a\-z`, false},
		{"identity_escape_underscore", `\_`, false},
		{"class_range_from_a_class", `[\w-x]`, false},
		// \xHH is admitted by SHAPE — exactly two hex digits. The brace form is an RE2
		// spelling the other two refuse, and a short one is refused by all three.
		{"hex_escape", `^\x41$`, true},
		{"hex_escape_lowercase_in_class", `^[\x0a]$`, true},
		{"brace_hex_escape", `\x{41}`, false},
		{"short_hex_escape", `\x4`, false},
		{"non_hex_escape", `\xZZ`, false},
		// \0 agrees on its own and is still refused: admitting it would consume the
		// "\0" of "\012" and leave "12" as literals, silently admitting an octal escape
		// the engines do NOT agree on.
		{"null_escape", `\0`, false},
		{"octal_escape", `\012`, false},

		// Refused — nested quantifiers. Catastrophic backtracking needs neither
		// lookaround nor backreferences, so the escape list above does not cover it,
		// and no timer in the backtracking ports could: a regex spin holds CPython's
		// interpreter and blocks Node's event loop.
		{"quantified_group_with_inner_plus", `(a+)+$`, false},
		{"quantified_group_with_inner_star", `^(?:a*)*b$`, false},
		{"quantified_group_with_inner_optional", `(a?)+$`, false},
		{"quantified_group_with_alternation", `(a|a)*$`, false},
		{"quantified_group_with_class_repeat", `([a-zA-Z]+)*$`, false},
		// The same group WITHOUT the outer quantifier is ordinary and admitted.
		{"unquantified_group_with_alternation", `^(cat|dog)$`, true},
		{"quantified_group_with_a_fixed_body", `^(?:ab)+$`, true},

		// Refused — a repeat bound the engines do not share. RE2 refuses a count over
		// 1000 outright where the other two expand it.
		{"repeat_at_the_portable_bound", `^a{1000}$`, true},
		// A counted repeat with no first bound. RE2 reads "a{,5}" as the five literal
		// characters and Python reads it as a repeat of zero to five, so both engines
		// compile the pattern and then disagree about which payloads match it — the
		// silent class, and the reason the first bound is now required. "{n,}" is a
		// different shape and stays admitted.
		{"repeat_missing_the_first_bound", `^a{,5}$`, false},
		{"open_ended_repeat_keeps_its_empty_second_part", `^a{2,}$`, true},
		// A body with more than two parts. Every engine refuses it, but this port's
		// scanner admitted it: JavaScript's String.split takes an element LIMIT that
		// discards the remainder, where Go's SplitN and Python's maxsplit keep it, so
		// "1,2,3" arrived as two clean numbers here and as "1" and "2,3" there.
		{"repeat_with_three_parts", `^a{1,2,3}$`, false},
		// A closing brace that closes nothing. RE2 and Python read it as a literal and
		// ECMA-262 under the `u` flag refuses it, exactly like the unmatched "]" above.
		{"unmatched_closing_brace", `^price}$`, false},
		{"escaped_closing_brace_is_a_literal", `^price\}$`, true},
		{"repeat_over_the_portable_bound", `^a{1001}$`, false},
		{"open_ended_repeat", `^a{2,}$`, true},
		{"bare_brace", `a{`, false},

		// Refused — bracket expressions the engines read differently.
		{"posix_class_mid_bracket", "^[a[:alpha:]]+$", false},
		{"unmatched_closing_bracket", `]`, false},
		{"unclosed_class", `^[abc`, false},

		// Refused — not a pattern any engine compiles.
		{"trailing_backslash", `abc\`, false},
		{"bare_group_prefix", "(?", false},
	}

	out := make([]patternVector, 0, len(cases))
	for _, c := range cases {
		got := IsSafeSchemaPattern(c.pattern)
		if got != c.want {
			t.Fatalf("pattern vector %s: oracle safe=%v, intended=%v for %q", c.name, got, c.want, c.pattern)
		}
		// Self-consistency: a pattern this rule ADMITS must be one Go can actually
		// compile, or the alphabet promises an agreement the Go SDK cannot keep.
		if got {
			if _, err := regexp.Compile(c.pattern); err != nil {
				t.Fatalf("pattern vector %s: the alphabet admits %q, which Go refuses to compile: %v", c.name, c.pattern, err)
			}
		}
		out = append(out, patternVector{Name: c.name, Pattern: c.pattern, Safe: got})
	}
	return out
}

// portablePatternEscapes renders the admitted escape set as sorted characters, so the
// corpus carries the rule itself rather than a description of it. Both halves are
// emitted together — the classes and control characters, and the metacharacters that
// stand for themselves — because the contract states one alphabet, not two.
//
// `x` is deliberately absent: \xHH is admitted by shape, not by letter, so a single
// character could not represent it and a port that dropped the two-hex-digit rule
// would still match this string.
func portablePatternEscapes() string {
	out := make([]byte, 0, len(portableEscapes)+len(portableSyntaxEscapes))
	for c := range portableEscapes {
		out = append(out, c)
	}
	for c := range portableSyntaxEscapes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return string(out)
}

// schemaVerdictVocabulary is every token the face can answer with. A port that grew a
// verdict the oracle does not have, or lost one it does, is caught by comparing this
// list rather than by whichever cases happen to exercise each token.
func schemaVerdictVocabulary() []string {
	all := []SchemaVerdict{
		SchemaNoVerdict, SchemaAccepted, SchemaMalformed, SchemaWrongDialect,
		SchemaRemoteRef, SchemaTooLarge, SchemaTooDeep, SchemaUnsafePattern,
		SchemaTooComplex, SchemaRefCycle, SchemaRefChainTooLong, SchemaCompileTimeout,
		SchemaUncompilable,
		SchemaNotPublished,
	}
	out := make([]string, 0, len(all))
	for _, v := range all {
		out = append(out, v.String())
	}
	return out
}

// TestGenerateRegSchemaVectors emits the registration-schema golden corpus.
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateRegSchemaVectors(t *testing.T) {
	doc := map[string]any{
		"dialect":                  RegistrationSchemaDialect,
		"max_schema_bytes":         MaxRegistrationSchemaBytes,
		"max_schema_depth":         MaxRegistrationSchemaDepth,
		"max_schema_evaluations":   MaxRegistrationSchemaEvaluations,
		"max_schema_ref_hops":      MaxRegistrationSchemaRefHops,
		"max_field_errors":         MaxRegistrationFieldErrors,
		"max_field_error_path_len": MaxRegistrationFieldErrorPathLen,
		"max_field_error_text_len": MaxRegistrationFieldErrorTextLen,
		// The alphabet as DATA, not as a sentence a guard restates. The conformance
		// tier compares these against the contract's own wording, and a rule stated
		// only in prose on both sides is one nothing compares: dropping an escape from
		// all three SDKs used to leave every gate green.
		"max_registration_data_bytes":   MaxRegistrationDataBytes,
		"max_registration_data_members": MaxRegistrationDataMembers,
		"max_registration_data_depth":   MaxRegistrationDataDepth,
		"registration_data_verdicts":    regDataVerdictVocabulary(),
		"portable_pattern_escapes":      portablePatternEscapes(),
		"max_pattern_repeat":            maxPortableRepeat,
		"verdicts":                      schemaVerdictVocabulary(),
		"compile":                       buildRegSchemaCompileVectors(t),
		"validate":                      buildRegSchemaValidateVectors(t),
		"pattern":                       buildRegSchemaPatternVectors(t),
		"match":                         buildRegSchemaMatchVectors(t),
		"registration_data":             buildRegDataVectors(t),
	}
	path := filepath.Join("testdata", "registration-schema-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
