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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// compileVector is one CompileRegistrationSchema case. The schema is carried as the
// RAW JSON TEXT rather than as a nested object, for two reasons: the size cap is
// defined over the bytes as served, so a corpus that re-encoded the schema could not
// state the boundary case at all; and a port reads the same bytes this face read.
type compileVector struct {
	Name    string `json:"name"`
	Schema  string `json:"schema"`
	Verdict string `json:"expected_verdict"`
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
		{"boolean_true_schema", `true`, SchemaAccepted},
		{"boolean_false_schema", `false`, SchemaAccepted},
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

		// Refused — a pattern outside the shared alphabet.
		{"pattern_with_lookahead", objectSchema(`{"type":"string","pattern":"^(?=.*[0-9]).+$"}`), SchemaUnsafePattern},
		{"pattern_with_backreference", objectSchema(`{"type":"string","pattern":"^(a)\\1$"}`), SchemaUnsafePattern},
		{"pattern_properties_key_with_lookahead", `{"type":"object","patternProperties":{"^(?!x).*$":{"type":"string"}}}`, SchemaUnsafePattern},
		{"property_names_pattern_with_lookbehind", `{"type":"object","propertyNames":{"pattern":"(?<=a)b"}}`, SchemaUnsafePattern},

		// Refused — not a schema at all.
		{"not_json", `{"type":`, SchemaMalformed},
		{"empty_input", ``, SchemaMalformed},
		{"json_array_at_the_top_level", `[{"type":"object"}]`, SchemaMalformed},
		{"json_string_at_the_top_level", `"a schema"`, SchemaMalformed},
		{"trailing_content_after_the_document", `{"type":"object"} {}`, SchemaMalformed},
		// Well-formed JSON, past every rule above, and still not a 2020-12 schema.
		{"type_names_a_type_that_does_not_exist", `{"type":"objekt"}`, SchemaUncompilable},
		{"required_is_not_a_list", `{"type":"object","required":"vat_id"}`, SchemaUncompilable},
	}

	out := make([]compileVector, 0, len(cases))
	for _, c := range cases {
		_, got := CompileRegistrationSchema([]byte(c.schema))
		if got != c.want {
			t.Fatalf("compile vector %s: oracle verdict=%s, intended=%s", c.name, got, c.want)
		}
		out = append(out, compileVector{Name: c.name, Schema: c.schema, Verdict: got.String()})
	}
	return out
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
	out = append(out, buildTruncationVector(t))
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
		{"nested_non_capturing_groups", "^(?:a(?:bc)?)+$", true},
		{"shared_escape_classes", `^\d+\s\w+$`, true},
		{"escaped_metacharacters", `^\.\+\*\?\[\]\{\}$`, true},
		// An escaped paren followed by "?=" is a LITERAL "(?=", not a lookahead. The
		// scan has to consume the escape or it refuses a pattern every engine accepts.
		{"escaped_paren_before_a_question_mark", `^\(\?=x\)$`, true},
		// The inverse trap: a backslash that is itself escaped leaves the next
		// character as syntax. Without this case an implementation that skipped one
		// character per backslash unconditionally would agree everywhere else.
		{"escaped_backslash_then_a_group", `^\\(?:ab)$`, true},
		{"class_containing_a_bracket", `^[][]$`, true},

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

// TestGenerateRegSchemaVectors emits the registration-schema golden corpus.
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateRegSchemaVectors(t *testing.T) {
	doc := map[string]any{
		"dialect":                  RegistrationSchemaDialect,
		"max_schema_bytes":         MaxRegistrationSchemaBytes,
		"max_schema_depth":         MaxRegistrationSchemaDepth,
		"max_field_errors":         MaxRegistrationFieldErrors,
		"max_field_error_path_len": MaxRegistrationFieldErrorPathLen,
		"max_field_error_text_len": MaxRegistrationFieldErrorTextLen,
		"compile":                  buildRegSchemaCompileVectors(t),
		"validate":                 buildRegSchemaValidateVectors(t),
		"pattern":                  buildRegSchemaPatternVectors(t),
	}
	path := filepath.Join("testdata", "registration-schema-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
