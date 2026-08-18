package conformance

// Drift guard: the registration-schema rules the SDK enforces ARE the rules the
// contract publishes.
//
// A published data_schema is read by two parties on opposite ends of one
// registration — the Exchange enforcing it, and a client pre-checking a payload
// before it signs and sends one — and soon by three SDK languages. Every one of
// them applies the same bounds, and the bounds therefore exist twice: as prose in
// the data_schema field comment, which is what a third-party implementor reads, and
// as constants in the SDK, which is what the reference implementations run. The
// whole point of the second copy is that a schema the SDK accepts is one the
// contract accepts, and that holds only while the two agree. Nothing made them
// agree; this file does.
//
// The neighbouring domain guard learned the same lesson the expensive way: two
// copies of the bare-domain rule drifted at the port group, every suite in every
// language passed, and it was found by reading both regexes side by side. The
// registration rules are MORE exposed to that failure, not less, because they have
// no protovalidate rule to compare against — data_schema is a Struct, and no
// field-level rule can reach inside one. The numbers live in a COMMENT.
//
// Which is why this guard has two halves that work differently:
//
//	The bounds on the FAILURE shape are real protovalidate rules, so they are read
//	live off the descriptor. A change to field_errors' max_items or to either
//	string bound is caught byte for byte.
//
//	The bounds on the SCHEMA itself — size, depth, dialect, the reference rule, the
//	pattern alphabet — exist only as comment text. They are checked by reading the
//	.proto SOURCE, because the generated descriptor does not retain source comments
//	and because the comment is what a human integrating against RAMP actually
//	reads. A number that moved in the SDK and not in the prose fails here.
//
// The proto is authoritative. On failure the contract has not moved to meet the
// SDK; the SDK must be brought to the contract and its vectors regenerated.
//
// The expected values are READ from the SDK's committed vectors rather than
// restated here, for the reason the neighbouring guards give at length: this
// package cannot import sdk/go — nothing in conformance depends on sdk/, by design,
// since it is the guard tier BELOW the SDKs. A committed file generated from the
// real Go constants, and already replayed by the Python and TypeScript parity
// suites, is a data read exactly like the corpus and the doc scans.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// regSchemaVectors is the committed cross-language oracle for the registration
// schema rules, emitted from the real Go constants by the sdk/go/helpers vector
// generator. Read as data (see the file header on why this is not an import).
const regSchemaVectors = "../sdk/go/helpers/testdata/registration-schema-vectors.json"

// sdkRegSchemaRule is the rule set the SDK ships, as recorded in the vectors.
type sdkRegSchemaRule struct {
	Dialect        string `json:"dialect"`
	MaxBytes       int    `json:"max_schema_bytes"`
	MaxDepth       int    `json:"max_schema_depth"`
	MaxEvaluations int    `json:"max_schema_evaluations"`
	MaxRepeat      int    `json:"max_pattern_repeat"`
	PortableEsc    string `json:"portable_pattern_escapes"`
	MaxErrors      uint64 `json:"max_field_errors"`
	MaxPathLen     uint64 `json:"max_field_error_path_len"`
	MaxErrTextLn   uint64 `json:"max_field_error_text_len"`
	MaxDataBytes   int    `json:"max_registration_data_bytes"`
	MaxDataMembers int    `json:"max_registration_data_members"`
}

var errNoSDKRegSchemaRule = errors.New(
	regSchemaVectors + " is missing one of dialect / max_schema_bytes / max_schema_depth / " +
		"max_schema_evaluations / max_pattern_repeat / portable_pattern_escapes / " +
		"max_field_errors / max_field_error_path_len / max_field_error_text_len / " +
		"max_registration_data_bytes / max_registration_data_members — this guard reads " +
		"the SDK's copy of the registration-schema rules from there")

// sdkRegRule reads the SDK's copy of the rules from the committed vectors. Errors
// are fatal rather than skipped: a missing file or key means this guard has lost
// its anchor, and passing silently would be worse than failing.
var sdkRegRule = sync.OnceValues(func() (sdkRegSchemaRule, error) {
	b, err := os.ReadFile(regSchemaVectors)
	if err != nil {
		return sdkRegSchemaRule{}, err
	}
	var doc sdkRegSchemaRule
	if err := json.Unmarshal(b, &doc); err != nil {
		return sdkRegSchemaRule{}, err
	}
	if doc.Dialect == "" || doc.MaxBytes == 0 || doc.MaxDepth == 0 ||
		doc.MaxEvaluations == 0 || doc.MaxRepeat == 0 || doc.PortableEsc == "" ||
		doc.MaxErrors == 0 || doc.MaxPathLen == 0 || doc.MaxErrTextLn == 0 {
		return sdkRegSchemaRule{}, errNoSDKRegSchemaRule
	}
	return doc, nil
})

func mustSDKRegRule(t *testing.T) sdkRegSchemaRule {
	t.Helper()
	r, err := sdkRegRule()
	if err != nil {
		t.Fatalf("read the SDK's registration-schema rules: %v", err)
	}
	return r
}

// findContractField resolves a message and one of its fields by bare name, failing
// fatally when either is gone: a renamed message would otherwise make every
// assertion below vacuous and the failure would look like a pass.
func findContractField(t *testing.T, message, field string) protoreflect.FieldDescriptor {
	t.Helper()
	var fd protoreflect.FieldDescriptor
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if string(md.Name()) != message {
			return
		}
		if f := md.Fields().ByName(protoreflect.Name(field)); f != nil {
			fd = f
		}
	})
	if fd == nil {
		t.Fatalf("the contract carries no %s.%s — this guard would assert nothing", message, field)
	}
	return fd
}

// TestSDKRegistrationFailureBoundsMatchTheWire is the descriptor half. The SDK
// clamps its output to these three numbers so that what the validator builds is
// always a message the contract accepts; if the wire's bounds move and the SDK's
// do not, it starts building refusals that are rejected at ingest — a failure that
// surfaces only on the unhappy path, which is the worst place to find it.
func TestSDKRegistrationFailureBoundsMatchTheWire(t *testing.T) {
	want := mustSDKRegRule(t)

	fieldErrors := findContractField(t, "RegistrationFailure", "field_errors")
	rules, has := fieldRules(fieldErrors)
	if !has {
		t.Fatal("RegistrationFailure.field_errors carries no protovalidate rules — its item cap is gone")
	}
	if got := rules.GetRepeated().GetMaxItems(); got != want.MaxErrors {
		t.Errorf("RegistrationFailure.field_errors: the wire and the SDK disagree about the failure-list cap.\n"+
			"  wire (authoritative): repeated.max_items = %d\n"+
			"  SDK  (%s): %d\n"+
			"Bring the SDK to the contract and regenerate its vectors.",
			got, regSchemaVectors, want.MaxErrors)
	}

	for _, c := range []struct {
		field string
		want  uint64
	}{
		{"path", want.MaxPathLen},
		{"error", want.MaxErrTextLn},
	} {
		fd := findContractField(t, "RegistrationFieldError", c.field)
		r, ok := fieldRules(fd)
		if !ok {
			t.Errorf("RegistrationFieldError.%s carries no protovalidate rules — its length bound is gone", c.field)
			continue
		}
		if got := r.GetString().GetMaxLen(); got != c.want {
			t.Errorf("RegistrationFieldError.%s: the wire and the SDK disagree about the length bound.\n"+
				"  wire (authoritative): max_len = %d\n"+
				"  SDK  (%s): %d",
				c.field, got, regSchemaVectors, c.want)
		}
	}
}

// escapeListRe pulls the escape sentence out of the comment. The list is spelled out
// character by character in the contract precisely so this can read it back.
var escapeListRe = regexp.MustCompile(`only the escapes ((?:\\.(?:, )?| and )+) MAY appear`)

// assertEscapeSetsMatch compares the alphabet the contract states with the one the SDK
// enforces, in both directions.
//
// Both directions matter, and the one-directional version was self-satisfying: it read
// the SDK's set out of the corpus, and the corpus regenerates from the SDK, so dropping
// an escape from all three SDKs dropped it from the corpus too and the guard was
// comparing the mutation against itself. Only the contract is an independent witness.
func assertEscapeSetsMatch(t *testing.T, comment, sdkEscapes string) {
	t.Helper()
	m := escapeListRe.FindStringSubmatch(comment)
	if m == nil {
		t.Fatalf("AccountRegistration.data_schema no longer carries a readable "+
			"\"only the escapes ... MAY appear\" list — this half of the guard has lost its anchor.\n"+
			"  the SDK admits: %q", sdkEscapes)
	}
	contract := map[rune]bool{}
	for _, tok := range regexp.MustCompile(`\\(.)`).FindAllStringSubmatch(m[1], -1) {
		contract[rune(tok[1][0])] = true
	}
	sdk := map[rune]bool{}
	for _, r := range sdkEscapes {
		sdk[r] = true
	}
	for r := range contract {
		if !sdk[r] {
			t.Errorf("the contract admits the escape %s and the SDK does not.\n"+
				"  contract (authoritative): AccountRegistration.data_schema\n"+
				"  SDK (%s): %q\n"+
				"An author following the contract would write a pattern this SDK refuses.",
				strconv.QuoteRune(r), regSchemaVectors, sdkEscapes)
		}
	}
	for r := range sdk {
		if !contract[r] {
			t.Errorf("the SDK admits the escape %s and the contract does not name it.\n"+
				"  An implementor reading only the contract would refuse a pattern this SDK admits.",
				strconv.QuoteRune(r))
		}
	}
}

// byteCapPhrase renders the size cap the way the contract states it, EXACTLY. The
// KB form is used only when the number really is a whole number of kibibytes; any
// other value has to appear verbatim, so a cap that moved off the round number
// cannot hide behind an integer division that still reads "16KB".
func byteCapPhrase(n int) string {
	if n%1024 == 0 {
		return strconv.Itoa(n/1024) + "KB"
	}
	return strconv.Itoa(n)
}

// dataSchemaComment returns the leading // block above the data_schema field, read
// from the proto SOURCE. The descriptor does not retain source comments, and the
// comment is where these rules live — data_schema is a Struct, so no field-level
// protovalidate rule can reach inside it.
func fieldComment(t *testing.T, decl string) string {
	t.Helper()
	for _, cf := range Contract {
		path := filepath.Join("..", "proto", cf.File.Path())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		lines := strings.Split(string(b), "\n")
		for i, ln := range lines {
			if !strings.HasPrefix(strings.TrimSpace(ln), decl) {
				continue
			}
			var block []string
			for j := i - 1; j >= 0; j-- {
				trimmed := strings.TrimSpace(lines[j])
				if !strings.HasPrefix(trimmed, "//") {
					break
				}
				block = append([]string{strings.TrimSpace(strings.TrimPrefix(trimmed, "//"))}, block...)
			}
			if len(block) == 0 {
				t.Fatalf("%s: %s carries no leading comment — the rules it is supposed to state are gone", path, decl)
			}
			// Joined with a space so a rule split across two comment lines is still
			// one string to search; the source wraps at 80 columns and every phrase
			// below is longer than the wrap is generous.
			return strings.Join(block, " ")
		}
	}
	t.Fatalf("no contract file declares %q — this guard would assert nothing", decl)
	return ""
}

// dataSchemaComment and registrationDataComment name the two fields whose rules live
// only in prose. Same extraction, different declaration — factored rather than copied
// so a change to how a comment is read cannot apply to one field and not the other.
func dataSchemaComment(t *testing.T) string {
	t.Helper()
	return fieldComment(t, "google.protobuf.Struct data_schema = 1")
}

func registrationDataComment(t *testing.T) string {
	t.Helper()
	return fieldComment(t, "google.protobuf.Struct registration_data = 2")
}

// TestDataSchemaCommentStatesTheRulesTheSDKEnforces is the source half.
//
// Each entry is one rule the SDK implements, paired with the phrase the contract
// must contain for a third-party implementor to learn it. The numbers come from the
// SDK's vectors, so a cap changed in one place and not the other goes red rather
// than leaving two copies to drift — which, for a value that exists only as prose,
// is the only mechanism available at all.
func TestDataSchemaCommentStatesTheRulesTheSDKEnforces(t *testing.T) {
	want := mustSDKRegRule(t)
	comment := dataSchemaComment(t)

	// Guard the guard: pin the extraction to the block it is supposed to have read.
	// A reader that over-reached — returning the whole file, or the banner above the
	// enclosing message — would satisfy every phrase below while checking nothing,
	// and the failure would look like a pass.
	const opening = "JSON Schema (draft 2020-12) describing"
	if !strings.HasPrefix(comment, opening) {
		t.Fatalf("the extracted comment does not begin with data_schema's own first line "+
			"(%q) — this guard is reading the wrong block and would assert nothing.\n  read: %.120s…",
			opening, comment)
	}

	// Every phrase is DERIVED from the SDK's own numbers, not restated. The earlier
	// version of this list spelled five of them as literals in this file, and a
	// mutation run proved what that was worth: dropping an escape from all three SDKs
	// left every gate green, and moving the byte cap to 17000 also passed, because the
	// assertion rendered it as MaxBytes/1024 and integer division still said "16KB".
	checks := []struct {
		rule   string
		phrase string
	}{
		{"the size cap", byteCapPhrase(want.MaxBytes)},
		{"the depth cap", strconv.Itoa(want.MaxDepth) + " nested JSON containers"},
		{"the evaluation cap", strconv.Itoa(want.MaxEvaluations) + " evaluations"},
		{"the repeat bound", "MUST NOT exceed " + strconv.Itoa(want.MaxRepeat)},
		{"the pinned dialect", want.Dialect},
		{"same-document references only", `it begins with "#"`},
		{"no reference cycles", "MUST NOT return to a schema already on it"},
		{"the group forms a pattern may use", `A group MUST open with "(" or "(?:"`},
		{"the POSIX bracket form a pattern may not use", `"[:"` + " MUST NOT appear inside a bracket expression"},
		{"no nested quantifiers", "No nested quantifiers"},
		{"format and friends are annotations", "MUST NOT assert format"},
		{"the object-only rule", "MUST be a JSON object"},
		// The two rules the SDK applies that the contract used to leave unsaid. An
		// implementor reading only the contract accepted schemas the SDK refuses, and
		// refused schemas the SDK accepts.
		{"patternProperties keys are patterns", "patternProperties"},
		{"const and friends hold data, not schema", "const"},
		// The encoding, which decides WHICH document every rule above is read against.
		{"UTF-8 with no byte order mark", "byte order mark"},
		// What counts as "no schema published" — the enforcement switch, so a byte
		// sequence read as absent is one that turns validation off.
		{"absent means empty or JSON whitespace", "only JSON whitespace"},
	}
	// The alphabet itself, character by character, so an escape dropped from the SDK
	// is an escape the contract stops naming.
	for _, r := range want.PortableEsc {
		checks = append(checks, struct {
			rule   string
			phrase string
		}{
			rule:   "the admitted escape " + strconv.QuoteRune(r),
			phrase: `\` + string(r),
		})
	}
	// ... and the same comparison in the OTHER direction, which is the one that
	// matters. Checking only that the contract names everything the SDK forbids is
	// self-satisfying: regenerating the corpus after dropping an escape updates the
	// SDK's side of the comparison too, so the set shrinks on both sides and the guard
	// stays green while the contract still promises a rule nothing enforces. The
	// contract is authoritative, so its set is the one that decides.
	assertEscapeSetsMatch(t, comment, want.PortableEsc)

	for _, c := range checks {
		if !strings.Contains(comment, c.phrase) {
			t.Errorf("AccountRegistration.data_schema does not state %s.\n"+
				"  the SDK enforces it (%s), so an implementor reading only the contract\n"+
				"  would write a validator that accepts schemas the SDK refuses.\n"+
				"  expected the comment to contain: %s",
				c.rule, regSchemaVectors, strconv.Quote(c.phrase))
		}
	}
}

// TestRegistrationSchemaVectorsAreNotVacuous guards the guard from the other side.
// The two tests above read numbers out of the corpus; if the corpus lost its cases
// they would still pass while the corpus asserted nothing, so the case counts are
// pinned to be non-zero here — the conformance tier's own copy of the non-empty
// check the SDK parity suites run.
func TestRegistrationSchemaVectorsAreNotVacuous(t *testing.T) {
	b, err := os.ReadFile(regSchemaVectors)
	if err != nil {
		t.Fatalf("read %s: %v", regSchemaVectors, err)
	}
	var doc struct {
		Compile  []json.RawMessage `json:"compile"`
		Validate []json.RawMessage `json:"validate"`
		Pattern  []json.RawMessage `json:"pattern"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode %s: %v", regSchemaVectors, err)
	}
	for _, c := range []struct {
		dimension string
		n         int
	}{
		{"compile", len(doc.Compile)},
		{"validate", len(doc.Validate)},
		{"pattern", len(doc.Pattern)},
	} {
		if c.n == 0 {
			t.Errorf("%s carries no %s cases — that dimension asserts nothing in any language",
				regSchemaVectors, c.dimension)
		}
	}
}

// TestRegistrationDataCommentStatesItsBounds is the sibling of the data_schema guard,
// for the field the schema is APPLIED to.
//
// It matters for the same reason and one more: the byte cap here is over a canonical
// ENCODING rather than over bytes anyone served, because registration_data arrives as a
// decoded Struct. A number without its unit is the ambiguity that produces two
// implementations measuring different things, so the unit is a phrase this checks too.
func TestRegistrationDataCommentStatesItsBounds(t *testing.T) {
	want := mustSDKRegRule(t)
	comment := registrationDataComment(t)

	const opening = "Business-registration data about the operator"
	if !strings.HasPrefix(comment, opening) {
		t.Fatalf("the extracted comment does not begin with registration_data's own first line "+
			"(%q) — this guard is reading the wrong block and would assert nothing.\n  read: %.120s…",
			opening, comment)
	}

	checks := []struct {
		rule   string
		phrase string
	}{
		{"the payload byte cap", strconv.Itoa(want.MaxDataBytes) + " bytes"},
		{"the payload member cap", "At most " + strconv.Itoa(want.MaxDataMembers) + " members"},
		// The unit, without which the number above states nothing checkable.
		{"the encoding the byte cap is measured over", "RFC 8785"},
		{"the top-level qualifier on the member cap", "top level"},
		// The ordering, which is what makes the bound a bound rather than a report.
		{"checked before the schema runs", "BEFORE the schema runs"},
	}
	for _, c := range checks {
		if !strings.Contains(comment, c.phrase) {
			t.Errorf("RegisterRequest.registration_data no longer states %s.\n"+
				"  the SDK enforces it (%s), so an implementor reading only the contract "+
				"would send a payload the SDK refuses.\n  expected the comment to contain %s",
				c.rule, regSchemaVectors, strconv.Quote(c.phrase))
		}
	}
}
