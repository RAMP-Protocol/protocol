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
	Dialect      string `json:"dialect"`
	MaxBytes     int    `json:"max_schema_bytes"`
	MaxDepth     int    `json:"max_schema_depth"`
	MaxErrors    uint64 `json:"max_field_errors"`
	MaxPathLen   uint64 `json:"max_field_error_path_len"`
	MaxErrTextLn uint64 `json:"max_field_error_text_len"`
}

var errNoSDKRegSchemaRule = errors.New(
	regSchemaVectors + " is missing one of dialect / max_schema_bytes / max_schema_depth / " +
		"max_field_errors / max_field_error_path_len / max_field_error_text_len — this guard reads " +
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

// dataSchemaComment returns the leading // block above the data_schema field, read
// from the proto SOURCE. The descriptor does not retain source comments, and the
// comment is where these rules live — data_schema is a Struct, so no field-level
// protovalidate rule can reach inside it.
func dataSchemaComment(t *testing.T) string {
	t.Helper()
	for _, cf := range Contract {
		path := filepath.Join("..", "proto", cf.File.Path())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		lines := strings.Split(string(b), "\n")
		for i, ln := range lines {
			if !strings.HasPrefix(strings.TrimSpace(ln), "google.protobuf.Struct data_schema = 1") {
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
				t.Fatalf("%s: data_schema carries no leading comment — the rules it is supposed to state are gone", path)
			}
			// Joined with a space so a rule split across two comment lines is still
			// one string to search; the source wraps at 80 columns and every phrase
			// below is longer than the wrap is generous.
			return strings.Join(block, " ")
		}
	}
	t.Fatal("no contract file declares data_schema — this guard would assert nothing")
	return ""
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

	for _, c := range []struct {
		rule   string
		phrase string
	}{
		{"the size cap", strconv.Itoa(want.MaxBytes/1024) + "KB"},
		{"the depth cap", strconv.Itoa(want.MaxDepth) + " nested JSON containers"},
		{"the pinned dialect", want.Dialect},
		{"same-document references only", `it begins with "#"`},
		{"the group forms a pattern may use", `A group MUST open with "(" or "(?:"`},
		{"the escapes a pattern may not use", `\1-\9, \k, \p, \P, \A, \z, \Z, \Q, \E, \C, \G and \K`},
		{"the POSIX bracket form a pattern may not use", `"[[:" MUST NOT appear`},
		{"format and friends are annotations", "MUST NOT be asserted"},
	} {
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
