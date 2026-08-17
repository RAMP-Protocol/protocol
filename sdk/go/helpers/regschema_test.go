package helpers_test

// Behaviour the shared conformance corpus cannot carry.
//
// The vectors pin what a given schema and payload ANSWER. Three properties are not
// about any particular payload and so have no vector: that a refusal never carries
// the submitted value back out, that the refusal is a message the wire will accept,
// and that the pure tier never grew a way to dial. Each is asserted here.

import (
	"strconv"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func mustCompile(t *testing.T, schema string) *helpers.RegistrationSchema {
	t.Helper()
	s, v := helpers.CompileRegistrationSchema([]byte(schema))
	if v != helpers.SchemaAccepted {
		t.Fatalf("schema did not compile: %s", v)
	}
	return s
}

// TestSchemaVerdictZeroValueIsNotAnAcceptance pins the ordering of the enum. A
// caller who ignores the verdict reads the zero value, and the zero value must not
// be the one that means "publish this schema and enforce it".
func TestSchemaVerdictZeroValueIsNotAnAcceptance(t *testing.T) {
	var v helpers.SchemaVerdict
	if v == helpers.SchemaAccepted {
		t.Fatal("the zero SchemaVerdict is SchemaAccepted — an ignored verdict would read as an acceptance")
	}
	if got := v.String(); got != "no_verdict" {
		t.Errorf("zero verdict token = %q, want %q", got, "no_verdict")
	}
}

// TestNoCompiledSchemaPassesThePayloadThrough covers the manifest case the field
// contract calls out: an Exchange that publishes no data_schema accepts
// registration_data uninspected. The nil schema IS that state, so it must answer
// "nothing failed" rather than panic or refuse.
func TestNoCompiledSchemaPassesThePayloadThrough(t *testing.T) {
	var none *helpers.RegistrationSchema
	if got := none.Validate(map[string]any{"anything": "at all"}); got != nil {
		t.Errorf("a nil schema reported %d failures; publishing no schema means enforcing none", len(got))
	}
}

// TestFieldErrorsNeverEchoTheSubmittedValue is the leakage guard.
//
// RegistrationFieldError.error states the violated constraint and never the value,
// because a refusal travels back over the wire while registration_data is an
// operator's business data. The guard has teeth: the underlying library's own
// renderings DO quote the offending value ("\"DE-SECRET\" does not match pattern
// ..."), so a future edit that reached for err.Error() to save a switch statement
// would leak, and would look like a simplification while doing it.
func TestFieldErrorsNeverEchoTheSubmittedValue(t *testing.T) {
	const secret = "ZZTOPSECRETVALUE9999"
	s := mustCompile(t, `{
		"type":"object",
		"required":["legal_name"],
		"properties":{
			"vat_id":{"type":"string","pattern":"^[A-Z]{2}[0-9]+$","minLength":40},
			"count":{"type":"number","minimum":10},
			"kind":{"enum":["a","b"]},
			"fixed":{"const":"only-this"},
			"tags":{"type":"array","uniqueItems":true}
		},
		"additionalProperties":false
	}`)

	// Every value below is a value the schema refuses, so every branch of the
	// describe switch that can fire on this document fires.
	got := s.Validate(map[string]any{
		"vat_id":   secret,
		"count":    1.0,
		"kind":     secret,
		"fixed":    secret,
		"tags":     []any{secret, secret},
		secret:     secret,
		"nonempty": secret,
	})
	if len(got) == 0 {
		t.Fatal("the payload was expected to fail; the guard would assert nothing")
	}
	for _, fe := range got {
		if strings.Contains(fe.GetError(), secret) {
			t.Errorf("error text for %q carries the submitted value: %q", fe.GetPath(), fe.GetError())
		}
		if strings.Contains(fe.GetPath(), secret) {
			t.Errorf("pointer carries the submitted value: %q", fe.GetPath())
		}
	}
}

// TestFieldErrorsAreAMessageTheWireAccepts closes the loop the other way: the
// validator's output is only useful if it can actually be sent. It builds the
// refusal the way a service would — through RegistrationFailureDetail — and runs
// the contract's own protovalidate rules over it, so the per-entry bounds, the
// 64-item cap and the CEL rule scoping field_errors to this one reason are all
// checked by the wire's rules rather than restated here.
func TestFieldErrorsAreAMessageTheWireAccepts(t *testing.T) {
	// More failing members than the wire carries, with names long enough that a
	// pointer bound also has to hold.
	var props, req []string
	data := map[string]any{}
	for i := 0; i < helpers.MaxRegistrationFieldErrors+20; i++ {
		name := strings.Repeat("m", 40) + strconv.Itoa(i)
		props = append(props, strconv.Quote(name)+`:{"type":"string"}`)
		req = append(req, strconv.Quote(name))
		data[name] = float64(i)
	}
	s := mustCompile(t, `{"type":"object","required":[`+strings.Join(req, ",")+
		`],"properties":{`+strings.Join(props, ",")+`}}`)

	fieldErrors := s.Validate(data)
	if len(fieldErrors) != helpers.MaxRegistrationFieldErrors {
		t.Fatalf("got %d field errors, want the cap %d", len(fieldErrors), helpers.MaxRegistrationFieldErrors)
	}
	detail := helpers.RegistrationFailureDetail(
		"ramp.v1.ExchangeService", "registration_data does not conform",
		rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
		fieldErrors...)
	if err := helpers.Validate(detail); err != nil {
		t.Fatalf("the validator built a refusal the wire refuses: %v", err)
	}
}

// TestAnOverlongPointerDegradesToAnAncestor pins what happens when a member sits
// deeper than the wire's 255-byte pointer bound allows. Truncating mid-token would
// name a DIFFERENT member, or none — a wrong answer dressed as a precise one — so
// the pointer falls back to the longest ancestor that fits. Less precise, still true.
func TestAnOverlongPointerDegradesToAnAncestor(t *testing.T) {
	const seg = "abcdefghijklmnopqrstuvwxyz012345678901234567890123" // 50 bytes
	// Six levels of 50-byte names is a 306-byte pointer, comfortably past the bound.
	const depth = 6
	schema := `{"type":"string","minLength":99}`
	data := any("x")
	for i := 0; i < depth; i++ {
		schema = `{"type":"object","properties":{"` + seg + `":` + schema + `}}`
		data = map[string]any{seg: data}
	}
	s := mustCompile(t, schema)

	got := s.Validate(data.(map[string]any))
	if len(got) != 1 {
		t.Fatalf("got %d failures, want 1", len(got))
	}
	p := got[0].GetPath()
	if len(p) > helpers.MaxRegistrationFieldErrorPathLen {
		t.Fatalf("pointer is %d bytes, over the wire bound of %d: %q",
			len(p), helpers.MaxRegistrationFieldErrorPathLen, p)
	}
	// An ancestor, not a cut: every token is whole, so the value is still a pointer
	// that addresses something real.
	for _, tok := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if tok != seg {
			t.Fatalf("pointer %q holds a partial token %q — it was truncated, not degraded", p, tok)
		}
	}
	if !strings.HasPrefix("/"+seg+"/"+seg+"/"+seg+"/"+seg+"/"+seg+"/"+seg, p) {
		t.Errorf("pointer %q is not an ancestor of the failing member", p)
	}
}

// TestTheCompilerIsBuiltWithoutALoader is a source-level guard, in the shape of the
// package's other structural guards, for the two properties this face cannot
// demonstrate by behaviour alone.
//
// The first is the SSRF one. The scan refuses a reference that leaves the document,
// and the compiler is built with no URLLoader so a reference the scan did not
// recognise fails closed instead of dialing. Installing a loader would remove that
// backstop silently — every existing test would still pass — and the io-leaf guard
// would not see it, because the dial would happen inside the library rather than in
// a helpers file naming http.Client.
//
// The second is the leakage one from the test above, asserted at the source so the
// intent survives a refactor: the library's own renderings quote the submitted
// value, so this file must never call them.
func TestTheCompilerIsBuiltWithoutALoader(t *testing.T) {
	src := readHelperSource(t, "regschema.go")
	for _, forbidden := range []string{
		"UseLoader",             // would let the compiler resolve a reference by fetching it
		"jsonschema.FileLoader", // the same, from disk
		"SchemeURLLoader",
		"LocalizedString", // the library's rendering — quotes the offending value
		"LocalizedError",
		"LocalizedGoString",
		"BasicOutput", // carries the library's messages too
		"DetailedOutput",
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("regschema.go names %q — the compiler must resolve nothing off this "+
				"process and must never render the library's own messages, which quote the "+
				"submitted value", forbidden)
		}
	}
	// Guard the guard: if the file stopped using the library entirely the checks
	// above would pass vacuously.
	if !strings.Contains(src, "jsonschema.NewCompiler()") {
		t.Fatal("regschema.go no longer builds a compiler — this guard would assert nothing")
	}
}
