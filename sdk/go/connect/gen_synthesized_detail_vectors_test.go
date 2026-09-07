package connect_test

// Synthesized-detail golden-vector emitter: the typed details this SDK BUILDS rather
// than receives.
//
// Most ErrorDetails a client hands back were written by a peer, so what the three SDKs
// have to agree on is only how they DECODE one — which error-detail-vectors.json already
// pins. Two are different. A delivery edge answers a small JSON object rather than a
// protobuf, so the content leg promotes its refusal token into a typed reason and writes
// the envelope around it. A registration the client refuses against the Exchange's
// published schema never reaches a peer at all, so every field of that detail is ours.
//
// In both, the domain, the sentence and the reason are AUTHORED, in three languages,
// from three copies of the same decision. Nothing compared them. That is the shape a
// shared corpus exists for, and the reason the edge rows are here beside the newer ones
// even though they predate them: the domain had been a bare literal in three files, and
// the token table beneath it had silently come apart. Two of the ports had DERIVED each
// enum name from the token by uppercasing it, which is right for two of the eleven
// tokens the protocol records and wrong for the rest — so nine real edge refusals
// carried a typed reason in Go and none in either port, and every suite was green.
// Every recorded token is a row now, including the two that must stay UNTYPED.
//
// What is NOT pinned is the field errors' prose. Their PATHS are recorded, because those
// are a projection of the payload the three agree on; the constraint text beside each
// comes from a different validator library in each language and the contract calls it
// non-authoritative for exactly that reason.
//
// Vectors are captured by driving the REAL client until it refuses, so this records what
// the oracle does rather than a description of it.
//
// Verification no-op by default; (re)writes under RAMP_UPDATE_VECTORS=1. TEST
// INFRASTRUCTURE.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/vectorio"
)

const synthesizedDetailVectorsPath = "testdata/synthesized-detail-vectors.json"

// precheckVector is one registration the client refused before sending anything, and the
// typed detail that refusal carries.
type precheckVector struct {
	Name string `json:"name"`
	//: The data_schema the Exchange published, verbatim, as the reader would serve it.
	Schema string `json:"schema"`
	//: The registration_data the caller offered against that schema.
	Data map[string]any `json:"data"`
	//: The failing surface. A refusal computed here names the CLIENT's own tier: the
	//: Exchange never saw the request, so naming it would attribute a local verdict to a
	//: party that reached none.
	Domain string `json:"domain"`
	//: The detail's developer message. Authored by the SDK, so the three must write it
	//: identically or a consumer reads two problems where there is one.
	Message string `json:"message"`
	//: Which typed reason block is populated, as its proto-JSON key.
	ReasonField string `json:"reason_field"`
	//: The reason enum's name.
	ReasonEnum string `json:"reason_enum"`
	//: The offending members, as RFC 6901 pointers relative to registration_data — the
	//: empty pointer addressing the whole object. PATHS ONLY: the constraint prose beside
	//: each comes from each language's validator library and is documented
	//: non-authoritative, so pinning it here would pin an accident.
	FieldErrorPaths []string `json:"field_error_paths"`
}

// edgeRefusalVector is one delivery-edge refusal, promoted from the edge's own token into
// a typed reason the SDK wrote the envelope around.
type edgeRefusalVector struct {
	Name string `json:"name"`
	//: The token the edge answered in its own vocabulary.
	ReasonToken string `json:"reason_token"`
	//: The failing surface: the delivery edge, not the fetched resource. A per-URL value
	//: has unbounded cardinality and groups nothing. EMPTY when the protocol records no
	//: typed reason for this token — there is then no detail at all, and the caller falls
	//: back to the failure class and the raw token, which is the honest answer.
	Domain string `json:"domain"`
	//: The detail's developer message. The token is the edge's; this sentence is ours.
	Message string `json:"message"`
	//: Which typed reason block is populated, as its proto-JSON key.
	ReasonField string `json:"reason_field"`
	//: The reason enum's name.
	ReasonEnum string `json:"reason_enum"`
}

func TestGenerateSynthesizedDetailVectors(t *testing.T) {
	doc := map[string]any{
		"note": "Typed error details this SDK builds itself rather than receiving, " +
			"captured from the real Go client. Each row records what the three " +
			"languages must author identically: the failing surface, the sentence and " +
			"the typed reason. Field errors are recorded as PATHS and never as text — " +
			"the text comes from a different validator library in each language and the " +
			"contract calls it non-authoritative.",
		"registration_precheck": buildPrecheckVectors(t),
		"edge_refusal":          buildEdgeRefusalVectors(t),
	}
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(synthesizedDetailVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", synthesizedDetailVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(synthesizedDetailVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", synthesizedDetailVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate",
			synthesizedDetailVectorsPath)
	}
}

func buildPrecheckVectors(t *testing.T) []precheckVector {
	t.Helper()
	cases := []struct {
		name   string
		schema string
		data   map[string]any
	}{
		// Both member shapes in one refusal: a required member that is ABSENT, which is a
		// whole-object failure reported against the empty pointer, and a member that is
		// PRESENT and breaks its pattern, reported against its own. The empty pointer is
		// the one a consumer most plausibly renders wrong, so no row may omit it.
		{"both_member_shapes", bothShapesSchema, map[string]any{"vat_id": "de1"}},
		// The single whole-object failure on its own, because it is the shape a first
		// registration against a real Exchange actually hits.
		{"whole_object_only", legalEntitySchema, map[string]any{"trading_name": "Acme"}},
	}

	out := make([]precheckVector, 0, len(cases))
	for _, c := range cases {
		cerr, _ := refusedByTheSchema(t, c.schema, c.data)
		detail, ok := rampconnect.ErrorDetailFrom(cerr)
		if !ok {
			t.Fatalf("%s: the pre-check refusal carries no typed detail", c.name)
		}
		field, enum := reasonProjectionOf(t, detail)
		paths := make([]string, 0, len(detail.GetRegistrationFailure().GetFieldErrors()))
		for _, f := range detail.GetRegistrationFailure().GetFieldErrors() {
			paths = append(paths, f.GetPath())
		}
		out = append(out, precheckVector{
			Name:            c.name,
			Schema:          c.schema,
			Data:            c.data,
			Domain:          detail.GetDomain(),
			Message:         detail.GetMessage(),
			ReasonField:     field,
			ReasonEnum:      enum,
			FieldErrorPaths: paths,
		})
	}
	return out
}

func buildEdgeRefusalVectors(t *testing.T) []edgeRefusalVector {
	t.Helper()
	// EVERY token the protocol records, not a sample. This is a per-token lookup against
	// a table, so a sample proves only that the table exists — and one language having
	// computed the enum name from the token instead of reading the record, and thereby
	// typing two of these and dropping the rest, is exactly what a sample would have
	// missed. The order is the proto's own.
	tokens := []string{
		// Signed-URL checks.
		"expired", "missing_exp", "signature_mismatch",
		// Proof-of-possession checks.
		"missing_agent_key", "keyid_mismatch", "thumbprint_mismatch",
		"pop_missing_created", "pop_missing_exp", "pop_expired", "pop_sig_invalid",
		// Recorded by the proto against TWO values, so the body cannot say which check
		// ran and no language may guess. It is here as a row rather than left out,
		// because "deliberately untyped" is a decision a corpus should hold, and a
		// language that types it has over-promoted a refusal the wire never attributed.
		"missing_sig",
		// Not a token any edge emits — it is the enum's own suffix, and it lands here
		// only in a language that DERIVES the name from the token instead of reading the
		// protocol's record. Recorded as untyped so that mistake cannot come back green.
		"url_expired",
	}

	out := make([]edgeRefusalVector, 0, len(tokens))
	for _, token := range tokens {
		cerr := refusedByTheEdge(t, token)
		vector := edgeRefusalVector{Name: "edge_" + token, ReasonToken: token}
		if detail, ok := rampconnect.ErrorDetailFrom(cerr); ok {
			vector.Domain = detail.GetDomain()
			vector.Message = detail.GetMessage()
			vector.ReasonField, vector.ReasonEnum = reasonProjectionOf(t, detail)
		}
		out = append(out, vector)
	}
	return out
}

// refusedByTheEdge drives one bound fetch against an edge that answers a refusal token,
// and returns the client's typed failure.
func refusedByTheEdge(t *testing.T, token string) *rampconnect.CallError {
	t.Helper()
	sig := newSigningFixture(t)
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"reason":%q}`, token)
	}))
	defer edge.Close()

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t),
			rampconnect.WithSigner(sig.signer),
			rampconnect.WithAgentKey(sig.pub),
		)...)
	_, err := client.Fetch(context.Background(), edge.URL+"/doc?agent_id=tp")

	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("edge refusal is not a typed failure: %v", err)
	}
	return cerr
}

// reasonProjectionOf reads which typed reason block a detail carries and what it says.
//
// The field name comes off the DESCRIPTOR rather than a switch here, so a reason family
// added to the contract cannot be projected under a name this file invented for it.
func reasonProjectionOf(t *testing.T, detail *rampv1.ErrorDetail) (field, enum string) {
	t.Helper()
	reason := helpers.Reason(detail)
	if reason == nil {
		t.Fatal("a synthesized detail carries no typed reason; the vector would pin nothing")
	}
	named, ok := reason.(fmt.Stringer)
	if !ok {
		t.Fatalf("typed reason %T does not name itself", reason)
	}
	m := detail.ProtoReflect()
	od := m.Descriptor().Oneofs().ByName("reason")
	if od == nil {
		t.Fatal("ErrorDetail has no `reason` oneof; this projection has lost its anchor")
	}
	fd := m.WhichOneof(od)
	if fd == nil {
		t.Fatal("the `reason` oneof is unset on a detail that named a reason")
	}
	return string(fd.Name()), named.String()
}
