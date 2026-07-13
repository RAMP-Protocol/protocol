package helpers

// ErrorDetail cross-language golden-vector emitter (ADR-019 error contract).
//
// The ADR-019 failure envelope — ErrorDetail{Domain, Message, Metadata, typed
// reason oneof} — was, until this corpus, built AND read ONLY in sdk/go. The
// Python (mcp shim) and TS (edge) SDKs are the READ side of that contract: they
// consume Connect error envelopes that carry an ErrorDetail. With no shared
// corpus the wire mapping was unverified across languages — exactly the drift the
// shared-vector discipline exists to prevent.
//
// This emitter DERIVES every vector from the REAL Go faces (self-contained
// oracle), mirroring gen_util_vectors_test.go: the ErrorDetail is built via the
// helpers.*Detail builders (or a bare struct for the no-reason cases the wire also
// carries), its typed reason is read back through the REAL helpers.Reason
// accessor, and its wire form is the PINNED canonical proto-JSON (snake_case field
// names, enums as NAME strings, unpopulated omitted) — the same option set the
// signing payload uses (canonicalsign.go) and the exact form the generated
// Pydantic/Zod ErrorDetail models parse. Deterministic protobuf BINARY is
// explicitly NOT a cross-language primitive (protobuf's own caveat), so the shared
// wire is proto-JSON, which any language reproduces without a binary codec.
//
// Each vector records a stable field projection (domain, message, metadata,
// reason_field, reason_enum) DERIVED from the real detail, plus wire_json (the
// canonical proto-JSON object). The Python + TS replays parse wire_json into their
// generated ErrorDetail model and assert the extracted projection matches — so a
// cross-language divergence in the ErrorDetail encoding fails at the replay
// boundary. The Go replay (errordetail_corpus_test.go) does the same via
// protojson + helpers.Reason.
//
// Like TestGenerateVectors this test is a verification no-op by default (it asserts
// the committed file matches a fresh emit) and (re)writes it under
// RAMP_UPDATE_VECTORS=1 — the emitter is both generator and drift gate. It is TEST
// INFRASTRUCTURE, not the code under test.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// errorDetailVector is one ErrorDetail case: the field projection a reader MUST
// extract (domain, message, metadata, and the typed reason as its oneof json key
// + enum NAME), plus wire_json — the canonical proto-JSON object all three SDKs
// parse. metadata is null when the detail carries none; reason_field/reason_enum
// are "" when no typed reason is set.
type errorDetailVector struct {
	Name        string            `json:"name"`
	Domain      string            `json:"domain"`
	Message     string            `json:"message"`
	Metadata    map[string]string `json:"metadata"`
	ReasonField string            `json:"reason_field"`
	ReasonEnum  string            `json:"reason_enum"`
	WireJSON    any               `json:"wire_json"`
}

// errorDetailJSONOptions is the PINNED proto-JSON option set the ErrorDetail wire
// form uses — identical to canonicalSignJSONOptions: snake_case field names
// (UseProtoNames), enums as NAME strings (UseEnumNumbers=false), unpopulated
// omitted (EmitUnpopulated=false). This is the exact shape the generated
// Pydantic/Zod ErrorDetail models parse.
var errorDetailJSONOptions = protojson.MarshalOptions{
	UseProtoNames:   true,
	UseEnumNumbers:  false,
	EmitUnpopulated: false,
}

// reasonProjection reads the active typed reason from d via the REAL
// helpers.Reason accessor and returns its proto-JSON oneof key and enum NAME
// string. Returns ("", "") when no reason is set. The oneof key is derived from
// which reason block is populated — the same switch helpers.Reason walks — so the
// projection cannot drift from the accessor.
func reasonProjection(d *rampv1.ErrorDetail) (field, enum string) {
	r := Reason(d)
	if r == nil {
		return "", ""
	}
	s, ok := r.(fmt.Stringer)
	if !ok {
		panic(fmt.Sprintf("reasonProjection: reason %T is not a Stringer", r))
	}
	switch {
	case d.GetTransactionDenial() != nil:
		field = "transaction_denial"
	case d.GetRetrievalAuthFailure() != nil:
		field = "retrieval_auth_failure"
	case d.GetCatalogRejection() != nil:
		field = "catalog_rejection"
	case d.GetRegistrationFailure() != nil:
		field = "registration_failure"
	case d.GetDisputeFailure() != nil:
		field = "dispute_failure"
	case d.GetDomainVerificationFailure() != nil:
		field = "domain_verification_failure"
	case d.GetUsageReportRejection() != nil:
		field = "usage_report_rejection"
	default:
		panic("reasonProjection: reason set but no known oneof block populated")
	}
	return field, s.String()
}

// wireOf renders d to the canonical proto-JSON object (the shared wire form). It
// decodes the protojson output into a generic value so the committed corpus is
// deterministic — encoding/json sorts object keys on re-marshal, and protojson's
// own output carries intentionally-unstable whitespace that must not leak into the
// golden file.
func wireOf(t *testing.T, d *rampv1.ErrorDetail) any {
	t.Helper()
	pj, err := errorDetailJSONOptions.Marshal(d)
	if err != nil {
		t.Fatalf("protojson marshal ErrorDetail: %v", err)
	}
	var v any
	if err := json.Unmarshal(pj, &v); err != nil {
		t.Fatalf("decode proto-JSON ErrorDetail: %v", err)
	}
	return v
}

// vectorFrom builds one vector from a REAL *rampv1.ErrorDetail: the projection is
// read back through the real getters + helpers.Reason, and wire_json is the
// canonical proto-JSON. Nothing is hand-authored.
func vectorFrom(t *testing.T, name string, d *rampv1.ErrorDetail) errorDetailVector {
	t.Helper()
	field, enum := reasonProjection(d)
	return errorDetailVector{
		Name:        name,
		Domain:      d.GetDomain(),
		Message:     d.GetMessage(),
		Metadata:    d.GetMetadata(), // nil when the detail carries none
		ReasonField: field,
		ReasonEnum:  enum,
		WireJSON:    wireOf(t, d),
	}
}

// buildErrorDetailVectors emits the ErrorDetail corpus, covering: domain+message
// only; a single metadata pair; an explicitly-empty metadata map (proto3 omits it
// on the wire); two distinct typed-reason families (TransactionDenial and
// RetrievalAuthFailure); and multi-key metadata combined with a typed reason (the
// ordering case — a reader must extract the same key/value map regardless of
// encoding order).
func buildErrorDetailVectors(t *testing.T) []errorDetailVector {
	t.Helper()

	domainOnly := &rampv1.ErrorDetail{
		Domain:  "ramp.v1.ExchangeService",
		Message: "internal error",
	}

	withMetadata := &rampv1.ErrorDetail{
		Domain:   "ramp.v1.CatalogService",
		Message:  "quota exceeded",
		Metadata: map[string]string{"limit": "100"},
	}

	// An explicitly-set empty map: proto3 map semantics omit it on the wire, so
	// wire_json carries no "metadata" key and a reader extracts an empty/absent map.
	emptyMetadata := &rampv1.ErrorDetail{
		Domain:   "ramp.v1.ExchangeService",
		Message:  "no metadata here",
		Metadata: map[string]string{},
	}

	denial := TransactionDenialDetail(
		"ramp.v1.ExchangeService", "balance too low",
		rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)

	retrievalAuth := RetrievalAuthFailureDetail(
		"ramp.v1.Edge", "signed URL expired",
		rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED)

	// Multi-key metadata + a typed reason together: the keys are authored
	// out of sorted order to make the ordering case meaningful.
	multiKey := TransactionDenialDetail(
		"ramp.v1.ExchangeService", "rate limited",
		rampv1.DenialReason_DENIAL_REASON_RATE_LIMITED)
	multiKey.Metadata = map[string]string{"zeta": "3", "alpha": "1", "mid": "2"}

	cases := []struct {
		name string
		d    *rampv1.ErrorDetail
	}{
		{"domain_message_only", domainOnly},
		{"with_single_metadata", withMetadata},
		{"empty_metadata_omitted", emptyMetadata},
		{"transaction_denial_reason", denial},
		{"retrieval_auth_failure_reason", retrievalAuth},
		{"multi_key_metadata_with_reason", multiKey},
	}
	out := make([]errorDetailVector, 0, len(cases))
	for _, c := range cases {
		out = append(out, vectorFrom(t, c.name, c.d))
	}
	return out
}

// TestGenerateErrorDetailVectors emits the ErrorDetail golden corpus. Verification
// no-op by default (asserts the committed file is byte-identical to a fresh emit);
// (re)writes it under RAMP_UPDATE_VECTORS=1.
func TestGenerateErrorDetailVectors(t *testing.T) {
	doc := map[string]any{
		"canonicalization": "proto-json-snake",
		"vectors":          buildErrorDetailVectors(t),
	}
	path := filepath.Join("testdata", "error-detail-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
