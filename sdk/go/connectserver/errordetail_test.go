package connectserver_test

// AttachErrorDetail is the SDK-owned realisation of the ADR-019 ErrorDetail<->domain
// envelope build (RAMP-118): a service maps a domain error to a classified
// connect.Error, then stamps the generic (Domain + Message + optional Metadata)
// detail with this ONE body instead of copying it per service. These tests pin the
// emitted shape by reading it back through the client binding's ErrorDetailFrom —
// the same path a downstream client uses — never by reaching into connect internals.

import (
	"errors"
	"testing"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

const testServiceDomain = "ramp.v1.ExchangeService"

func TestAttachErrorDetail_StampsEnvelopeOnClassifiedError(t *testing.T) {
	t.Parallel()
	// A pre-classified transport error — the code is the caller's policy choice,
	// unchanged by the detail stamp.
	cerr := connectrpc.NewError(connectrpc.CodeInvalidArgument, errors.New("bad idempotency_key"))
	meta := map[string]string{"field": "idempotency_key"}

	out := rampserver.AttachErrorDetail(cerr, testServiceDomain, "bad idempotency_key", meta)

	// Code survives the stamp.
	if got := connectrpc.CodeOf(out); got != connectrpc.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
	// Read the detail back exactly as a client would.
	ed, ok := rampconnect.ErrorDetailFrom(out)
	if !ok {
		t.Fatal("ErrorDetailFrom returned false; no ErrorDetail attached")
	}
	if got := ed.GetDomain(); got != testServiceDomain {
		t.Fatalf("Domain = %q, want %q", got, testServiceDomain)
	}
	if got := ed.GetMessage(); got != "bad idempotency_key" {
		t.Fatalf("Message = %q, want %q", got, "bad idempotency_key")
	}
	if got := ed.GetMetadata()["field"]; got != "idempotency_key" {
		t.Fatalf("Metadata[field] = %q, want %q", got, "idempotency_key")
	}
	// A generic fault carries no typed reason oneof.
	if r := helpers.Reason(ed); r != nil {
		t.Fatalf("Reason = %v, want nil for a generic fault", r)
	}
}

func TestAttachErrorDetail_EmptyMetadataIsAbsent(t *testing.T) {
	t.Parallel()
	cerr := connectrpc.NewError(connectrpc.CodeInternal, errors.New("boom"))

	out := rampserver.AttachErrorDetail(cerr, testServiceDomain, "boom", nil)

	ed, ok := rampconnect.ErrorDetailFrom(out)
	if !ok {
		t.Fatal("ErrorDetailFrom returned false")
	}
	if len(ed.GetMetadata()) != 0 {
		t.Fatalf("Metadata = %v, want empty/absent", ed.GetMetadata())
	}
}

func TestNewErrorDetail_BuildHalfMatchesAttachAndStaysMutable(t *testing.T) {
	t.Parallel()
	// The exposed build half stamps metadata only when non-empty…
	if d := rampserver.NewErrorDetail(testServiceDomain, "boom", nil); len(d.GetMetadata()) != 0 {
		t.Fatalf("Metadata = %v, want absent for nil input", d.GetMetadata())
	}
	meta := map[string]string{"field": "quantity"}
	d := rampserver.NewErrorDetail(testServiceDomain, "bad quantity", meta)
	if got := d.GetMetadata()["field"]; got != "quantity" {
		t.Fatalf("Metadata[field] = %q, want %q", got, "quantity")
	}
	// …and returns a MUTABLE detail: a caller that owns a typed reason sets the
	// oneof on the returned value before attaching. That mutability is the whole
	// point of exposing the build half separately from AttachErrorDetail.
	d.Reason = &rampv1.ErrorDetail_TransactionDenial{
		TransactionDenial: &rampv1.TransactionDenial{Reason: rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED},
	}
	cerr := connectrpc.NewError(connectrpc.CodeFailedPrecondition, errors.New("bad quantity"))
	ed, ok := rampconnect.ErrorDetailFrom(rampserver.AttachDetail(cerr, d))
	if !ok {
		t.Fatal("ErrorDetailFrom returned false")
	}
	if reason, _ := helpers.Reason(ed).(rampv1.DenialReason); reason != rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED {
		t.Fatalf("Reason = %v, want OFFER_EXPIRED (typed reason set post-build must survive the attach)", reason)
	}
}

func TestAttachDetail_RoundTripsTypedReason(t *testing.T) {
	t.Parallel()
	// A caller that needs a typed reason builds the detail via the helpers.*Detail
	// builders and attaches it with AttachDetail — the shape AttachErrorDetail
	// delegates to for the generic case.
	d := helpers.TransactionDenialDetail(testServiceDomain, "insufficient balance",
		rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
	cerr := connectrpc.NewError(connectrpc.CodeFailedPrecondition, errors.New("insufficient balance"))

	out := rampserver.AttachDetail(cerr, d)

	ed, ok := rampconnect.ErrorDetailFrom(out)
	if !ok {
		t.Fatal("ErrorDetailFrom returned false")
	}
	reason, ok := helpers.Reason(ed).(rampv1.DenialReason)
	if !ok {
		t.Fatalf("Reason type = %T, want rampv1.DenialReason", helpers.Reason(ed))
	}
	if reason != rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Fatalf("DenialReason = %v, want INSUFFICIENT_BALANCE", reason)
	}
}
