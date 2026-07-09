package connect_test

// The ADR-019 ErrorDetail↔Connect round-trip, split by direction: AsConnectError
// (emit) lives in the SERVER binding sdk/go/connectserver, ErrorDetailFrom (read)
// lives in the CLIENT binding sdk/go/connect; the neutral *rampv1.ErrorDetail
// builders and the Reason accessor stay in sdk/go/helpers. This suite exercises the
// full loop — a server-emitted typed error detail (AsConnectError) read back and
// branched on by a client (ErrorDetailFrom + helpers.Reason) — assertions unchanged
// across the connect→(connect + connectserver) split.

import (
	"errors"
	"testing"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestErrorDetail_transactionDenialRoundTrip(t *testing.T) {
	detail := helpers.TransactionDenialDetail(
		"ramp.v1.ExchangeService", "balance too low",
		rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)

	cerr := rampserver.AsConnectError(connectrpc.CodeFailedPrecondition, detail)
	if connectrpc.CodeOf(cerr) != connectrpc.CodeFailedPrecondition {
		t.Errorf("code = %v", connectrpc.CodeOf(cerr))
	}

	got, ok := rampconnect.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatal("ErrorDetailFrom returned false")
	}
	if got.GetMessage() != "balance too low" || got.GetDomain() != "ramp.v1.ExchangeService" {
		t.Errorf("envelope = %q %q", got.GetMessage(), got.GetDomain())
	}
	reason, ok := helpers.Reason(got).(rampv1.DenialReason)
	if !ok || reason != rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Errorf("reason = %v (%T)", helpers.Reason(got), helpers.Reason(got))
	}
}

func TestErrorDetail_retrievalAuthFailureRoundTrip(t *testing.T) {
	detail := helpers.RetrievalAuthFailureDetail("ramp.v1.Edge", "pop mismatch",
		rampv1.RetrievalAuthFailureReason(1)) // first defined, non-zero
	cerr := rampserver.AsConnectError(connectrpc.CodePermissionDenied, detail)
	got, ok := rampconnect.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatal("extract failed")
	}
	if _, ok := helpers.Reason(got).(rampv1.RetrievalAuthFailureReason); !ok {
		t.Errorf("reason type = %T, want RetrievalAuthFailureReason", helpers.Reason(got))
	}
}

func TestErrorDetailFrom_nonConnectError(t *testing.T) {
	if _, ok := rampconnect.ErrorDetailFrom(errors.New("plain")); ok {
		t.Error("plain error should not yield a detail")
	}
}

func TestReason_unset(t *testing.T) {
	if r := helpers.Reason(&rampv1.ErrorDetail{Message: "no reason"}); r != nil {
		t.Errorf("Reason of detail without oneof = %v, want nil", r)
	}
}

func TestErrorDetail_clientBranchesOnTypedReason(t *testing.T) {
	// Demonstrates the intended client usage: branch on the enum, not a string.
	detail := helpers.TransactionDenialDetail("d", "rate limited",
		rampv1.DenialReason_DENIAL_REASON_RATE_LIMITED)
	cerr := rampserver.AsConnectError(connectrpc.CodeResourceExhausted, detail)

	ed, _ := rampconnect.ErrorDetailFrom(cerr)
	var handled bool
	switch r := helpers.Reason(ed).(type) {
	case rampv1.DenialReason:
		if r == rampv1.DenialReason_DENIAL_REASON_RATE_LIMITED {
			handled = true
		}
	}
	if !handled {
		t.Error("expected to branch on DenialReason_RATE_LIMITED")
	}
}
