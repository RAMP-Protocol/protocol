package ramphelpers_test

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

func TestErrorDetail_transactionDenialRoundTrip(t *testing.T) {
	detail := ramphelpers.TransactionDenialDetail(
		"ramp.v1.ExchangeService", "balance too low",
		rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)

	cerr := ramphelpers.AsConnectError(connect.CodeFailedPrecondition, detail)
	if connect.CodeOf(cerr) != connect.CodeFailedPrecondition {
		t.Errorf("code = %v", connect.CodeOf(cerr))
	}

	got, ok := ramphelpers.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatal("ErrorDetailFrom returned false")
	}
	if got.GetMessage() != "balance too low" || got.GetDomain() != "ramp.v1.ExchangeService" {
		t.Errorf("envelope = %q %q", got.GetMessage(), got.GetDomain())
	}
	reason, ok := ramphelpers.Reason(got).(rampv1.DenialReason)
	if !ok || reason != rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Errorf("reason = %v (%T)", ramphelpers.Reason(got), ramphelpers.Reason(got))
	}
}

func TestErrorDetail_retrievalAuthFailureRoundTrip(t *testing.T) {
	detail := ramphelpers.RetrievalAuthFailureDetail("ramp.v1.Edge", "pop mismatch",
		rampv1.RetrievalAuthFailureReason(1)) // first defined, non-zero
	cerr := ramphelpers.AsConnectError(connect.CodePermissionDenied, detail)
	got, ok := ramphelpers.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatal("extract failed")
	}
	if _, ok := ramphelpers.Reason(got).(rampv1.RetrievalAuthFailureReason); !ok {
		t.Errorf("reason type = %T, want RetrievalAuthFailureReason", ramphelpers.Reason(got))
	}
}

func TestErrorDetailFrom_nonConnectError(t *testing.T) {
	if _, ok := ramphelpers.ErrorDetailFrom(errors.New("plain")); ok {
		t.Error("plain error should not yield a detail")
	}
}

func TestReason_unset(t *testing.T) {
	if r := ramphelpers.Reason(&rampv1.ErrorDetail{Message: "no reason"}); r != nil {
		t.Errorf("Reason of detail without oneof = %v, want nil", r)
	}
}

func TestErrorDetail_clientBranchesOnTypedReason(t *testing.T) {
	// Demonstrates the intended client usage: branch on the enum, not a string.
	detail := ramphelpers.TransactionDenialDetail("d", "rate limited",
		rampv1.DenialReason_DENIAL_REASON_RATE_LIMITED)
	cerr := ramphelpers.AsConnectError(connect.CodeResourceExhausted, detail)

	ed, _ := ramphelpers.ErrorDetailFrom(cerr)
	var handled bool
	switch r := ramphelpers.Reason(ed).(type) {
	case rampv1.DenialReason:
		if r == rampv1.DenialReason_DENIAL_REASON_RATE_LIMITED {
			handled = true
		}
	}
	if !handled {
		t.Error("expected to branch on DenialReason_RATE_LIMITED")
	}
}
