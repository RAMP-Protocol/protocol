package ramphelpers

import (
	"errors"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// ADR-019 error contract. Failure is a typed ErrorDetail attached to the
// transport error: the Connect/gRPC Code is the coarse class, the ErrorDetail
// oneof carries the precise machine-readable reason. Clients branch on the typed
// reason, never on a human string. These helpers are the single place the SDK
// builds an ErrorDetail, attaches it to a transport error, and extracts it back
// — so every service and client speaks the contract identically instead of
// re-expressing it. The transport Code is the caller's to choose (it is
// service-specific policy which Code a given reason maps to, ADR-019 §Consequences).

func base(domain, message string) *rampv1.ErrorDetail {
	return &rampv1.ErrorDetail{Domain: domain, Message: message}
}

// TransactionDenialDetail builds an ErrorDetail carrying a typed DenialReason.
func TransactionDenialDetail(domain, message string, reason rampv1.DenialReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_TransactionDenial{TransactionDenial: &rampv1.TransactionDenial{Reason: reason}}
	return d
}

// RetrievalAuthFailureDetail builds an ErrorDetail carrying a typed RetrievalAuthFailureReason.
func RetrievalAuthFailureDetail(domain, message string, reason rampv1.RetrievalAuthFailureReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_RetrievalAuthFailure{RetrievalAuthFailure: &rampv1.RetrievalAuthFailure{Reason: reason}}
	return d
}

// CatalogRejectionDetail builds an ErrorDetail carrying a typed CatalogRejectionReason.
func CatalogRejectionDetail(domain, message string, reason rampv1.CatalogRejectionReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_CatalogRejection{CatalogRejection: &rampv1.CatalogRejection{Reason: reason}}
	return d
}

// RegistrationFailureDetail builds an ErrorDetail carrying a typed RegistrationFailureReason.
func RegistrationFailureDetail(domain, message string, reason rampv1.RegistrationFailureReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_RegistrationFailure{RegistrationFailure: &rampv1.RegistrationFailure{Reason: reason}}
	return d
}

// DisputeFailureDetail builds an ErrorDetail carrying a typed DisputeFailureReason.
func DisputeFailureDetail(domain, message string, reason rampv1.DisputeFailureReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_DisputeFailure{DisputeFailure: &rampv1.DisputeFailure{Reason: reason}}
	return d
}

// DomainVerificationFailureDetail builds an ErrorDetail carrying a typed DomainVerificationFailureReason.
func DomainVerificationFailureDetail(domain, message string, reason rampv1.DomainVerificationFailureReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_DomainVerificationFailure{DomainVerificationFailure: &rampv1.DomainVerificationFailure{Reason: reason}}
	return d
}

// UsageReportRejectionDetail builds an ErrorDetail carrying a typed UsageReportRejectionReason.
func UsageReportRejectionDetail(domain, message string, reason rampv1.UsageReportRejectionReason) *rampv1.ErrorDetail {
	d := base(domain, message)
	d.Reason = &rampv1.ErrorDetail_UsageReportRejection{UsageReportRejection: &rampv1.UsageReportRejection{Reason: reason}}
	return d
}

// AsConnectError builds a *connect.Error of the given Code with detail attached
// as a typed error detail (the ADR-019 transport mechanism). The detail's
// Message becomes the error string.
func AsConnectError(code connect.Code, detail *rampv1.ErrorDetail) *connect.Error {
	msg := "ramp error"
	if detail.GetMessage() != "" {
		msg = detail.GetMessage()
	}
	cerr := connect.NewError(code, errors.New(msg))
	if d, err := connect.NewErrorDetail(detail); err == nil {
		cerr.AddDetail(d)
	}
	return cerr
}

// ErrorDetailFrom extracts the first RAMP ErrorDetail attached to err's Connect
// error chain. It returns false when err is not a Connect error or carries no
// ErrorDetail.
func ErrorDetailFrom(err error) (*rampv1.ErrorDetail, bool) {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return nil, false
	}
	for _, d := range cerr.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		if ed, ok := msg.(*rampv1.ErrorDetail); ok {
			return ed, true
		}
	}
	return nil, false
}

// Reason returns the active typed reason enum from detail — one of
// rampv1.DenialReason, RetrievalAuthFailureReason, CatalogRejectionReason,
// RegistrationFailureReason, DisputeFailureReason, DomainVerificationFailureReason,
// or UsageReportRejectionReason — or nil when no reason is set. Callers type-switch
// on the result to branch on the failure, never on a string.
func Reason(detail *rampv1.ErrorDetail) any {
	switch {
	case detail.GetTransactionDenial() != nil:
		return detail.GetTransactionDenial().GetReason()
	case detail.GetRetrievalAuthFailure() != nil:
		return detail.GetRetrievalAuthFailure().GetReason()
	case detail.GetCatalogRejection() != nil:
		return detail.GetCatalogRejection().GetReason()
	case detail.GetRegistrationFailure() != nil:
		return detail.GetRegistrationFailure().GetReason()
	case detail.GetDisputeFailure() != nil:
		return detail.GetDisputeFailure().GetReason()
	case detail.GetDomainVerificationFailure() != nil:
		return detail.GetDomainVerificationFailure().GetReason()
	case detail.GetUsageReportRejection() != nil:
		return detail.GetUsageReportRejection().GetReason()
	default:
		return nil
	}
}
