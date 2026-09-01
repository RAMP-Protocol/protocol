package connectserver

import (
	"encoding/json"
	"errors"
	"net/http"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// RejectCode maps a verify-face rejection sentinel to the Connect code returned to
// the client. Two rejections are resource/policy limits rather than authentication
// failures and say so: a hop-budget rejection (ErrTooManyHops), and a body past the
// read cap, which the buffering read reports as *http.MaxBytesError. Every other
// rejection (bad signature, replay, broken chain, expiry, missing headers) is an
// authentication failure. Classifying an over-size body as Unauthenticated would
// tell a correctly-signed caller its credentials were wrong, and would hide the one
// refusal a caller fixes by sending less. It is a pure, stateless error→code
// mapping — the budget and cap VALUES stay injected.
//
// It answers the TRANSPORT question. ClassifyReject answers the AUDIT question over
// the same errors, returning a RejectReason token for a log rather than a code for
// the wire; a consumer that needs both calls both.
//
// It is exported so a mount whose gate carries its OWN resource-limit sentinel — one
// this package cannot know about — answers that case itself and defers every other
// case here, instead of re-deriving the whole mapping. That is the composition
// WriteReject is shaped for.
func RejectCode(err error) connectrpc.Code {
	if errors.Is(err, helpers.ErrTooManyHops) || IsBodyTooLarge(err) {
		return connectrpc.CodeResourceExhausted
	}
	return connectrpc.CodeUnauthenticated
}

// IsBodyTooLarge reports whether err is net/http's over-cap signal from the read the
// body bound wraps — the error http.MaxBytesHandler / http.MaxBytesReader produces
// once a body passes the cap.
//
// It is exported because the classification has callers outside the response path: a
// middleware that must decide, before it can answer, whether the read it just failed
// was a size refusal or a malformed request. Those two answer differently, so the
// caller branches — and the predicate it branches on has to be the one this package
// answers with, not a second copy that can drift from it.
func IsBodyTooLarge(err error) bool {
	var maxBytes *http.MaxBytesError
	return errors.As(err, &maxBytes)
}

// httpStatus maps a rejection to its canonical Connect-over-HTTP status. The two
// ResourceExhausted causes separate here because they ask the caller for different
// things: a body past the cap is 413 (send less), a hop budget is 429 (send fewer,
// or slower). Unauthenticated is 401.
//
// The 413 is a deliberate departure from the Connect specification, which maps
// ResourceExhausted to 429 for every cause. That is exactly why the split lives in
// one place: it is not the canonical answer, so a second implementation derives the
// canonical one and the two mounts disagree. The over-cap arm is gated on the code
// as well as the error so a caller that classifies a rejection as something other
// than a resource limit cannot be answered 413 over a body that says otherwise.
//
// It stays unexported: nothing needs the status without also wanting the body that
// goes with it, and WriteReject is that pairing.
func httpStatus(code connectrpc.Code, err error) int {
	switch {
	case code == connectrpc.CodeResourceExhausted && IsBodyTooLarge(err):
		return http.StatusRequestEntityTooLarge
	case code == connectrpc.CodeResourceExhausted:
		return http.StatusTooManyRequests
	default:
		return http.StatusUnauthorized
	}
}

// WriteReject emits a Connect-compatible error response so a Connect client sees a
// proper code (and matching HTTP status) instead of a raw status. The body shape
// mirrors Connect's unary error JSON: the two keys code and message, and nothing
// else — err's own text is the message, so a caller that rejects with a wrapped
// internal error publishes that text.
//
// The code is a parameter rather than derived, so a mount whose gate carries a
// resource-limit sentinel this package cannot know about supplies its own verdict
// and still gets this status split and this body. A caller with no such sentinel
// passes RejectCode(err), which is what this package's own handlers do.
func WriteReject(w http.ResponseWriter, code connectrpc.Code, err error) {
	ce := connectrpc.NewError(code, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus(code, err))
	body, _ := json.Marshal(map[string]string{"code": code.String(), "message": ce.Message()})
	_, _ = w.Write(body)
}

// AsConnectError builds a *connect.Error of the given Code with detail attached
// as a typed error detail (the ADR-019 transport mechanism). The detail's
// Message becomes the error string. It lives in the SERVER binding (the emit
// direction: a server EMITS a typed error detail) — not the transport-neutral L1
// helpers — so a non-Connect consumer of helpers/core compiles zero connectrpc; the
// neutral *rampv1.ErrorDetail builders and Reason stay in helpers, and this is where
// the ErrorDetail meets the Connect transport. The read direction (ErrorDetailFrom)
// lives in the client binding sdk/go/connect.
func AsConnectError(code connectrpc.Code, detail *rampv1.ErrorDetail) *connectrpc.Error {
	msg := "ramp error"
	if detail.GetMessage() != "" {
		msg = detail.GetMessage()
	}
	cerr := connectrpc.NewError(code, errors.New(msg))
	if d, err := connectrpc.NewErrorDetail(detail); err == nil {
		cerr.AddDetail(d)
	}
	return cerr
}
