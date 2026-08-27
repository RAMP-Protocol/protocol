package connectserver

import (
	"encoding/json"
	"errors"
	"net/http"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// rejectCode maps a verify-face rejection sentinel to the Connect code returned to
// the client. Two rejections are resource/policy limits rather than authentication
// failures and say so: a hop-budget rejection (ErrTooManyHops), and a body past the
// read cap, which the buffering read reports as *http.MaxBytesError. Every other
// rejection (bad signature, replay, broken chain, expiry, missing headers) is an
// authentication failure. Classifying an over-size body as Unauthenticated would
// tell a correctly-signed caller its credentials were wrong, and would hide the one
// refusal a caller fixes by sending less. It is a pure, stateless error→code
// mapping — the budget and cap VALUES stay injected.
func rejectCode(err error) connectrpc.Code {
	if errors.Is(err, helpers.ErrTooManyHops) || isBodyTooLarge(err) {
		return connectrpc.CodeResourceExhausted
	}
	return connectrpc.CodeUnauthenticated
}

// isBodyTooLarge reports whether err is net/http's over-cap signal from the read
// the body bound wraps.
func isBodyTooLarge(err error) bool {
	var maxBytes *http.MaxBytesError
	return errors.As(err, &maxBytes)
}

// httpStatus maps a rejection to its canonical Connect-over-HTTP status. The two
// ResourceExhausted causes separate here because they ask the caller for different
// things: a body past the cap is 413 (send less), a hop budget is 429 (send fewer,
// or slower). Unauthenticated is 401.
func httpStatus(code connectrpc.Code, err error) int {
	switch {
	case isBodyTooLarge(err):
		return http.StatusRequestEntityTooLarge
	case code == connectrpc.CodeResourceExhausted:
		return http.StatusTooManyRequests
	default:
		return http.StatusUnauthorized
	}
}

// writeReject emits a Connect-compatible error response so a Connect client sees a
// proper code (and matching HTTP status) instead of a raw status. The body shape
// mirrors Connect's unary error JSON.
func writeReject(w http.ResponseWriter, err error) {
	code := rejectCode(err)
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
