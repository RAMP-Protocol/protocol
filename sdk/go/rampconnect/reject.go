package rampconnect

import (
	"encoding/json"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// rejectCode maps a verify-face rejection sentinel to the Connect code returned to
// the client. A hop-budget rejection (ErrTooManyHops) is a resource/policy limit,
// not an authentication failure, so it surfaces as ResourceExhausted; every other
// rejection (bad signature, replay, broken chain, expiry, missing headers) is an
// authentication failure. It is a pure, stateless error→code mapping — the SDK
// mechanics half of the hop-budget concern; the budget VALUE stays injected.
func rejectCode(err error) connect.Code {
	if errors.Is(err, helpers.ErrTooManyHops) {
		return connect.CodeResourceExhausted
	}
	return connect.CodeUnauthenticated
}

// httpStatus maps the two codes the verify face emits to their canonical
// Connect-over-HTTP statuses (ResourceExhausted → 429, Unauthenticated → 401).
func httpStatus(code connect.Code) int {
	if code == connect.CodeResourceExhausted {
		return http.StatusTooManyRequests
	}
	return http.StatusUnauthorized
}

// writeReject emits a Connect-compatible error response so a Connect client sees a
// proper code (and matching HTTP status) instead of a raw status. The body shape
// mirrors Connect's unary error JSON.
func writeReject(w http.ResponseWriter, err error) {
	code := rejectCode(err)
	ce := connect.NewError(code, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus(code))
	body, _ := json.Marshal(map[string]string{"code": code.String(), "message": ce.Message()})
	_, _ = w.Write(body)
}
