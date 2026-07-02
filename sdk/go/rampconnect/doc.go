// Package rampconnect is the L2 low-tier RAMP SDK server face: the verify
// http-seam wrapper around the generated Connect handlers plus the mirror
// interceptor stack (request-id outermost · verify · validate · error-detail-emit)
// over the sdk/go/helpers L1 primitives, with KeyResolver and ReplayStore injected
// by the application (ADR-020 §2/§3; server order per the architect-review
// amendment).
//
// NewExchangeServiceHandler wraps the generated Connect handler: verify and
// request-id are http.Handler seam wrappers (RFC 9421 verification needs the exact
// body bytes, which a connect.Interceptor never sees), with request-id OUTERMOST so
// a reject response still carries a stamped X-Request-ID; validate and error-detail
// are true connect.Interceptors. The KeyResolver, ReplayStore, hop budget, and
// request-id source are injected via ServerOption — the SDK orchestrates fail-closed
// verify + replay-check but owns no keys and no replay state.
package rampconnect
