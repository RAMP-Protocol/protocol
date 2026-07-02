// Package ramp is the L2 low-tier RAMP SDK client face: a configurable Connect
// client, the unified offer Verifier, the fail-closed {verified, rejected}
// contract, the unforgeable VerifiedOffer compile guard, and the loud
// WithVerification opt-out — two faces over the sdk/go/helpers L1 primitives with
// signer, KeyResolver, baseURL, and (server-side) ReplayStore all injected
// (ADR-020 §2/§3).
//
// The client SIGN face is a signing http.RoundTripper (NewSigningTransport) —
// Content-Digest is computed over the marshaled body bytes, which a
// connect.Interceptor never sees — composed onto the http.Client BEFORE the
// Connect client is built. request-id and (opt-in) validate are true
// connect.Interceptors. Discover returns the fail-closed Result{Verified,
// Rejected}; Execute accepts ONLY an unforgeable VerifiedOffer (compile guard),
// with RejectedOffer.Unsafe() the single explicit escape. ReplayStore is defined
// here so the client and server (rampconnect) faces share one interface name.
package ramp
