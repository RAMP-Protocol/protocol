// Package helpers is the RAMP SDK low-tier L1: stateless protocol helpers
// built directly on the L0 generated wire types (github.com/RAMP-Protocol/protocol/gen/go).
//
// # Layering
//
//	L0  generated wire types          gen/go/ramp/v1, gen/go/vocab/*   (consumed, never rebuilt)
//	L1  stateless protocol helpers    THIS PACKAGE                     (no IO, no state, no transport)
//	L2  transport-neutral core + Connect bindings  sdk/go/core; sdk/go/connect (client), sdk/go/connectserver (server)  (state injected)
//	L3  framework adapters            separate packages                (convert, never replace)
//
// L1 owns exactly the protocol mechanics that are defined by the spec, are
// stateless / single-operation, and have two or more consumers (the inclusion
// test): RFC 9421 request signing and verification, RFC 7638 JWK
// thumbprints, signed-URL signing/verification and proof-of-possession, money
// (canonical decimal string) parsing and formatting, the ErrorDetail
// mapping, idempotency-key minting, scope/subscription plumbing, the cross-field
// CEL validation rules, and the KeyResolver abstraction with a well-known
// default.
//
// # What L1 never does
//
// L1 never owns state, never custodies a secret, and never performs transport.
// Keys arrive through the Signer interface (which may be a KMS the SDK cannot
// read); verifying keys arrive through an injected KeyResolver. Everything in
// this package is a pure function over its inputs or a small value type — it is
// safe to share across goroutines and trivial to unit-test, and it is the same
// code the Broker, Exchange, MCP shim, Edge, and external implementors all build
// on. This package is a relocation of the previously service-internal helpers
// (internal/httpsig, internal/rampthumbprint, internal/rampwellknown,
// src/exchange/internal/signing), made into one reusable surface — the crypto is
// kept byte-identical across the move.
package helpers
