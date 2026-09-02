// Package connectserver is the opt-in Connect-Go SERVER binding over the
// transport-neutral sdk/go/core L2 substance: the verify http-seam handlers
// (NewExchangeServiceHandler, NewBrokerServiceHandler and NewCatalogServiceHandler
// — request-id outermost · verify · validate · error-detail), the
// reject→connect.Code mapping (RejectCode · IsBodyTooLarge · WriteReject), and the
// EMIT direction of the
// ADR-019 ErrorDetail↔Connect bridge (AsConnectError — a server emits a typed error
// detail). KeyResolver and ReplayStore are injected by the application (ADR-020
// §2/§3; the server interceptor order is deliberate — see NewExchangeServiceHandler).
//
// # One authority for how a refusal is answered
//
// The three reject functions are exported, not internal, because the answer they
// produce is not the canonical one: the Connect specification maps ResourceExhausted
// to 429 for every cause, and this binding answers 413 for a body past the read cap,
// since that is the one refusal a caller fixes by sending less. A consumer that
// re-derives the split lands on the canonical answer and its mount then disagrees
// with a mount built here — silently, and only for the case a cap exists to handle.
// So the split and the error-envelope body live in WriteReject alone, and it takes
// the Connect code as a PARAMETER: a gate carrying a resource-limit sentinel this
// package cannot know about answers that one case itself and defers the rest to
// RejectCode, rather than keeping a second copy of the mapping.
//
// # Validation is opt-in, on every one of the three handlers
//
// The `validate` step named in that stack is composed ONLY when the application
// passes WithValidation(connect.ValidationStrict). ValidationOff is the enum's zero
// value, so a handler built with no options serves without protovalidate in either
// direction — and a deleted WithValidation line is indistinguishable from an
// explicit opt-out. Anything the contract describes as refused "at the boundary" —
// the ResourceEntry envelope rules, the LicenseTerm rules and the caps the catalog
// rejection reasons were retired against — arrives with that option and not
// otherwise. A deployment that wants the contract's own wire tier passes it on
// every mount; the reference implementation does, on all of them.
//
// It is a SEPARATE package from the client binding sdk/go/connect so that each face
// exposes BARE, symmetric option names — this package's WithKeyResolver,
// WithValidation, WithRequestIDFunc, WithInterceptors do not collide with the
// client's identically-named options because they live in different packages. It
// imports sdk/go/connect for the shared Validation enum and NewValidateInterceptor
// (one validate engine for both faces, zero duplication) and sdk/go/core for the
// ReplayStore interface and the request-id middleware. The dependency edge is
// one-directional (connectserver → connect → core); core and helpers stay
// Connect-free.
//
// # Import name clash (consumers: alias one)
//
// This package imports the Connect-Go framework from "connectrpc.com/connect"
// aliased as `connectrpc "connectrpc.com/connect"`. A consumer that imports both
// this package and connectrpc.com/connect should alias one for clarity (as the SDK
// client binding's doc also notes).
package connectserver
