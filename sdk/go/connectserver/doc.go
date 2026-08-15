// Package connectserver is the opt-in Connect-Go SERVER binding over the
// transport-neutral sdk/go/core L2 substance: the verify http-seam handler
// (NewExchangeServiceHandler — request-id outermost · verify · validate ·
// error-detail), the reject→connect.Code mapping, and the EMIT direction of the
// ErrorDetail↔Connect bridge (AsConnectError — a server emits a typed error
// detail). KeyResolver and ReplayStore are injected by the application
// (the server interceptor order is deliberate — see NewExchangeServiceHandler).
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
