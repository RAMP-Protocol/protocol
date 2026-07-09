// Package connect is the opt-in Connect-Go CLIENT binding over the transport-neutral
// sdk/go/core L2 substance: the configurable Connect client (NewClient — sign face
// as a signing RoundTripper, request-id/validate interceptors, the fail-closed offer
// Verifier), the shared bidirectional protovalidate interceptor
// (NewValidateInterceptor, the single definition the server binding also composes),
// and the READ direction of the ADR-019 ErrorDetail↔Connect bridge (ErrorDetailFrom
// — a client reads the typed error detail an upstream emitted). It depends
// one-directionally on core (Verifier, Result, VerifiedOffer guard, signing
// transport, ReplayStore) and imports connectrpc; core and helpers stay Connect-free
// (ADR-020 §2/§3).
//
// The SERVER binding is a SEPARATE package, sdk/go/connectserver
// (NewExchangeServiceHandler + the verify http-seam + AsConnectError / reject→code).
// Splitting client and server into two packages lets each expose BARE, symmetric
// option names — both have their own WithKeyResolver, WithValidation,
// WithRequestIDFunc, WithInterceptors — with no cross-face collision. connectserver
// imports this package for the shared Validation enum and NewValidateInterceptor;
// the edge is one-directional (connectserver → connect → core), no cycle.
//
// # Import name clash (consumers: alias one)
//
// This package is named "connect" and the Connect-Go framework is imported from
// "connectrpc.com/connect", whose package is ALSO named "connect". Inside this
// package the framework is aliased as `connectrpc "connectrpc.com/connect"` to
// avoid the self-clash. A CONSUMER that imports BOTH this package
// (github.com/RAMP-Protocol/protocol/sdk/go/connect) and connectrpc.com/connect
// MUST alias one of them, e.g.:
//
//	import (
//		rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
//		"connectrpc.com/connect"
//	)
package connect
