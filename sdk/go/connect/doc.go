// Package connect is the opt-in Connect-Go CLIENT binding over the transport-neutral
// sdk/go/core L2 substance. It carries the agent verb set — Discover, Resolve,
// Execute, ReportUsage, Dispute and the low-tier content Fetch — across two
// constructors: NewClient for an Exchange and NewBrokerClient for a Broker, which
// are different parties and so cannot share one base URL.
//
// Around those sit the configurable client itself (sign face as a signing
// RoundTripper, request-id/validate interceptors, the fail-closed offer Verifier),
// the routing tier that resolves an offer's Exchange from that Exchange's own
// manifest and vets it before anything signed is sent, the CallError taxonomy that
// tells a refusal from a failure from a local decline, the shared bidirectional
// protovalidate interceptor (NewValidateInterceptor, the single definition the
// server binding also composes), and the READ direction of the
// ErrorDetail↔Connect bridge (ErrorDetailFrom — a client reads the typed error
// detail an upstream emitted, whether a peer sent it or the content leg
// synthesized it).
//
// It depends one-directionally on core (Verifier, DiscoveryResult, VerifiedOffer
// guard, signing transport, ReplayStore) and on resolvers for the one thing this
// package must not do itself — dial. The content fetch and the offer-derived RPC
// leg both run on the resolvers tier's guarded transport; core and helpers stay
// Connect-free.
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
