// Package core is the transport-neutral L2 substance of the RAMP SDK: the unified
// offer Verifier, the fail-closed {verified, rejected} contract (Result), the
// per-URI discovery shape both discovery verbs return (DiscoveryResult /
// OfferGroupResult, sorted by Verifier.SortGroups), the unforgeable VerifiedOffer
// compile guard with the loud RejectedOffer.Unsafe escape, the client signing
// http.RoundTripper (NewSigningTransport), the injected ReplayStore interface, and
// the neutral request-id mint/middleware — all built on the sdk/go/helpers L1
// primitives with net/http as the only transport dependency (ADR-020 §2/§3).
//
// The discovery shape is grouped rather than flat because a discovery call is
// per-URI: a URI that yielded nothing has no offer to carry its identity back, so
// flattening would erase both which resource was refused and the typed reason it
// was — and those reasons are different agent actions, not shades of "none".
//
// core imports NOTHING from connectrpc: RAMP is an HTTP protocol, and this package
// only needs net/http, so a team on grpc-go / plain net/http / any transport can
// compose the Verifier, the signing transport, and the guard WITHOUT a Connect
// dependency. The Connect bindings (sdk/go/connect for the client, sdk/go/connectserver
// for the server) are one opt-in adapter family over this core among potentially
// several; they depend one-directionally on core.
//
// The client SIGN face is a signing http.RoundTripper (NewSigningTransport) —
// Content-Digest is computed over the marshaled body bytes, which an RPC-framework
// interceptor never sees — so it is realized at the HTTP seam, not as an
// interceptor. The Verifier surfaces the fail-closed Result{Verified, Rejected};
// only an unforgeable VerifiedOffer is executable, with RejectedOffer.Unsafe() the
// single explicit escape. ReplayStore is defined here so the client and server
// faces share one interface name.
package core
