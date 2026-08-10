package connect

import (
	"context"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
)

// BrokerClient is the Connect client for BrokerService.
//
// It is a SEPARATE constructor rather than a second surface on the exchange
// client because the two speak to different parties. A Broker is not an
// Exchange: it fans a query out across Exchanges it knows and relays back what
// they offered, so its address is the Broker's, not any Exchange's. Hanging both
// off one base URL would mean one of the two was always pointed at the wrong
// party.
//
// It shares the exchange client's plumbing — the same signing transport, the same
// cross-cutting interceptors, the same fail-closed offer Verifier — so the two
// faces cannot drift in how they sign, correlate, validate or verify.
type BrokerClient struct {
	rpc      rampv1connect.BrokerServiceClient
	verifier core.Verifier
}

// NewBrokerClient builds a BrokerClient against a Broker's base URL. It takes the
// same options as NewClient; the ones that do not apply to a Broker are simply
// unused.
//
// BrokerService carries exactly one method today. The purchase path through a
// Broker is still a relay route rather than an RPC; when it becomes one, this
// type gains one method and nothing else here changes.
func NewBrokerClient(baseURL string, opts ...ClientOption) *BrokerClient {
	cfg := resolvedConfig(opts...)
	httpClient, interceptors, verifier := plumbing(cfg)
	return &BrokerClient{
		rpc:      rampv1connect.NewBrokerServiceClient(httpClient, baseURL, interceptors),
		verifier: verifier,
	}
}

// Resolve runs discovery through the Broker, which fans out to the Exchanges it
// knows and returns one group per requested URI.
//
// Every returned offer is verified through the SAME fail-closed Verifier
// Discover uses — not a second verification path. Broker-relayed offers are
// precisely the case that rule exists for: the Broker forwards offers it did not
// mint, and an unverified relay can steer an agent's selection with doctored
// terms that only fail later, at the purchase.
//
// A resolve that finds nothing is a SUCCESSFUL answer carrying a typed reason,
// not an error: the whole-call reason lands on DiscoveryResult.AbsenceReason and
// the per-URI ones on each group. Only a genuine fault returns an error.
//
// Resolve carries no idempotency key. Pure discovery buys nothing and changes
// nothing, so there is nothing for a server to deduplicate — the request message
// has no such field.
//
// The request is the CALLER's message and is sent unmodified, so the caller is
// the sender for ver purposes and MUST set req.Ver = helpers.ProtocolVersion.
func (b *BrokerClient) Resolve(ctx context.Context, req *rampv1.DiscoveryRequest) (core.DiscoveryResult, error) {
	resp, err := b.rpc.Resolve(ctx, connectrpc.NewRequest(req))
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	msg := resp.Msg
	return core.DiscoveryResult{
		Groups: b.verifier.SortGroups(ctx, msg.GetOfferGroups()),
		// The raw field, not the getter: an absent optional enum and the
		// unspecified value are different answers, and a getter collapses them.
		AbsenceReason: msg.AbsenceReason,
		// A DiscoveryResponse names no single Exchange and carries no rate-limit
		// signal — each offer carries its own issuing domain instead.
	}, nil
}
