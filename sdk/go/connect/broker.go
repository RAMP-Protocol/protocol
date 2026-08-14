package connect

import (
	"context"
	"errors"

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
	// requester is the agent identity a Broker resolves the caller from. Held
	// here rather than demanded on every request for the same reason the exchange
	// client holds it: one client speaks for one agent.
	requester *rampv1.Requester
}

// NewBrokerClient builds a BrokerClient against a Broker's base URL. It accepts
// the same option type as NewClient, but only the options a discovery call has
// any use for actually do anything, and two of those need care:
//
//   - WithOfferKey pins a SINGLE offer-verifying key for every exchange, which is
//     the wrong shape here. Broker fan-out returns offers minted by different
//     Exchanges, so anything not signed by that one key lands in Rejected. Inject
//     WithKeyResolver instead — the resolvers tier ships one that resolves each
//     issuing Exchange's own key.
//   - WithRequester is REQUIRED, not optional: a Broker resolves the calling agent
//     from it and declines a request that names none, so Resolve refuses locally
//     rather than spending a round trip to be told.
//
// The options that do nothing here are the ones belonging to legs a Broker client
// does not have: WithAgentKey, WithProofWindow and WithContentTimeout /
// WithMaxContentBytes configure the delivery fetch; WithEndpointResolver and
// WithGuardedBaseTransport configure the offer-derived leg. Both legs live on the
// exchange client. Passing them here is silently inert rather than an error, so
// one shared option set can build both faces.
//
// BrokerService carries exactly one method today. The purchase path through a
// Broker is still a relay route rather than an RPC; when it becomes one, this
// type gains one method and nothing else here changes.
func NewBrokerClient(baseURL string, opts ...ClientOption) *BrokerClient {
	cfg := resolvedConfig(opts...)
	httpClient, connectOpts, verifier := plumbing(cfg)
	return &BrokerClient{
		rpc:       rampv1connect.NewBrokerServiceClient(httpClient, baseURL, connectOpts...),
		verifier:  verifier,
		requester: cfg.requester,
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
// The request is CLONED before ver and the requester are filled in, so the message
// the caller built stays untouched. Both are filled only when EMPTY: a value the
// caller set is theirs. A Broker resolves the calling agent from requester.id and
// refuses a request that names none, so leaving it to every caller to remember
// would make the identity the client already holds useless exactly where it is
// needed.
func (b *BrokerClient) Resolve(ctx context.Context, req *rampv1.DiscoveryRequest) (core.DiscoveryResult, error) {
	const op = "resolve"
	if req == nil {
		return core.DiscoveryResult{}, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	stampDiscovery(&sent.Ver, &sent.Requester, b.requester)
	// Refused locally rather than sent: a Broker resolves the calling agent from
	// the requester and declines a request that names none, so this is a verdict
	// the client already knows, and naming the remedy beats relaying "requester
	// required" from a round trip away. Execute refuses the same way.
	if sent.Requester == nil {
		return core.DiscoveryResult{}, malformed(op, errors.New(
			"no requester configured; a Broker resolves who is asking (see WithRequester)"))
	}
	resp, err := b.rpc.Resolve(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return core.DiscoveryResult{}, sendError(op, err)
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
