package connect

import (
	"context"
	"errors"
	"fmt"
	"time"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// defaultProofWindow is how long a delivery-fetch proof stays valid.
//
// Short on purpose, and deliberately NOT the signed URL's own expiry, which can
// be hours: the proof covers only the method and the URL, so for as long as the
// window is open anyone who observes the request can repeat it.
const defaultProofWindow = 30 * time.Second

// edgeErrorDomain is the ErrorDetail domain for a refusal by a delivery edge. It
// is the failing surface, not the fetched resource: the field is a stable
// grouping key for tooling, so it names the tier that refused.
const edgeErrorDomain = "ramp.v1.Edge"

// ReportUsage files a usage report with the Exchange that ISSUED the offer —
// never through a Broker, and never to an address from configuration.
//
// The destination comes off the report itself: UsageReport.exchange carries the
// offer's signed exchange domain, and the endpoint is then resolved from that
// Exchange's own well-known manifest. Reading it off the message rather than
// taking it as an argument is what makes the rule structural — there is no
// parameter a configured origin could be passed as, so it cannot become the
// default by anyone's convenience. Set it from the offer being reported:
//
//	report.Exchange = verified.Offer(.GetExchange())
//
// The report is cloned before ver and the idempotency key are stamped, so the
// message the caller built stays untouched — it crossed a package boundary as an
// argument, not as a buffer to fill in.
//
// The idempotency key identifies the REPORT, not the attempt. A fresh one is
// minted only when the caller supplied none — a value already on the message, or
// one pinned with WithIdempotencyKey, is left alone. That distinction matters: an
// application that mints its own key for its own dedup would otherwise have it
// silently discarded and see every retry counted as a second report.
func (c *Client) ReportUsage(ctx context.Context, report *rampv1.UsageReport, opts ...CallOption) (*rampv1.UsageReportResponse, error) {
	const op = "report usage"
	if report == nil {
		return nil, malformed(op, errors.New("report is nil"))
	}
	endpoint, err := vetExchangeEndpoint(ctx, c.endpoints, report.GetExchange(), op)
	if err != nil {
		return nil, err
	}
	stamped, err := cloneRequest(report, op)
	if err != nil {
		return nil, err
	}
	if err = stampEnvelope(&stamped.Ver, &stamped.IdempotencyKey, opts); err != nil {
		return nil, malformed(op, err)
	}
	resp, err := c.exchanges.clientFor(endpoint).ReportUsage(ctx, connectrpc.NewRequest(stamped))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// Dispute files a dispute with the Exchange that issued the offer, over the same
// vetted routing a usage report takes.
//
// The exchange domain is an ARGUMENT here rather than a field, because
// DisputeRequest carries no exchange field to read it from — an asymmetry forced
// by the message shape, not chosen. It is still the offer's signed domain and
// still goes through the identical checks, so a configured value cannot reach the
// wire unvetted.
//
// The dispute chain is a structural invariant: an agent must have filed a usage
// report and received a report_id before it can dispute, so req.ReportId and
// req.TransactionId both name links the Exchange already holds.
func (c *Client) Dispute(ctx context.Context, exchangeDomain string, req *rampv1.DisputeRequest, opts ...CallOption) (*rampv1.DisputeResponse, error) {
	const op = "dispute"
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	endpoint, err := vetExchangeEndpoint(ctx, c.endpoints, exchangeDomain, op)
	if err != nil {
		return nil, err
	}
	stamped, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	if err = stampEnvelope(&stamped.Ver, &stamped.IdempotencyKey, opts); err != nil {
		return nil, malformed(op, err)
	}
	resp, err := c.exchanges.clientFor(endpoint).DisputeTransaction(ctx, connectrpc.NewRequest(stamped))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// Fetch retrieves the content a signed delivery URL names, presenting proof of
// possession of the agent key that URL is bound to.
//
// This is the LOW-TIER fetch: follow one signed URL, present the key, return the
// bytes. It does not discover, select, buy or report — that orchestration is a
// separate, higher tier.
//
// The transport rules are the report leg's, for the same reason: the retrieval
// host is chosen by a party on the network. It dials through the SSRF guard and
// REFUSES redirects. Following one would either replay a proof bound to the old
// URL, which the edge's own check rejects, or hand a fresh proof of possession of
// the agent's key to whatever host the first hop named.
//
// A refusal from the edge arrives as a typed reason where the edge's vocabulary
// maps onto the protocol's, so ErrorDetailFrom reads a fetch failure and an RPC
// failure through the same accessor.
//
// It takes no CallOption: a fetch is a GET against an already-issued URL, so
// there is no idempotency key to pin — nothing on this path mutates state.
//
// The URL is taken as given. Whether it is one this agent bought, and whether its
// agent_id matches this agent's key, are the CALLER's checks to make — the SDK
// exports helpers.VerifyURLEd25519 and VerifiedURL.CheckProofOfPossession for
// exactly that, and running them first turns an edge 403 into a local answer.
// Worth doing when the URL reached the caller from anywhere but its own execute
// response: a proof of possession is minted for whatever URL is passed in.
func (c *Client) Fetch(ctx context.Context, signedURL string) (resolvers.Content, error) {
	const op = "fetch content"
	signer, err := c.proofSigner()
	if err != nil {
		return resolvers.Content{}, &CallError{Kind: CallNotSignable, Op: op, Err: err}
	}
	content, err := c.fetcher.Fetch(ctx, signedURL, signer)
	if err != nil {
		return resolvers.Content{}, fetchCallError(op, signedURL, err)
	}
	return content, nil
}

// proofSigner composes the injected custody into the seam the content tier asks
// for. Both halves are required and neither can be derived from the other: the
// Signer keeps the private half, and the header presents the public one.
func (c *Client) proofSigner() (resolvers.ProofSigner, error) {
	signer := c.cfg.signer
	if signer == nil {
		return nil, errors.New("no signer configured; a bound fetch proves possession of the agent key (see WithSigner)")
	}
	if len(c.cfg.agentKey) == 0 {
		return nil, errors.New("no agent public key configured; a bound fetch presents it alongside the proof (see WithAgentKey)")
	}
	window := c.cfg.proofWindow
	if window == nil {
		window = core.ClockWindow(time.Now, defaultProofWindow)
	}
	return proofSigner{signer: signer, pub: c.cfg.agentKey, window: window}, nil
}

// proofSigner mints one agent binding per fetch.
type proofSigner struct {
	signer helpers.Signer
	pub    []byte
	window core.Window
}

func (p proofSigner) SignFetch(ctx context.Context, target string) (helpers.AgentBinding, error) {
	created, expires := p.window()
	return helpers.SignAgentBinding(ctx, p.signer, p.pub, helpers.PoPOptions{
		URL: target, Created: created, Expires: expires,
	})
}

// fetchCallError translates the content tier's failure into the client's own
// taxonomy, and promotes the edge's refusal token to a typed protocol reason when
// the vocabularies line up.
//
// The detail is SYNTHESIZED here rather than received: a delivery edge answers a
// small JSON object, not a protobuf. Its domain names the delivery edge as the
// failing SURFACE — a stable grouping, matching the value the cross-language
// error-detail corpus already uses for this reason block. Deliberately not the
// fetched URL: domain mirrors google.rpc.ErrorInfo.domain so generic tooling can
// group errors, and a per-URL value has unbounded cardinality and groups nothing.
func fetchCallError(op, signedURL string, err error) error {
	var ferr *resolvers.FetchError
	if !errors.As(err, &ferr) {
		return &CallError{Kind: CallUnknown, Op: op, Err: err}
	}
	out := &CallError{
		Kind:   fetchKinds[ferr.Failure],
		Op:     op,
		Status: ferr.Status,
		Reason: ferr.Reason,
		Err:    err,
	}
	if reason, ok := helpers.RetrievalAuthFailureReasonFromToken(ferr.Reason); ok {
		out.Detail = helpers.RetrievalAuthFailureDetail(
			edgeErrorDomain,
			fmt.Sprintf("delivery refused: %s", ferr.Reason),
			reason,
		)
	}
	return out
}

// fetchKinds maps the content tier's failure classes onto the client's. The two
// vocabularies are deliberately separate — the content tier knows nothing about
// RPCs — and this is the single place they meet.
var fetchKinds = map[resolvers.FetchFailure]CallErrorKind{
	resolvers.FetchRefused:     CallRefused,
	resolvers.FetchUnreachable: CallUnreachable,
	resolvers.FetchTooLarge:    CallTooLarge,
	resolvers.FetchNotSignable: CallNotSignable,
	resolvers.FetchMalformed:   CallMalformed,
}
