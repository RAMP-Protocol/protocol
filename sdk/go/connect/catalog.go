package connect

import (
	"context"
	"errors"
	"fmt"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/hostredact"
)

// CatalogClient is the Connect client for CatalogService — the publisher role's
// face: push, remove and refresh the catalog entries a publisher, or a
// contributor it authorised, supplies to an Exchange.
//
// It is a SEPARATE constructor, as the Broker client is, and for a related
// reason: the address is a different one. An Exchange advertises CatalogService
// at WellKnownManifest.catalog_endpoint, distinct from the ExchangeService
// endpoint the agent client dials, and the caller is a different party holding
// a different key — a contributor's, published in its own WBA directory and
// named by caller_id, never an agent's. Hanging the catalog verbs on the agent
// client would carry every agent-only holder (the offer Verifier, the
// requester, the delivery fetcher) into a client that uses none of them, and
// point one of the two roles at the wrong address.
//
// The publisher chose the Exchange, so the origin is configuration and the leg
// runs on the plain signing transport — the posture of the agent client's home
// Exchange, not of its offer-derived leg: nobody but the caller named this
// address. A deployment that reads the address off the Exchange's manifest
// still dials only what it configured here.
//
// It shares the agent client's plumbing — the same signing RoundTripper, the
// same redirect refusal, the same request-id and validate interceptors, the
// same read cap — so the faces cannot drift in how they sign or correlate.
type CatalogClient struct {
	rpc rampv1connect.CatalogServiceClient
}

// NewCatalogClient builds a CatalogClient against an Exchange's catalog endpoint.
// It accepts the same option type as NewClient. WithSigner is what a real push
// needs — an Exchange refuses an unsigned catalog call — and WithValidation,
// WithHTTPClient, WithRequestIDFunc, WithInterceptors, WithSignWindow,
// WithSignatureAgent and WithClientOptions configure this leg exactly as they
// configure the agent client's home leg.
//
// The options a catalog call has no use for are inert rather than errors, so one
// option set can build every face: WithOfferKey, WithKeyResolver and
// WithVerification (offer verification — nothing here returns an offer),
// WithRequester (the caller is named by caller_id, not a Requester), WithAgentKey,
// WithProofWindow, WithContentTimeout and WithMaxContentBytes (the delivery
// fetch), and WithEndpointResolver and WithGuardedBaseTransport (the
// offer-derived leg).
func NewCatalogClient(baseURL string, opts ...ClientOption) *CatalogClient {
	cfg := resolvedConfig(opts...)
	httpClient, connectOpts, _ := plumbing(cfg)
	return &CatalogClient{
		rpc: rampv1connect.NewCatalogServiceClient(httpClient, baseURL, connectOpts...),
	}
}

// PushResources pushes or updates catalog entries.
//
// The request is CLONED before `ver` is stamped, so the message the caller built
// stays untouched; `ver` is filled only when empty. No idempotency key is
// stamped, because the message carries none: a catalog push is an upsert and
// naturally idempotent, so a key there would be ceremony rather than a
// guarantee. `exchange` is the caller's to set — the bare domain of the
// Exchange this push is meant for, which is the whole point of the field — and a
// request that names none, or names something that is not a bare domain, is
// refused before anything is signed or sent.
//
// An Exchange applies two tiers to every entry: the wire rules, then
// canonicalisation and registry membership over the terms. Both ship in
// sdk/go/helpers (ValidateResourceEntry) so a publisher can run them first; the
// Exchange's own run is the deciding one. A push it refuses as a whole comes
// back as a non-OK call whose typed reason, when the Exchange attaches one, is
// readable through ErrorDetailFrom as a CatalogRejection.
func (c *CatalogClient) PushResources(ctx context.Context, req *rampv1.PushResourcesRequest) (*rampv1.PushResourcesResponse, error) {
	const op = "push resources"
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	resp, err := c.rpc.PushResources(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// RemoveResources removes the catalog entries the request's paths name. Same
// envelope rule as PushResources: `ver` filled when empty, no idempotency key,
// `exchange` required and refused locally when it is not a bare domain.
func (c *CatalogClient) RemoveResources(ctx context.Context, req *rampv1.RemoveResourcesRequest) (*rampv1.RemoveResourcesResponse, error) {
	const op = "remove resources"
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	resp, err := c.rpc.RemoveResources(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// RefreshCatalog asks the Exchange to refresh the tenant's catalog from its
// configured sources. Same envelope rule as PushResources.
func (c *CatalogClient) RefreshCatalog(ctx context.Context, req *rampv1.RefreshCatalogRequest) (*rampv1.RefreshCatalogResponse, error) {
	const op = "refresh catalog"
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	resp, err := c.rpc.RefreshCatalog(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// stampVer fills the protocol version only when the caller left it empty — the
// envelope a catalog call carries, which is the discovery envelope minus the
// requester: `ver` has a single owner, and the caller's own value is theirs.
func stampVer(ver *string) {
	if *ver == "" {
		*ver = helpers.ProtocolVersion
	}
}

// requireRecipient refuses a catalog request that names no recipient, or one
// whose recipient is not a bare domain, BEFORE anything is signed or sent. The
// field is required on the wire and the Exchange rejects a request that names
// someone else, so an unaddressed request can only be refused; refusing it here
// names the remedy instead of relaying a validation failure from a round trip
// away. It is a refusal to send, not a malformed message: the same verdict a
// report or a dispute with no routable recipient gets.
//
// The predicate is IsBareDomain, the SHAPE rule, not the routing rule IsBareHost.
// Nothing dials this value — a catalog client is built against an address the
// publisher configured — so the only question it answers is whether the value is
// the form the contract admits, which is the protovalidate pattern `exchange`
// carries and the same rule the Exchange's own audience check applies on arrival.
// The routing predicate is deliberately wider: an underscore, a trailing root dot
// and a bracketed IPv6 literal are all usable hosts and none of them is a value
// this field may hold, so vetting with it would sign and send a request the
// recipient can only refuse — the round trip this check exists to save.
//
// The refused value is redacted before it is named. A reference carrying userinfo
// is a verdict rather than a parse failure, so it reaches the message below
// verbatim; the routing check next door redacts for the same reason, and a tier
// that echoes is the drift hostredact exists to prevent.
func requireRecipient(op, exchange string) error {
	if exchange == "" {
		return notSent(op, errors.New("request names no recipient; set exchange to the Exchange's bare domain"))
	}
	if !helpers.IsBareDomain(exchange) {
		return notSent(op, fmt.Errorf("exchange %q is not a bare domain", hostredact.Userinfo(exchange)))
	}
	return nil
}
