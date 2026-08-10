package connect

import (
	"context"
	"fmt"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// Client is the L2 low-tier RAMP Connect client: a configurable ExchangeService
// client with the sign face composed as a signing RoundTripper and the
// cross-cutting request-id / validate interceptors wired, plus the fail-closed
// offer Verifier that sorts every discovered offer into {verified, rejected}. It
// owns NO state — signer, keys, HTTP client, and verification policy are all
// injected (ADR-020 §2/§3).
type Client struct {
	rpc      rampv1connect.ExchangeServiceClient
	verifier core.Verifier
	cfg      clientConfig

	// exchanges caches one client per OFFER-DERIVED Exchange origin. The home
	// client above is the configured one; a usage report or a dispute goes to
	// whichever Exchange issued the offer, which is discovered at runtime.
	exchanges *exchangePool
	// endpoints resolves an offer's exchange domain to that Exchange's own
	// advertised origin. Never configuration.
	endpoints EndpointResolver
	// fetcher is the content leg. It dials, so it lives one tier down.
	fetcher *resolvers.ContentFetcher
}

// resolvedConfig applies opts over the defaults every client shares.
func resolvedConfig(opts ...ClientOption) clientConfig {
	cfg := clientConfig{httpClient: &http.Client{}, mode: core.Strict}
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// plumbing assembles what every client face is built from: the signing HTTP
// client, the cross-cutting interceptors as a Connect option, and the offer
// Verifier. Extracted so the exchange and broker faces cannot drift in how they
// sign, correlate, validate, or verify.
func plumbing(cfg clientConfig) (*http.Client, connectrpc.ClientOption, core.Verifier) {
	return signedHTTPClient(cfg, cfg.httpClient.Transport),
		connectrpc.WithInterceptors(clientInterceptors(cfg)...),
		core.NewVerifier(cfg.mode, cfg.resolveOfferResolver(), time.Now)
}

// NewClient builds a Client against baseURL — the agent's HOME Exchange, the one
// its account lives on. The sign face is composed onto the HTTP client's
// transport BEFORE the Connect client is built (Content-Digest needs the
// marshaled body bytes), then the cross-cutting interceptors are wired in the
// ADR order: sign(RoundTripper) · request-id · validate · (app extras). Offer
// verification is Strict by default.
//
// Discovery and purchase go to baseURL. A usage report or a dispute does NOT:
// those reach the Exchange that issued the offer, resolved per call from that
// Exchange's own manifest, over a separately guarded transport.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	cfg := resolvedConfig(opts...)
	httpClient, interceptors, verifier := plumbing(cfg)
	return &Client{
		rpc:      rampv1connect.NewExchangeServiceClient(httpClient, baseURL, interceptors),
		verifier: verifier,
		cfg:      cfg,
		// A SECOND signing client for the offer-derived leg, over the guarded
		// transport: the caller names a domain, the manifest it serves names an
		// endpoint, and a signed call then goes there. Without the guard one hop
		// down, that is a signed request aimed at an arbitrary internal address.
		// Redirects are refused outright — following one would re-sign the call for
		// a target the peer chose, after the endpoint check had already passed.
		exchanges: newExchangePool(signedHTTPClient(cfg, guardedFetchTransport(cfg)), interceptors),
		endpoints: cfg.resolveEndpointResolver(),
		fetcher: resolvers.NewContentFetcher(resolvers.ContentFetchOptions{
			Transport: cfg.fetchTransport,
		}),
	}
}

// signedHTTPClient returns an *http.Client whose transport is the SDK signing
// RoundTripper wrapping base (preserving a custom proxy/mTLS transport
// underneath). Redirects are refused: a RAMP RPC has no legitimate reason to be
// redirected, and following one would re-sign the caller's request for a target
// the peer chose — which would also move the destination after the endpoint check
// had run.
func signedHTTPClient(cfg clientConfig, base http.RoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	signed := *cfg.httpClient
	signed.Transport = core.NewSigningTransport(cfg.signer, base)
	signed.CheckRedirect = refuseRPCRedirect
	return &signed
}

// refuseRPCRedirect stops the client following any 3xx on an RPC leg.
//
// The target is redacted rather than passed through url.URL.Redacted(): that
// masks userinfo passwords only, and a RAMP target's query is not something to
// render into a log on the assumption it holds nothing worth hiding.
func refuseRPCRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("connect: refusing redirect to %s: a RAMP call is never redirected",
		helpers.RedactURL(req.URL.String()))
}

// guardedFetchTransport is the base transport for the offer-derived leg: the
// SSRF-guarded one, or whatever the caller injected for the content path (a test
// stack reaching a loopback Exchange injects its own).
func guardedFetchTransport(cfg clientConfig) http.RoundTripper {
	if cfg.fetchTransport != nil {
		return cfg.fetchTransport
	}
	return resolvers.NewGuardedClientFromEnv().Transport
}

// clientInterceptors assembles the cross-cutting interceptor stack (request-id ·
// validate · app extras). Sign is NOT here — it is the RoundTripper. Panics only
// if the shared validator fails to build, which is a programmer/config error, not
// a runtime condition.
func clientInterceptors(cfg clientConfig) []connectrpc.Interceptor {
	out := []connectrpc.Interceptor{newRequestIDInterceptor(cfg.requestID)}
	if cfg.validation == ValidationStrict {
		if v, err := NewValidateInterceptor(); err == nil {
			out = append(out, v)
		}
	}
	out = append(out, cfg.extra...)
	return out
}

// Discover issues DiscoverResources and returns one group per requested URI,
// each carrying the fail-closed {verified, rejected} split: EVERY returned offer
// is verified against the exchange offer-signing key (resolved through the
// injected resolver) before it is handed back. Neither an unverifiable nor a
// doctored offer is silently dropped — it lands in Rejected with a reason. A URI
// that yielded nothing keeps its group, carrying the typed reason, so a refusal
// is an answer rather than an absence. Round-trip: client sign → HTTP → server
// verify → origin → response, then the offer Verifier over the response.
//
// The query is the CALLER's message and is sent unmodified — unlike Execute,
// which builds its own request, Discover cannot stamp fields without mutating
// what it was handed. The caller is therefore the sender for ver purposes and
// MUST set query.Ver = helpers.ProtocolVersion (see "Protocol version" in
// ramp.proto: senders stamp it from one constant, never a literal).
func (c *Client) Discover(ctx context.Context, query *rampv1.ResourceQuery) (core.DiscoveryResult, error) {
	resp, err := c.rpc.DiscoverResources(ctx, connectrpc.NewRequest(query))
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	msg := resp.Msg
	return core.DiscoveryResult{
		Groups:    c.discoveredGroups(ctx, query, msg),
		Exchange:  msg.GetExchange(),
		RateLimit: msg.GetRateLimit(),
	}, nil
}

// discoveredGroups folds a ResourceResponse's two offer representations into the
// per-URI form.
//
// The message carries a grouped list AND a flat one, and the contract says a
// responder populating groups SHOULD leave the flat list empty "to avoid
// ambiguity" — but a real Exchange populates both, the flat list mirroring the
// grouped offers as a single-URI convenience. So the two are read as ALTERNATIVES,
// never concatenated: concatenating would double every offer against such a
// server, and deduplicating would silently accept a responder whose two lists
// disagree, which is precisely the ambiguity the contract forbids.
//
// Groups win when present. The flat fallback becomes a single group; it carries
// no URI of its own, so it takes the query's only URI when the query named
// exactly one, and none otherwise — the SDK does not invent an attribution the
// wire did not make.
func (c *Client) discoveredGroups(ctx context.Context, query *rampv1.ResourceQuery, msg *rampv1.ResourceResponse) []core.OfferGroupResult {
	if groups := msg.GetOfferGroups(); len(groups) > 0 {
		return c.verifier.SortGroups(ctx, groups)
	}
	flat := msg.GetOffers()
	if len(flat) == 0 {
		return nil
	}
	var uri string
	if uris := query.GetUris(); len(uris) == 1 {
		uri = uris[0]
	}
	return []core.OfferGroupResult{{URI: uri, Result: c.verifier.Sort(ctx, flat)}}
}

// CallOption tunes a single state-mutating call.
type CallOption func(*callConfig)

// ExecuteOption is the original name for CallOption, kept because the option set
// is identical across execute, report and dispute — the three RPCs the protocol
// requires an idempotency key on.
type ExecuteOption = CallOption

type callConfig struct {
	idempotencyKey string
}

// WithIdempotencyKey pins the idempotency key for this call. Reusing a key makes
// the call a deliberate replay: the server dedupes on it (a fresh key is minted
// per call by default). The SDK never tracks keys — the server owns dedup
// (ADR-019 §4, ADR-020 §3).
//
// Hold the key and pass the same one back when retrying, on every verb that takes
// this option. The key identifies the ACTION, not the attempt: a fresh key on a
// retry reads to the server as a second purchase, a second report, a second
// dispute.
func WithIdempotencyKey(key string) CallOption {
	return func(e *callConfig) { e.idempotencyKey = key }
}

// idempotencyKeyFor resolves the key for one call: the pinned one, or a freshly
// minted one.
func idempotencyKeyFor(opts []CallOption) (string, error) {
	var cc callConfig
	for _, o := range opts {
		o(&cc)
	}
	if cc.idempotencyKey != "" {
		return cc.idempotencyKey, nil
	}
	return helpers.NewIdempotencyKey()
}

// Execute commits to a VERIFIED offer and returns the transaction response. It
// accepts ONLY a core.VerifiedOffer — passing a RejectedOffer or a raw *rampv1.Offer
// is a COMPILE error (the unforgeable-VerifiedOffer guard). A per-call idempotency
// key is minted fresh unless WithIdempotencyKey pins one. Execute builds the whole
// TransactionRequest, so it also stamps ver from helpers.ProtocolVersion — the
// caller neither supplies nor overrides it.
func (c *Client) Execute(ctx context.Context, offer core.VerifiedOffer, opts ...CallOption) (*rampv1.TransactionResponse, error) {
	const op = "execute"
	if c.cfg.requester == nil {
		return nil, malformed(op, fmt.Errorf(
			"no requester configured; an Exchange resolves who is buying from it (see WithRequester)"))
	}
	signer := c.cfg.resolveAcceptanceSigner()
	if signer == nil {
		return nil, malformed(op, fmt.Errorf(
			"no signer configured; a purchase carries a detached acceptance (see WithSigner or WithAcceptanceSigner)"))
	}
	// An acceptance floating free of a concrete offer is meaningless, and an
	// unsigned offer is reachable here: WithVerification(Off) and
	// RejectedOffer.Unsafe() both mint a VerifiedOffer without a signature check.
	if offer.Offer().GetSignature() == "" {
		return nil, malformed(op, fmt.Errorf("cannot accept an unsigned offer"))
	}
	key, err := idempotencyKeyFor(opts)
	if err != nil {
		return nil, malformed(op, err)
	}
	// The acceptance covers the offer, the requester, and the idempotency key, so
	// a retry that pins the same key reproduces byte-identical acceptance bytes.
	// That is the deliberate-replay semantic, not an accident.
	acceptance, err := helpers.SignOfferAcceptanceWith(ctx, signer, offer.Offer(), c.cfg.requester, key)
	if err != nil {
		return nil, &CallError{Kind: CallNotSignable, Op: op, Err: err}
	}
	// Items-only wire shape: a single offer is the degenerate 1-element items
	// list, each item reflecting its signed Offer back exactly as received at
	// discovery. The authoritative identity is the reflected offer; the optional
	// top-level offer_id correlation scalar is left unset.
	//
	// ver comes from helpers.ProtocolVersion — the single owner of the protocol
	// version across all three SDKs — never a literal, so a bump is one edit.
	req := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: key,
		Requester:      c.cfg.requester,
		Items: []*rampv1.TransactionItem{{
			Offer: offer.Offer(),
			AgentAcceptance: &rampv1.AgentAcceptance{
				Signature:          acceptance,
				SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
			},
		}},
	}
	resp, err := c.rpc.ExecuteTransaction(ctx, connectrpc.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
