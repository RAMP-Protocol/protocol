package connect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/failure"
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

// DefaultMaxRPCReadBytes caps the response body a single RAMP call will read.
// Connect
// treats an unset cap as "any size" and compresses every exchange, so without one
// a hostile or misconfigured peer can decompress an unbounded body into the
// caller's memory. A RAMP response for a realistic batch is small; the bound is
// what stops a peer — including one an offer named — spending the caller's memory
// on its behalf. Override it per client with WithClientOptions.
const DefaultMaxRPCReadBytes = 1 << 20 // 1 MiB

// plumbing assembles what every client face is built from: the signing HTTP
// client, the Connect options, and the offer Verifier. Extracted so the exchange
// and broker faces cannot drift in how they sign, correlate, validate, verify, or
// bound what they read.
func plumbing(cfg clientConfig) (*http.Client, []connectrpc.ClientOption, core.Verifier) {
	// The caller's options come last so an application can tighten (or widen) a
	// default the SDK chose.
	opts := append([]connectrpc.ClientOption{
		connectrpc.WithInterceptors(clientInterceptors(cfg)...),
		connectrpc.WithReadMaxBytes(DefaultMaxRPCReadBytes),
	}, cfg.connectOpts...)
	return signedHTTPClient(cfg, cfg.httpClient.Transport),
		opts,
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
	httpClient, connectOpts, verifier := plumbing(cfg)
	return &Client{
		rpc:      rampv1connect.NewExchangeServiceClient(httpClient, baseURL, connectOpts...),
		verifier: verifier,
		cfg:      cfg,
		// A SECOND signing client for the offer-derived leg, over the guarded
		// transport: the caller names a domain, the manifest it serves names an
		// endpoint, and a signed call then goes there. Without the guard one hop
		// down, that is a signed request aimed at an arbitrary internal address.
		// Redirects are refused outright — following one would re-sign the call for
		// a target the peer chose, after the endpoint check had already passed. And
		// it carries its own deadline, because an offer-named Exchange that accepts
		// a connection and then never answers would otherwise hold the call, a
		// goroutine and a socket open indefinitely.
		exchanges: newExchangePool(
			offerDerivedClient(cfg, resolvers.NewGuardedTransport(cfg.guardedBase)), connectOpts...),
		endpoints: cfg.resolveEndpointResolver(),
		fetcher: resolvers.NewContentFetcher(resolvers.ContentFetchOptions{
			BaseTransport: cfg.guardedBase,
			Timeout:       cfg.fetchTimeout,
			MaxBytes:      cfg.fetchMaxByte,
			// The same mint the RPC legs read, so WithRequestIDFunc reaches all
			// three. Without it the delivery fetch is the one leg with no id, and
			// an edge that mints its own logs a refusal under a value nothing here
			// can join it to.
			RequestID: requestIDMint(cfg.requestID),
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
	signed.Transport = core.NewSigningTransport(cfg.signer, base, signingOptions(cfg)...)
	signed.CheckRedirect = refuseRPCRedirect
	return &signed
}

// signingOptions renders the signing knobs the client models onto the transport's
// own option type. It is the ONE place they meet, so every face the SDK builds —
// the home Exchange, the Broker, and the offer-derived pool, which all reach the
// wire through signedHTTPClient — signs on identical terms.
// It ACCUMULATES rather than returning on the first knob it finds. Written as an
// early return for a single option, the second one to arrive is silently dropped
// whenever the first is unset — which is how a client came to sign an empty
// Signature-Agent while the option to fill it already existed a tier down.
func signingOptions(cfg clientConfig) []core.SigningOption {
	var opts []core.SigningOption
	if cfg.signWindow != nil {
		opts = append(opts, core.WithWindow(cfg.signWindow))
	}
	if cfg.signatureAgent != "" {
		opts = append(opts, core.WithSignatureAgent(cfg.signatureAgent))
	}
	return opts
}

// refuseRPCRedirect stops the client following any 3xx on an RPC leg. Following
// one would re-sign the caller's request for a target the peer chose, after the
// endpoint check had already passed.
var refuseRPCRedirect = failure.RefuseRedirect(
	"connect", "a RAMP call is never redirected", helpers.RedactURL)

// DefaultCallTimeout bounds one call on the offer-derived leg. A RAMP RPC is
// interactive — something is waiting on the other end — so a request that has not
// answered by now is more useful as an error than as a hang.
const DefaultCallTimeout = 30 * time.Second

// offerDerivedClient is signedHTTPClient plus a deadline. The home Exchange and
// the Broker are operator-configured, so their timeout is the caller's to set
// through WithHTTPClient; an Exchange an offer named is not, and a client with no
// deadline against a host chosen by another party is a hang waiting to happen.
// An explicit timeout on the injected client is respected.
func offerDerivedClient(cfg clientConfig, base http.RoundTripper) *http.Client {
	client := signedHTTPClient(cfg, base)
	if client.Timeout <= 0 {
		client.Timeout = DefaultCallTimeout
	}
	// The caller's cookie jar does not come along. This leg already drops the
	// caller's proxy, TLS dialer and redirect policy, and a jar is the same kind of
	// ambient state: http.CookieJar is an interface, so what an arbitrary
	// implementation sends to a host an offer named is not this package's to
	// assume. A RAMP call carries its identity in the signature, never in a cookie.
	client.Jar = nil
	return client
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
// that the responder GROUPED and left empty keeps its group, carrying the typed
// reason, so a refusal is an answer rather than an absence. (A response carrying
// no groups at all yields none — there is nothing to keep.) Round-trip: client
// sign → HTTP → server verify → origin → response, then the offer Verifier over
// the response.
//
// The query is CLONED before ver and the requester are filled in, so the message
// the caller built stays untouched — it crossed a package boundary as an
// argument, not as a buffer. Both fields are filled only when EMPTY: a value the
// caller set is theirs.
func (c *Client) Discover(ctx context.Context, query *rampv1.ResourceQuery) (core.DiscoveryResult, error) {
	const op = "discover"
	if query == nil {
		return core.DiscoveryResult{}, malformed(op, errors.New("query is nil"))
	}
	sent, err := cloneRequest(query, op)
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	stampDiscovery(&sent.Ver, &sent.Requester, c.cfg.requester)
	resp, err := c.rpc.DiscoverResources(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return core.DiscoveryResult{}, sendError(op, err)
	}
	msg := resp.Msg
	return core.DiscoveryResult{
		Groups:    c.discoveredGroups(ctx, sent, msg),
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

// idempotencyKeyFor resolves the key for one call, in precedence order: the key
// pinned for this call, then whatever the caller already put on the message, then
// a freshly minted one.
func idempotencyKeyFor(opts []CallOption, onMessage string) (string, error) {
	var cc callConfig
	for _, o := range opts {
		o(&cc)
	}
	if cc.idempotencyKey != "" {
		return cc.idempotencyKey, nil
	}
	if onMessage != "" {
		return onMessage, nil
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
		return nil, malformed(op, errors.New(
			"no requester configured; an Exchange resolves who is buying from it (see WithRequester)"))
	}
	signer := c.cfg.signer
	if signer == nil {
		// CallNotSignable, matching what Fetch answers for the same missing
		// holder: a caller branching on the kind sees one condition under one
		// class, whichever verb met it first.
		return nil, &CallError{Kind: CallNotSignable, Op: op, Err: errors.New(
			"no signer configured; a purchase carries a detached acceptance signed with the agent's own key (see WithSigner)")}
	}
	// An acceptance floating free of a concrete offer is meaningless, and an
	// unsigned offer is reachable here: WithVerification(Off) and
	// RejectedOffer.Unsafe() both mint a VerifiedOffer without a signature check.
	if offer.Offer().GetSignature() == "" {
		return nil, malformed(op, errors.New("cannot accept an unsigned offer"))
	}
	key, err := idempotencyKeyFor(opts, "")
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
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// stampEnvelope fills the two envelope fields the protocol requires on a
// state-mutating call, WITHOUT overwriting what the caller already set.
//
// Fill-when-empty is the whole rule. `ver` has a single owner, so the SDK supplies
// it rather than making every caller reach for the constant. The idempotency key
// is REQUIRED and identifies the action rather than the attempt, so a value the
// caller put there is theirs — discarding it would turn each of their retries into
// a fresh action, which is the double-counting the field exists to prevent.
// WithIdempotencyKey overrides both.
func stampEnvelope(ver, idempotencyKey *string, opts []CallOption) error {
	if *ver == "" {
		*ver = helpers.ProtocolVersion
	}
	key, err := idempotencyKeyFor(opts, *idempotencyKey)
	if err != nil {
		return err
	}
	*idempotencyKey = key
	return nil
}

// stampDiscovery fills the envelope a DISCOVERY call carries, which is the
// mutating envelope minus the idempotency key: pure discovery buys nothing and
// changes nothing, so there is no action for a key to identify.
//
// Both fills are only-when-empty. The caller's own value always wins — the
// message crossed a package boundary as an argument, not as a buffer to fill in —
// and the requester is filled because both reference services resolve the calling
// agent from it and refuse a request that names none, while the client already
// holds that identity.
func stampDiscovery(ver *string, requester **rampv1.Requester, configured *rampv1.Requester) {
	if *ver == "" {
		*ver = helpers.ProtocolVersion
	}
	if *requester == nil {
		*requester = configured
	}
}

// cloneRequest copies a caller's message so the SDK can stamp its envelope
// without touching what the caller still holds.
//
// The type assertion cannot fail for a concrete message — proto.Clone returns the
// same dynamic type it was given — but it is checked rather than asserted blind,
// because a silent nil would reach the wire as an empty request. One helper
// rather than four copies of the same three lines.
func cloneRequest[T proto.Message](msg T, op string) (T, error) {
	cloned, ok := proto.Clone(msg).(T)
	if !ok {
		var zero T
		return zero, malformed(op, fmt.Errorf(
			"cloned %T has the wrong type", msg))
	}
	return cloned, nil
}
