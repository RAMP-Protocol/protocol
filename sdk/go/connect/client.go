package connect

import (
	"context"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
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
}

// NewClient builds a Client against baseURL. The sign face is composed onto the
// HTTP client's transport BEFORE the Connect client is built (Content-Digest needs
// the marshaled body bytes), then the cross-cutting interceptors are wired in the
// ADR order: sign(RoundTripper) · request-id · validate · (app extras). Offer
// verification is Strict by default.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	cfg := clientConfig{httpClient: &http.Client{}, mode: core.Strict}
	for _, o := range opts {
		o(&cfg)
	}
	httpClient := signedHTTPClient(cfg)
	interceptors := clientInterceptors(cfg)
	rpc := rampv1connect.NewExchangeServiceClient(
		httpClient, baseURL, connectrpc.WithInterceptors(interceptors...),
	)
	return &Client{
		rpc:      rpc,
		verifier: core.NewVerifier(cfg.mode, cfg.resolveOfferResolver(), time.Now),
	}
}

// signedHTTPClient returns an *http.Client whose transport is the SDK signing
// RoundTripper wrapping the injected client's base transport (preserving a custom
// proxy/mTLS transport as the base).
func signedHTTPClient(cfg clientConfig) *http.Client {
	base := cfg.httpClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	signed := *cfg.httpClient
	signed.Transport = core.NewSigningTransport(cfg.signer, base)
	return &signed
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

// Discover issues DiscoverResources and returns the fail-closed {verified,
// rejected} split: EVERY returned offer is verified against the exchange
// offer-signing key (resolved through the injected resolver) before it is handed
// back. Neither an unverifiable nor a doctored offer is silently dropped — it lands
// in Rejected with a reason. Round-trip: client sign → HTTP → server verify →
// origin → response, then the offer Verifier over the response.
func (c *Client) Discover(ctx context.Context, query *rampv1.ResourceQuery) (core.Result, error) {
	resp, err := c.rpc.DiscoverResources(ctx, connectrpc.NewRequest(query))
	if err != nil {
		return core.Result{}, err
	}
	return c.verifier.Sort(ctx, resp.Msg.GetOffers()), nil
}

// ExecuteOption tunes a single Execute call.
type ExecuteOption func(*executeConfig)

type executeConfig struct {
	idempotencyKey string
}

// WithIdempotencyKey pins the idempotency key for this Execute call. Reusing a key
// makes the call a deliberate replay: the server dedupes on it (a fresh key is
// minted per call by default). The SDK never tracks keys — the server owns dedup
// (ADR-019 §4, ADR-020 §3).
func WithIdempotencyKey(key string) ExecuteOption {
	return func(e *executeConfig) { e.idempotencyKey = key }
}

// Execute commits to a VERIFIED offer and returns the transaction response. It
// accepts ONLY a core.VerifiedOffer — passing a RejectedOffer or a raw *rampv1.Offer
// is a COMPILE error (the unforgeable-VerifiedOffer guard). A per-call idempotency
// key is minted fresh unless WithIdempotencyKey pins one.
func (c *Client) Execute(ctx context.Context, offer core.VerifiedOffer, opts ...ExecuteOption) (*rampv1.TransactionResponse, error) {
	var ec executeConfig
	for _, o := range opts {
		o(&ec)
	}
	key := ec.idempotencyKey
	if key == "" {
		minted, err := helpers.NewIdempotencyKey()
		if err != nil {
			return nil, err
		}
		key = minted
	}
	// Items-only wire shape: a single offer is the degenerate
	// 1-element items list, each item reflecting its signed Offer back exactly as
	// received at discovery. The authoritative identity is the reflected offer; the
	// optional top-level offer_id correlation scalar is left unset.
	req := &rampv1.TransactionRequest{
		IdempotencyKey: key,
		Items:          []*rampv1.TransactionItem{{Offer: offer.Offer()}},
	}
	resp, err := c.rpc.ExecuteTransaction(ctx, connectrpc.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
