package ramp

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"connectrpc.com/connect"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// clientConfig is the resolved set of injected holders a Client is built from.
// Everything is INJECTED — signer, offer KeyResolver, HTTP client, request-id
// source, verification mode, extra interceptors — and the SDK owns none of it as
// state (ADR-020 §3).
type clientConfig struct {
	signer        helpers.Signer
	httpClient    *http.Client
	offerKey      ed25519.PublicKey
	offerResolver helpers.KeyResolver
	mode          Mode
	validation    Validation
	requestID     RequestIDFunc
	extra         []connect.Interceptor
}

// ClientOption configures a Client. Options are the ONLY way to inject the
// signer, keys, HTTP client, and verification policy — the SDK has no ambient
// defaults for custody-bearing holders.
type ClientOption func(*clientConfig)

// WithSigner injects the RFC 9421 request Signer (custody stays with the app — the
// SDK never sees the private key). Without it the client sends unsigned requests,
// which a verifying server rejects.
func WithSigner(s helpers.Signer) ClientOption {
	return func(c *clientConfig) { c.signer = s }
}

// WithOfferKey injects the exchange's offer-verifying Ed25519 public key. The
// client's offer Verifier resolves every returned offer against it. Without it (and
// without WithKeyResolver) the client cannot verify offers, so under Strict every
// offer is rejected as unverifiable.
func WithOfferKey(pub ed25519.PublicKey) ClientOption {
	return func(c *clientConfig) { c.offerKey = pub }
}

// WithKeyResolver injects a custom offer-key resolver (a private registry, a proxy,
// a preloaded set). It is the same KeyResolver interface the server verify face
// resolves request-signing keys through — one interface for both faces. Overrides
// WithOfferKey.
func WithKeyResolver(r helpers.KeyResolver) ClientOption {
	return func(c *clientConfig) { c.offerResolver = r }
}

// WithVerification sets offer-verification strictness. The default is Strict
// (fail-closed); WithVerification(Off) is the single loud, named opt-out.
func WithVerification(m Mode) ClientOption {
	return func(c *clientConfig) { c.mode = m }
}

// WithValidation sets protovalidate strictness. The default is ValidationOff; a
// caller opts into bidirectional wire-shape enforcement with
// WithValidation(ValidationStrict). It is orthogonal to WithVerification (offer
// signature authenticity).
func WithValidation(v Validation) ClientOption {
	return func(c *clientConfig) { c.validation = v }
}

// WithHTTPClient injects a custom *http.Client (proxy, mTLS, pooling). The SDK
// composes its signing RoundTripper onto the client's transport, so a custom
// transport is preserved as the base.
func WithHTTPClient(h *http.Client) ClientOption {
	return func(c *clientConfig) { c.httpClient = h }
}

// WithRequestIDFunc overrides the request-id source (e.g. to reuse a trace id).
func WithRequestIDFunc(fn RequestIDFunc) ClientOption {
	return func(c *clientConfig) { c.requestID = fn }
}

// WithInterceptors appends application interceptors (tracing, metrics) to the SDK
// stack. They run inside the SDK cross-cutting interceptors.
func WithInterceptors(is ...connect.Interceptor) ClientOption {
	return func(c *clientConfig) { c.extra = append(c.extra, is...) }
}

// resolveOfferResolver returns the KeyResolver the offer Verifier uses. A custom
// resolver (WithKeyResolver) wins; otherwise WithOfferKey produces a fixed-key
// resolver that returns the injected key for any exchange id (the offer signature
// is keyed by the exchange, which the tests leave implicit); if neither is set the
// resolver is empty so every offer is unverifiable under Strict.
func (c clientConfig) resolveOfferResolver() helpers.KeyResolver {
	if c.offerResolver != nil {
		return c.offerResolver
	}
	if c.offerKey != nil {
		return fixedKeyResolver{pub: c.offerKey}
	}
	return emptyResolver{}
}

// fixedKeyResolver returns a single injected public key for ANY keyID. It backs
// WithOfferKey: the offer signature is keyed by the exchange identity, and an app
// that injects exactly one exchange key trusts that one exchange.
type fixedKeyResolver struct {
	pub ed25519.PublicKey
}

func (f fixedKeyResolver) Resolve(_ context.Context, _ string) (ed25519.PublicKey, error) {
	return f.pub, nil
}

// emptyResolver resolves nothing — every lookup is an unknown key. It backs the
// no-key Strict case so an unverifiable offer is fail-closed rejected.
type emptyResolver struct{}

func (emptyResolver) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	return nil, helpers.ErrUnknownKey
}
