package connect

import (
	"context"
	"crypto/ed25519"
	"net/http"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
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
	mode          core.Mode
	validation    Validation
	requestID     core.RequestIDFunc
	extra         []connectrpc.Interceptor

	requester   *rampv1.Requester
	agentKey    ed25519.PublicKey
	proofWindow core.Window
	endpoints   EndpointResolver
	guardedBase *http.Transport
	connectOpts []connectrpc.ClientOption
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
// a preloaded set) for the client's offer Verifier. It is the same KeyResolver
// interface the server verify face resolves request-signing keys through
// (connectserver.WithKeyResolver) — one interface for both faces. Overrides
// WithOfferKey.
func WithKeyResolver(r helpers.KeyResolver) ClientOption {
	return func(c *clientConfig) { c.offerResolver = r }
}

// WithVerification sets offer-verification strictness. The default is Strict
// (fail-closed); WithVerification(core.Off) is the single loud, named opt-out.
func WithVerification(m core.Mode) ClientOption {
	return func(c *clientConfig) { c.mode = m }
}

// WithValidation sets protovalidate strictness for the client. The default is
// ValidationOff; a caller opts into bidirectional wire-shape enforcement with
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

// WithRequestIDFunc overrides the client request-id source (e.g. to reuse a trace
// id).
func WithRequestIDFunc(fn core.RequestIDFunc) ClientOption {
	return func(c *clientConfig) { c.requestID = fn }
}

// WithInterceptors appends application interceptors (tracing, metrics) to the client
// SDK stack. They run inside the SDK cross-cutting interceptors.
func WithInterceptors(is ...connectrpc.Interceptor) ClientOption {
	return func(c *clientConfig) { c.extra = append(c.extra, is...) }
}

// WithRequester injects the agent's own identity, forwarded on a purchase for
// authorization and audit and covered by the detached offer acceptance.
//
// It is client-level rather than per-call on purpose: the requester IS the
// identity the injected Signer already fixes for the transport signature, so a
// per-call requester would let the two disagree about who is buying — the exact
// ambiguity the acceptance exists to remove. A verifying Broker refuses a
// requester id that does not normalise to the signer's own directory host.
//
// The message is cloned here, so a later mutation by the caller cannot reach a
// request already in flight.
func WithRequester(r *rampv1.Requester) ClientOption {
	return func(c *clientConfig) {
		if r == nil {
			c.requester = nil
			return
		}
		cloned, ok := proto.Clone(r).(*rampv1.Requester)
		if !ok {
			return
		}
		c.requester = cloned
	}
}

// WithAgentKey injects the PUBLIC half of the key WithSigner signs with. A
// delivery fetch presents it in a header, and a Signer cannot yield it — custody
// keeps the private half, so the public half has to be supplied alongside.
// Without it the client can buy but cannot fetch what it bought.
//
// There is deliberately no option for a SEPARATE acceptance key. The protocol
// carries one agent identity: agent_identity_hash is defined as the thumbprint of
// the agent's request-signing key, an Exchange verifies the detached acceptance
// against the key registered for the caller its request signature identified, and
// the delivery URL is bound to that same thumbprint. A second key would be
// refused at execute, and any URL it did produce could never be fetched — the
// presented key would not match the binding.
func WithAgentKey(pub ed25519.PublicKey) ClientOption {
	return func(c *clientConfig) { c.agentKey = pub }
}

// WithProofWindow overrides the freshness window stamped on a delivery-fetch
// proof. The default is 30 seconds from the wall clock.
//
// Deliberately NOT the signed URL's own expiry, which can be hours: the proof
// covers only the method and the URL, so anyone who observes the request can
// repeat it until the window closes.
func WithProofWindow(w core.Window) ClientOption {
	return func(c *clientConfig) { c.proofWindow = w }
}

// WithEndpointResolver injects the resolver that turns an offer's exchange domain
// into the origin that Exchange advertises for itself. It defaults to the
// SSRF-guarded well-known resolver.
//
// There is deliberately no option to supply an endpoint directly. A usage report
// must reach the Exchange that issued the offer, and that address comes from the
// Exchange's own manifest — never from configuration. Leaving no configuration
// slot for it is what makes that structural rather than a convention.
func WithEndpointResolver(r EndpointResolver) ClientOption {
	return func(c *clientConfig) { c.endpoints = r }
}

// WithGuardedBaseTransport carries the caller's own transport settings — a tuned
// connection pool, client certificates via TLSClientConfig — UNDERNEATH the SSRF
// guard on both legs that dial an address another party named: the content fetch,
// and the RPCs that route to the Exchange an offer identified.
//
// It is not a way to replace the guard. Those two legs dial hosts the client did
// not configure, so the dial-time address pin and the https-only scheme check are
// applied in every case; a caller supplies what sits under them. The only way to
// reach a private or plaintext endpoint is the deliberate, deployment-level
// SKIP_SSRF / ALLOW_INSECURE opt-out.
//
// One setting is dropped rather than carried: a custom TLS dialer. net/http
// prefers a transport's own TLS dialer over the pinned one on https, so honouring
// it would take every signed call around the address check. TLS itself is
// configured through TLSClientConfig, which is kept.
//
// The home Exchange and the Broker are operator-configured origins and are
// trusted as far as that configuration is, so they dial through WithHTTPClient's
// transport instead.
func WithGuardedBaseTransport(base *http.Transport) ClientOption {
	return func(c *clientConfig) { c.guardedBase = base }
}

// WithClientOptions appends raw Connect client options (a codec, a read cap
// tighter than the SDK default) to every Connect client the SDK builds.
// Interceptors belong in WithInterceptors; this is the escape hatch for the
// remaining client-level knobs the SDK does not model, mirroring
// connectserver.WithHandlerOptions on the server face.
//
// Options are appended AFTER the SDK's own, so a caller-supplied value wins.
func WithClientOptions(opts ...connectrpc.ClientOption) ClientOption {
	return func(c *clientConfig) { c.connectOpts = append(c.connectOpts, opts...) }
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

// resolveEndpointResolver returns the resolver an offer-derived call routes
// through: the injected one, or the SSRF-guarded well-known resolver. The
// endpoint is always read from the Exchange's own manifest — there is no
// configuration path to it.
func (c clientConfig) resolveEndpointResolver() EndpointResolver {
	if c.endpoints != nil {
		return c.endpoints
	}
	return resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{})
}
