package connect

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	connectrpc "connectrpc.com/connect"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/lrucache"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// Routing a call to the Exchange that issued an offer.
//
// There are three kinds of destination, and the difference decides how much
// checking a call needs. The Broker and the home Exchange come from the client's
// own configuration and are trusted as far as that configuration is. The Exchange
// a usage report goes to is named inside an OFFER, which arrived over the
// network — so an actor who can influence an offer can influence that address.
//
// A signature covers the DOMAIN; it says nothing about where that domain's
// endpoint lives, or where its DNS points. That is why the address is resolved
// from the Exchange's own manifest and then checked, rather than taken on trust
// or, worse, read from configuration.

// EndpointResolver turns a signed exchange domain into the origin that Exchange
// advertises for itself. It is an interface so a test can drive reporting without
// standing up a manifest server — and, more to the point, so this package has no
// way to accept a report endpoint from configuration.
type EndpointResolver interface {
	ResolveEndpoint(ctx context.Context, host string) (string, error)
}

// vetExchangeEndpoint resolves exchangeDomain to an origin a signed call may be
// sent to, or refuses — naming the check that declined, and classifying it by
// CAUSE. "The Exchange said no", "we could not reach it" and "we refused to dial
// it" are three different outcomes calling for three different responses, and
// only the class tells them apart: a verdict is final, a transport failure is
// worth retrying.
//
// It is one function so the vetting reads in one place: the checks are the part
// that grows, and seeing them together is what makes it evident that no branch
// falls through to the send.
func vetExchangeEndpoint(ctx context.Context, resolver EndpointResolver, exchangeDomain, op string) (string, error) {
	if resolver == nil {
		return "", notSent(op, errors.New("no endpoint resolver configured"))
	}
	if exchangeDomain == "" {
		return "", notSent(op, errors.New("no exchange domain to route to; it comes from the signed offer"))
	}
	// A plain hostname, checked here even if the caller checked it. The resolver
	// builds its URL by concatenating this value, so a path or query smuggled
	// through would choose what gets fetched; this package owns the call and
	// cannot rely on every present and future caller having vetted it.
	bare, err := helpers.IsBareHost(exchangeDomain)
	if err != nil {
		return "", notSent(op, fmt.Errorf("exchange %q is not a usable domain: %w", exchangeDomain, err))
	}
	if !bare {
		return "", notSent(op, fmt.Errorf(
			"exchange %q is not a bare domain, refusing to resolve it", exchangeDomain))
	}
	endpoint, err := resolver.ResolveEndpoint(ctx, exchangeDomain)
	if err != nil {
		// Classified by CAUSE, not by position. Reaching the manifest is a network
		// operation, and a DNS blip or a 500 from an otherwise healthy Exchange is
		// TRANSIENT — reporting it as a refusal would tell a caller "we declined to
		// send this, do not retry" and permanently drop a usage report over a
		// momentary outage. Only a verdict is a refusal: the host was not allowed,
		// the manifest was read and advertises no endpoint at all, or it advertises
		// one the resolver will not hand back.
		kind := CallUnreachable
		if errors.Is(err, resolvers.ErrNoEndpoint) || errors.Is(err, resolvers.ErrEndpointRefused) {
			kind = CallNotSent
		}
		return "", &CallError{
			Kind: kind, Op: op,
			Err: fmt.Errorf("resolve exchange %q: %w", exchangeDomain, err),
		}
	}
	// Re-checked here even though the SDK's own resolver already refuses an
	// unanchored endpoint. The resolver is an injectable seam: a caller may supply
	// one, and this package cannot make a signed call conditional on a stranger's
	// implementation having remembered the rule. The cost is one string comparison
	// on a path that just did a network fetch.
	anchored, err := helpers.HostAnchored(exchangeDomain, endpoint)
	if err != nil {
		return "", notSent(op, fmt.Errorf(
			"check exchange %q endpoint %q: %w", exchangeDomain, endpoint, err))
	}
	if !anchored {
		return "", notSent(op, fmt.Errorf(
			"exchange %q advertises endpoint %q on a different host — refusing to send a signed call there",
			exchangeDomain, endpoint))
	}
	return endpoint, nil
}

// maxPooledExchanges bounds the per-origin client pool. Which Exchanges appear is
// driven by incoming offers, so the key space is open-ended and caller-influenced
// — an unbounded map is somewhere an authenticated caller can make the process
// grow without limit. A real deployment talks to a handful of Exchanges.
const maxPooledExchanges = 256

// exchangePool caches one Connect client per vetted origin over the SDK's shared
// bounded map, which carries the eviction policy and the reason for it.
//
// Every pooled client shares the ONE signing HTTP client, so a cached client
// still signs as the agent of the CURRENT request. The pool caches transport
// plumbing, never identity.
type exchangePool struct {
	http    connectrpc.HTTPClient
	opts    []connectrpc.ClientOption
	clients *lrucache.Cache[string, rampv1connect.ExchangeServiceClient]
}

func newExchangePool(httpClient *http.Client, opts ...connectrpc.ClientOption) *exchangePool {
	return &exchangePool{
		http:    httpClient,
		opts:    opts,
		clients: lrucache.New[string, rampv1connect.ExchangeServiceClient](maxPooledExchanges),
	}
}

// clientFor returns the cached client for origin, creating it on first use.
func (p *exchangePool) clientFor(origin string) rampv1connect.ExchangeServiceClient {
	return p.clients.GetOrCreate(origin, func(o string) rampv1connect.ExchangeServiceClient {
		return rampv1connect.NewExchangeServiceClient(p.http, o, p.opts...)
	})
}
