package connect

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"sync"

	connectrpc "connectrpc.com/connect"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
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
// sent to, or refuses. Every refusal is a CallNotSent naming the check that
// declined, because "the Exchange said no", "we could not reach it" and "we
// refused to dial it" are three different outcomes and only the class tells them
// apart.
//
// It is one function so the vetting reads in one place: the checks are the part
// that grows, and seeing them together is what makes it evident that no branch
// falls through to the send.
func vetExchangeEndpoint(ctx context.Context, resolver EndpointResolver, exchangeDomain, op string) (string, error) {
	if resolver == nil {
		return "", notSent(op, fmt.Errorf("no endpoint resolver configured"))
	}
	if exchangeDomain == "" {
		return "", notSent(op, fmt.Errorf("no exchange domain to route to; it comes from the signed offer"))
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
		return "", notSent(op, fmt.Errorf("resolve exchange %q: %w", exchangeDomain, err))
	}
	// The manifest that named this endpoint is served by the very host the call is
	// bound for, so the endpoint is only as trustworthy as that host. Anchoring it
	// to the domain it was resolved from stops a manifest redirecting a signed call
	// to an unrelated host: an Exchange may advertise itself or a subdomain of
	// itself, and nothing else. The dial-time guard refuses private addresses
	// independently; this is the half that stops delivery to an unrelated PUBLIC
	// host, which no address guard would object to.
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

// exchangePool caches one Connect client per vetted origin, evicting the
// least-recently-used entry at the cap.
//
// Least-recently-used and not drop-the-whole-map: dropping empties the cache
// exactly when it is under most pressure, and it makes which entries survive a
// function of the order a caller names hosts — a property the caller controls.
//
// Every pooled client shares the ONE signing HTTP client, so a cached client
// still signs as the agent of the CURRENT request. The pool caches transport
// plumbing, never identity.
type exchangePool struct {
	http    connectrpc.HTTPClient
	opts    []connectrpc.ClientOption
	mu      sync.Mutex
	order   *list.List // front is most-recently-used; values are origins
	entries map[string]*list.Element
}

// pooledClient is what the LRU list holds: the origin (so eviction can find its
// map key) beside the client built for it.
type pooledClient struct {
	origin string
	client rampv1connect.ExchangeServiceClient
}

func newExchangePool(httpClient *http.Client, opts ...connectrpc.ClientOption) *exchangePool {
	return &exchangePool{
		http:    httpClient,
		opts:    opts,
		order:   list.New(),
		entries: make(map[string]*list.Element),
	}
}

// clientFor returns the cached client for origin, creating it on first use and
// evicting the least-recently-used entry once the pool is full.
func (p *exchangePool) clientFor(origin string) rampv1connect.ExchangeServiceClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	if el, ok := p.entries[origin]; ok {
		p.order.MoveToFront(el)
		return el.Value.(*pooledClient).client
	}
	if len(p.entries) >= maxPooledExchanges {
		if oldest := p.order.Back(); oldest != nil {
			p.order.Remove(oldest)
			delete(p.entries, oldest.Value.(*pooledClient).origin)
		}
	}
	client := rampv1connect.NewExchangeServiceClient(p.http, origin, p.opts...)
	p.entries[origin] = p.order.PushFront(&pooledClient{origin: origin, client: client})
	return client
}

// size reports how many origins the pool currently holds.
func (p *exchangePool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}
