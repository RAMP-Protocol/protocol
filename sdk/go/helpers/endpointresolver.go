package helpers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ErrNoEndpoint signals that an Exchange's /.well-known/ramp.json was fetched and
// decoded successfully but advertises no endpoint (WellKnownManifest.endpoint,
// proto field 12, absent). It is deliberately distinct from a transport or
// decode failure: the manifest exists, the Exchange simply has not closed the
// "defined-but-inert endpoint" gap. Callers can tell "Exchange unreachable" from
// "Exchange reachable but not self-advertising an endpoint".
var ErrNoEndpoint = errors.New("helpers: well-known manifest has no endpoint")

// wellKnownDoc is the JSON projection of the subset of WellKnownManifest the SDK
// resolvers read: the RFC 7517 key set (field 5) and the self-advertised
// ExchangeService endpoint (field 12). One fetch decodes the whole document so a
// single body serves both the key face (WellKnownKeyResolver) and the endpoint
// face (WellKnownEndpointResolver).
type wellKnownDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	} `json:"keys"`
	Endpoint string `json:"endpoint"`
}

// fetchWellKnownDoc GETs url and decodes the well-known manifest. It is the one
// HTTP+decode path both resolvers share, so the request/status/decode handling
// cannot drift between the key and endpoint faces.
func fetchWellKnownDoc(ctx context.Context, client *http.Client, url string) (*wellKnownDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("helpers: well-known request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("helpers: well-known fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("helpers: well-known status %d", resp.StatusCode)
	}
	var doc wellKnownDoc
	if decErr := json.NewDecoder(resp.Body).Decode(&doc); decErr != nil {
		return nil, fmt.Errorf("helpers: well-known decode: %w", decErr)
	}
	return &doc, nil
}

// WellKnownEndpointResolver resolves an Exchange domain to its self-advertised
// ExchangeService endpoint by fetching https://{host}/.well-known/ramp.json and
// reading WellKnownManifest.endpoint. Unlike WellKnownKeyResolver (one fixed
// URL), it is HOST-KEYED: a Broker resolves an arbitrary, signature-covered
// Offer.exchange host per request, so the cache, TTL freshness, and single-flight
// coalescing are all per host. The pre-seeded registry is a TRUST overlay (the
// Allow hook), never the source of the endpoint — that is the Offer.exchange
// routing invariant: the endpoint always comes from the exchange's own manifest.
type WellKnownEndpointResolver struct {
	http   *http.Client
	ttl    time.Duration
	now    func() time.Time
	scheme string
	allow  func(host string) bool
	mu     sync.Mutex
	cache  map[string]endpointEntry
	flight map[string]*sync.Mutex
}

type endpointEntry struct {
	endpoint string
	exp      time.Time
}

// NewWellKnownEndpointResolver returns a host-keyed resolver. Zero-value options
// are safe defaults (https scheme, 5-minute TTL, real clock, default client).
func NewWellKnownEndpointResolver(opts WellKnownOptions) *WellKnownEndpointResolver {
	client := opts.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &WellKnownEndpointResolver{
		http:   client,
		ttl:    ttl,
		now:    now,
		scheme: scheme,
		allow:  opts.Allow,
		cache:  map[string]endpointEntry{},
		flight: map[string]*sync.Mutex{},
	}
}

// ResolveEndpoint returns the ExchangeService endpoint host advertises in its
// well-known manifest. A fresh cache entry short-circuits; a miss or TTL expiry
// triggers a single coalesced per-host fetch. A host the Allow overlay rejects
// never reaches the network.
func (r *WellKnownEndpointResolver) ResolveEndpoint(ctx context.Context, host string) (string, error) {
	if r.allow != nil && !r.allow(host) {
		return "", fmt.Errorf("%w: host %q not allowed", ErrNoEndpoint, host)
	}
	if ep, ok := r.cached(host); ok {
		return ep, nil
	}
	fl := r.hostFlight(host)
	fl.Lock()
	defer fl.Unlock()
	if ep, ok := r.cached(host); ok {
		return ep, nil // another goroutine fetched while we waited
	}
	url := r.scheme + "://" + host + "/.well-known/ramp.json"
	doc, err := fetchWellKnownDoc(ctx, r.http, url)
	if err != nil {
		return "", err
	}
	if doc.Endpoint == "" {
		return "", fmt.Errorf("%w: host=%q", ErrNoEndpoint, host)
	}
	r.store(host, doc.Endpoint)
	return doc.Endpoint, nil
}

func (r *WellKnownEndpointResolver) cached(host string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[host]
	if !ok || r.now().After(entry.exp) {
		return "", false
	}
	return entry.endpoint, true
}

func (r *WellKnownEndpointResolver) store(host, endpoint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[host] = endpointEntry{endpoint: endpoint, exp: r.now().Add(r.ttl)}
}

func (r *WellKnownEndpointResolver) hostFlight(host string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	fl, ok := r.flight[host]
	if !ok {
		fl = &sync.Mutex{}
		r.flight[host] = fl
	}
	return fl
}
