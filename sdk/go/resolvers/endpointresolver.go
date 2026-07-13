package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// maxWellKnownDocBytes bounds the well-known / JWKS response body read. A hostile
// or misconfigured origin cannot force an unbounded read into the JSON decoder;
// well-known documents are small. Mirrors the WBA fetch's maxDocBytes cap and the
// Python / TS 1 MiB well-known bound so the three SDKs agree on the ceiling.
const maxWellKnownDocBytes = 1 << 20 // 1 MiB

// ErrNoEndpoint signals that an Exchange's /.well-known/ramp.json was fetched and
// decoded successfully but advertises no endpoint (WellKnownManifest.endpoint,
// proto field 12, absent). It is deliberately distinct from a transport or
// decode failure: the manifest exists, the Exchange simply has not closed the
// "defined-but-inert endpoint" gap. Callers can tell "Exchange unreachable" from
// "Exchange reachable but not self-advertising an endpoint".
var ErrNoEndpoint = errors.New("resolvers: well-known manifest has no endpoint")

// wellKnownDoc is the JSON projection of the subset of WellKnownManifest the SDK
// resolvers read: the RFC 7517 key set (field 5) and the self-advertised
// ExchangeService endpoint (field 12). One fetch decodes the whole document so a
// single body serves both the key face (WellKnownKeyResolver) and the endpoint
// face (WellKnownEndpointResolver).
//
// The embedded jose.JSONWebKeySet promotes the "keys" member, so go-jose (the
// canonical JOSE library) parses each JWK — decoding the OKP/Ed25519 `x` member
// into an ed25519.PublicKey on JSONWebKey.Key — rather than the SDK hand-rolling
// the kty/crv match and the base64url `x` decode. The endpoint face still reads
// the promoted-alongside Endpoint field from the same body.
type wellKnownDoc struct {
	jose.JSONWebKeySet
	Endpoint string `json:"endpoint"`
}

// fetchWellKnownDoc GETs url and decodes the well-known manifest. It is the one
// HTTP+decode path both resolvers share, so the request/status/decode handling
// cannot drift between the key and endpoint faces.
func fetchWellKnownDoc(ctx context.Context, client *http.Client, url string) (*wellKnownDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("resolvers: well-known request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolvers: well-known fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resolvers: well-known status %d", resp.StatusCode)
	}
	// Bound the body read so a hostile origin cannot force an unbounded decode.
	var doc wellKnownDoc
	if decErr := json.NewDecoder(io.LimitReader(resp.Body, maxWellKnownDocBytes)).Decode(&doc); decErr != nil {
		return nil, fmt.Errorf("resolvers: well-known decode: %w", decErr)
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
// are safe defaults (https scheme, 5-minute TTL, real clock, SSRF-GUARDED client).
//
// The endpoint host is REQUEST-DERIVED: a Broker resolves a per-request,
// signature-covered Offer.exchange host and this resolver fetches that host's
// /.well-known/ramp.json. That is the same threat shape as the WBA directory
// fetch — a caller-influenced host reached over the network — so the default
// client is SSRF-guarded (NewGuardedClientFromEnv), NOT the unguarded
// http.DefaultClient. (The fixed-URL WellKnownKeyResolver stays on
// http.DefaultClient: its URL is an operator-chosen constant, not request-derived.)
// A deployment that must reach a private/loopback exchange (tests, on-prem) injects
// its own client via opts.HTTP or opts out via the SKIP_SSRF / ALLOW_INSECURE env flags.
func NewWellKnownEndpointResolver(opts WellKnownOptions) *WellKnownEndpointResolver {
	client := opts.HTTP
	if client == nil {
		client = NewGuardedClientFromEnv()
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
