package resolvers

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"sync"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// defaultOfferKeyTTL bounds how long a fetched offer-signing key is served from the
// per-domain cache when no TTL is configured.
const defaultOfferKeyTTL = 5 * time.Minute

// OfferDirectoryFetcher fetches a domain's WBA identity directory. It is the
// injected IO seam of CachedOfferKeyResolver: the default (NewWBADirectoryFetcher)
// GETs scheme://domain[:port]/.well-known/http-message-signatures-directory through
// an SSRF-guarded client, but an application injects its own (wrapping its shared
// well-known fetch) and a test injects a directory table with no network.
type OfferDirectoryFetcher func(ctx context.Context, domain string) (*rampv1.WBAFile, error)

// CachedOfferKeyResolverConfig wires a CachedOfferKeyResolver.
type CachedOfferKeyResolverConfig struct {
	// Fetch resolves a domain to its WBA directory. REQUIRED —
	// NewCachedOfferKeyResolver panics when it is nil.
	Fetch OfferDirectoryFetcher
	// TTL bounds the per-domain cache; <=0 uses defaultOfferKeyTTL. The stored
	// entry's expiry is clamped to min(now+TTL, key.not_after) so a key is never
	// served past its validity window.
	TTL time.Duration
	// Now is the cache-freshness + selection clock; nil uses time.Now. Tests inject.
	Now func() time.Time
	// Revoked screens a candidate offer-signing key by its RFC 7638 thumbprint: a
	// revoked key is skipped during selection so the resolver never serves a
	// window-active-but-revoked key on the verification path. nil screens nothing —
	// inject WBAKeyResolver.Revoked (or an equivalent revoked-set predicate) on any
	// verification path; leaving it nil is a visible waiver of emergency revocation.
	Revoked func(thumbprint string) bool
}

// CachedOfferKeyResolver resolves an exchange DOMAIN to that exchange's active
// Ed25519 offer-signing key, caching per domain with a TTL and folding revocation
// screening into selection. It is the SDK home of the per-domain-cache + active-key
// selection + not_after clamp that the Broker (offerkeys.Resolver) and the MCP shim
// (ExchangeOfferKeyCache) each re-implemented — so the clamp, the off-by-one-prone
// min(now+ttl, not_after), lives and is fixed once. It implements helpers.KeyResolver
// keyed by domain (Offer.exchange), the same shape core.Verifier resolves offer keys
// through, so a Broker or MCP client Verifier can inject the SAME cache.
type CachedOfferKeyResolver struct {
	fetch   OfferDirectoryFetcher
	ttl     time.Duration
	now     func() time.Time
	revoked func(string) bool

	mu    sync.Mutex
	cache map[string]offerKeyEntry
}

type offerKeyEntry struct {
	key ed25519.PublicKey
	exp time.Time
}

// NewCachedOfferKeyResolver builds a resolver with defaults applied. It panics when
// cfg.Fetch is nil: a resolver with no directory source can never resolve anything,
// so the misconfiguration is caught at construction, not on the first Resolve.
func NewCachedOfferKeyResolver(cfg CachedOfferKeyResolverConfig) *CachedOfferKeyResolver {
	if cfg.Fetch == nil {
		panic("resolvers: CachedOfferKeyResolver requires a Fetch directory fetcher")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultOfferKeyTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &CachedOfferKeyResolver{
		fetch:   cfg.Fetch,
		ttl:     ttl,
		now:     now,
		revoked: cfg.Revoked,
		cache:   map[string]offerKeyEntry{},
	}
}

// Resolve implements helpers.KeyResolver: domain -> the exchange's active
// offer-signing key. A fresh cache entry short-circuits; a miss or TTL expiry
// fetches the domain's WBA directory, selects the first window-active, non-revoked
// key (ActiveEd25519KeyWithExpiryScreened), and caches it with an expiry clamped to
// min(now+ttl, not_after). Any fetch or selection failure propagates so the Verifier
// rejects the offer fail-closed.
func (r *CachedOfferKeyResolver) Resolve(ctx context.Context, domain string) (ed25519.PublicKey, error) {
	now := r.now()
	r.mu.Lock()
	if e, ok := r.cache[domain]; ok && now.Before(e.exp) {
		r.mu.Unlock()
		return e.key, nil
	}
	r.mu.Unlock()

	dir, err := r.fetch(ctx, domain)
	if err != nil {
		return nil, err
	}
	key, notAfter, err := ActiveEd25519KeyWithExpiryScreened(dir, now, r.revoked)
	if err != nil {
		return nil, err
	}
	// Clamp so a key is never served past its validity window: with a plain now+ttl
	// the window is only re-checked on a cache miss, so a key could keep verifying up
	// to a full TTL beyond its not_after.
	exp := now.Add(r.ttl)
	if notAfter.Before(exp) {
		exp = notAfter
	}
	r.mu.Lock()
	r.cache[domain] = offerKeyEntry{key: key, exp: exp}
	r.mu.Unlock()
	return key, nil
}

// NewWBADirectoryFetcher returns the default OfferDirectoryFetcher: it GETs
// scheme://domain[:port]/.well-known/http-message-signatures-directory through
// client and protojson-decodes the WBAFile (any transport/status/decode failure
// wraps ErrDirectoryUnavailable). client nil installs the same SSRF-guarded default
// WBAKeyResolver uses — the exchange domain is signature-covered but
// attacker-influenceable, so the guard costs nothing. scheme empty → https; port
// empty → the scheme default.
func NewWBADirectoryFetcher(client *http.Client, scheme, port string) OfferDirectoryFetcher {
	if client == nil {
		client = newGuardedWBAClient()
	}
	if scheme == "" {
		scheme = "https"
	}
	return func(ctx context.Context, domain string) (*rampv1.WBAFile, error) {
		host := domain
		if port != "" {
			host = net.JoinHostPort(domain, port)
		}
		return fetchWBAFile(ctx, client, scheme+"://"+host)
	}
}
