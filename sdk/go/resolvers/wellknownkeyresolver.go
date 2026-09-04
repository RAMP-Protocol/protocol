package resolvers

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// WellKnownKeyResolver fetches a JWKS-shaped document from one fixed,
// operator-chosen URL and caches resolved keys with a TTL. The document is a
// plain RFC 7517 JWK Set, not a WellKnownManifest — a manifest carries no keys
// member, and a JWK Set carries no manifest version, so the endpoint face's
// version gate does not apply here. The wire form is the RFC 7517 subset:
//
//	{"keys":[{"kid":"agent1.v1","kty":"OKP","crv":"Ed25519","x":"<base64url>"}]}
//
// NOTE: kid-matched keys in ramp.json are the pre-WBA-split identity shape.
// For party IDENTITY keys use WBAKeyResolver, which resolves the WBA directory
// (WBADirectoryPath) by RFC 7638 thumbprint with validity windows and
// revocation; this resolver remains for fixed-URL JWKS documents.
type WellKnownKeyResolver struct {
	url         string
	http        *http.Client
	ttl         time.Duration
	now         func() time.Time
	allow       func(keyID string) bool
	mu          sync.RWMutex
	cache       map[string]ed25519.PublicKey
	cacheExp    time.Time
	fetchSingle sync.Mutex
}

// WellKnownOptions tune the resolver. Zero values are safe defaults.
type WellKnownOptions struct {
	// HTTP overrides the client used to fetch. The nil-default differs by resolver
	// because the URL's provenance differs: WellKnownKeyResolver fetches a
	// fixed, operator-chosen JWKS URL, so it defaults to the unguarded
	// http.DefaultClient; WellKnownEndpointResolver fetches a REQUEST-DERIVED
	// Offer.exchange host, so it defaults to the SSRF-guarded
	// NewGuardedClientFromEnv (same threat shape as the WBA directory fetch).
	HTTP *http.Client
	// TTL is how long a successful fetch is cached (≤0 → 5 minutes).
	TTL time.Duration
	// Now overrides the clock for cache freshness (nil → time.Now). Tests inject.
	Now func() time.Time
	// Allow, when set, gates which keyids (WellKnownKeyResolver) or hosts
	// (WellKnownEndpointResolver) may resolve (nil → allow all known). It is the
	// trust-allowlist seam: an Exchange host the application does not trust can be
	// rejected here before any fetch.
	Allow func(id string) bool
	// Scheme is the URL scheme the WellKnownEndpointResolver uses to build
	// {scheme}://{host}/.well-known/ramp.json (empty → "https"). Tests inject
	// "http" to drive an httptest server. Unused by WellKnownKeyResolver, which
	// is constructed with a full URL.
	Scheme string
}

// NewWellKnownKeyResolver returns a resolver that lazily fetches the JWKS at url.
func NewWellKnownKeyResolver(url string, opts WellKnownOptions) *WellKnownKeyResolver {
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
	return &WellKnownKeyResolver{
		url:   url,
		http:  client,
		ttl:   ttl,
		now:   now,
		allow: opts.Allow,
		cache: map[string]ed25519.PublicKey{},
	}
}

// Resolve implements helpers.KeyResolver. A cache hit short-circuits; a miss or
// TTL expiry triggers a single coalesced JWKS refresh.
func (r *WellKnownKeyResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if r.allow != nil && !r.allow(keyID) {
		return nil, fmt.Errorf("%w: keyid %q not allowed", helpers.ErrUnknownKey, keyID)
	}
	if pub, ok := r.cachedKey(keyID); ok {
		return pub, nil
	}
	if err := r.refresh(ctx); err != nil {
		return nil, err
	}
	if pub, ok := r.cachedKey(keyID); ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: keyid=%q", helpers.ErrUnknownKey, keyID)
}

func (r *WellKnownKeyResolver) cachedKey(keyID string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.now().After(r.cacheExp) {
		return nil, false
	}
	pub, ok := r.cache[keyID]
	return pub, ok
}

func (r *WellKnownKeyResolver) refresh(ctx context.Context) error {
	r.fetchSingle.Lock()
	defer r.fetchSingle.Unlock()
	r.mu.RLock()
	fresh := r.now().Before(r.cacheExp)
	r.mu.RUnlock()
	if fresh {
		return nil // another goroutine refreshed while we waited
	}
	doc, err := fetchWellKnownDoc(ctx, r.http, r.url)
	if err != nil {
		return err
	}
	next := ed25519KeysFromJWKS(doc.JSONWebKeySet)
	r.mu.Lock()
	r.cache = next
	r.cacheExp = r.now().Add(r.ttl)
	r.mu.Unlock()
	return nil
}

// ed25519KeysFromJWKS extracts the Ed25519 (OKP/crv=Ed25519) public keys from a
// go-jose-parsed JWK Set, keyed by kid. go-jose decodes the JWK `x` member into
// an ed25519.PublicKey on the JSONWebKey.Key field when kty=OKP and
// crv=Ed25519; any other key type (or a missing kid) is skipped, preserving the
// resolver's accept-only-Ed25519-keyed-by-kid behavior.
func ed25519KeysFromJWKS(set jose.JSONWebKeySet) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(set.Keys))
	for i := range set.Keys {
		k := set.Keys[i]
		if k.KeyID == "" {
			continue
		}
		pub, ok := k.Key.(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			continue
		}
		out[k.KeyID] = pub
	}
	return out
}
