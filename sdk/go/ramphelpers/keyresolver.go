package ramphelpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// KeyResolver is the injection point for verifying-key lookup (ADR-020 §4). The
// pure Verifier takes a key directly; the resolver is how an application supplies
// keys — from a well-known endpoint, a private registry, a preloaded set, a
// proxy, or mTLS. It is ONE interface for both faces: the client verifying offers
// it received and a server's verify interceptor resolve keys the same way, so
// custody and network policy stay with the application.
type KeyResolver interface {
	// Resolve returns the Ed25519 public key registered for keyID, or an error
	// wrapping ErrUnknownKey when the key is not known.
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

// ErrUnknownKey signals that a KeyResolver has no key for the requested keyid.
var ErrUnknownKey = errors.New("ramphelpers: unknown keyid")

// StaticKeyResolver serves public keys from an in-memory map — for preloaded key
// sets and tests.
type StaticKeyResolver struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewStaticKeyResolver returns a resolver seeded with keys (copied).
func NewStaticKeyResolver(keys map[string]ed25519.PublicKey) *StaticKeyResolver {
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for k, v := range keys {
		copied[k] = v
	}
	return &StaticKeyResolver{keys: copied}
}

// Resolve implements KeyResolver.
func (s *StaticKeyResolver) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pub, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: keyid=%q", ErrUnknownKey, keyID)
	}
	return pub, nil
}

// Put registers a keyid → public-key mapping (dynamic registration / test seeding).
func (s *StaticKeyResolver) Put(keyID string, pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keyID] = pub
}

// WellKnownKeyResolver fetches a JWKS-shaped document from a URL (the publisher's
// /.well-known/ramp.json keys) and caches resolved keys with a TTL. The wire form
// is the RFC 7517 subset:
//
//	{"keys":[{"kid":"agent1.v1","kty":"OKP","crv":"Ed25519","x":"<base64url>"}]}
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
	// HTTP overrides the client used to fetch the JWKS (nil → http.DefaultClient).
	HTTP *http.Client
	// TTL is how long a successful fetch is cached (≤0 → 5 minutes).
	TTL time.Duration
	// Now overrides the clock for cache freshness (nil → time.Now). Tests inject.
	Now func() time.Time
	// Allow, when set, gates which keyids may resolve (nil → allow all known).
	Allow func(keyID string) bool
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

// Resolve implements KeyResolver. A cache hit short-circuits; a miss or TTL
// expiry triggers a single coalesced JWKS refresh.
func (r *WellKnownKeyResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if r.allow != nil && !r.allow(keyID) {
		return nil, fmt.Errorf("%w: keyid %q not allowed", ErrUnknownKey, keyID)
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
	return nil, fmt.Errorf("%w: keyid=%q", ErrUnknownKey, keyID)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return fmt.Errorf("ramphelpers: well-known request: %w", err)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("ramphelpers: well-known fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ramphelpers: well-known status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&doc); decErr != nil {
		return fmt.Errorf("ramphelpers: well-known decode: %w", decErr)
	}
	next := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if !strings.EqualFold(k.Kty, "OKP") || !strings.EqualFold(k.Crv, "Ed25519") {
			continue
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(k.X)
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		next[k.Kid] = ed25519.PublicKey(raw)
	}
	r.mu.Lock()
	r.cache = next
	r.cacheExp = r.now().Add(r.ttl)
	r.mu.Unlock()
	return nil
}

// VerifyRequestResolved resolves the request's signing key via resolver, then
// runs the pure VerifyRequest. It is the convenience the server interceptor and a
// key-resolving client use: the resolver does the IO, VerifyRequest stays pure.
func VerifyRequestResolved(ctx context.Context, req *http.Request, body []byte, resolver KeyResolver, opts VerifyOptions) (*VerifiedRequest, error) {
	params, _, err := parseSignatureHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	pub, err := resolver.Resolve(ctx, params.KeyID)
	if err != nil {
		return nil, err
	}
	return VerifyRequest(req, body, pub, opts)
}
