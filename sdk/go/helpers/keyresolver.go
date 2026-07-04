package helpers

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
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
var ErrUnknownKey = errors.New("helpers: unknown keyid")

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

// VerifyRequestResolved resolves the request's signing key via resolver, then
// runs the pure VerifyRequest. It is the convenience the server interceptor and a
// key-resolving client use: the resolver does the IO, VerifyRequest stays pure.
func VerifyRequestResolved(ctx context.Context, req *http.Request, body []byte, resolver KeyResolver, opts VerifyOptions) (*VerifiedRequest, error) {
	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		return nil, err
	}
	ctx = WithSignatureAgent(ctx, signatureAgentOf(req))
	return verifySingleSignature(req, allParams[0], sigMap, body, ctxResolver(ctx, resolver), opts)
}

// ctxResolver adapts a KeyResolver (ctx-carrying Resolve) to the resolveFunc
// shape verifySingleSignature uses.
func ctxResolver(ctx context.Context, resolver KeyResolver) resolveFunc {
	return func(keyID string) (ed25519.PublicKey, error) {
		return resolver.Resolve(ctx, keyID)
	}
}

// VerifyMultisigRequestResolved verifies ALL signatures on req, resolving each
// label's key via resolver, and returns the VerifiedRequest list in sig1..sigN
// order. It is the multi-hop sibling of VerifyRequestResolved: it enforces the
// hop bound (opts.MaxSignatures) and the structural forwarding chain before
// cryptographically verifying every hop, so a stripped, reordered, or
// substituted predecessor is rejected. A single-signature request is the N=1
// case and verifies identically.
func VerifyMultisigRequestResolved(ctx context.Context, req *http.Request, body []byte, resolver KeyResolver, opts VerifyOptions) ([]VerifiedRequest, error) {
	ctx = WithSignatureAgent(ctx, signatureAgentOf(req))
	return VerifyMultisigRequest(req, body, ctxResolver(ctx, resolver), opts)
}
