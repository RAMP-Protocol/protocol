package helpers

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// KeyResolver is the injection point for verifying-key lookup. The
// pure Verifier takes a key directly; the resolver is how an application supplies
// keys — from a well-known endpoint, a private registry, a preloaded set, a
// proxy, or mTLS. It is ONE interface for both faces: the client verifying offers
// it received and a server's verify interceptor resolve keys the same way, so
// custody and network policy stay with the application. The fetching
// implementations (well-known JWKS, WBA directory, endpoint discovery) live in
// sdk/go/resolvers (L2, I/O); this interface and the in-memory StaticKeyResolver
// stay in the L1 trust core, which does no network I/O.
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
