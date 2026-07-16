package resolvers_test

// cachedofferkeyresolver_test.go — behavior suite for CachedOfferKeyResolver, the
// domain-keyed offer-signing-key cache that consolidates the Broker's
// offerkeys.Resolver and the MCP shim's ExchangeOfferKeyCache: per-domain TTL cache
// → WBA-directory fetch (injected seam) → revocation-aware active-key selection →
// not_after clamp. Tests inject a fake fetcher (no HTTP), a fixed clock, and a
// revoked-thumbprint predicate; they reuse the file-local activeWindowJWK /
// longWindowJWK / wbaDirectory / mustThumbprint fixtures.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// countingFetch returns a fetcher that always yields dir and records call count.
func countingFetch(dir *rampv1.WBAFile, calls *atomic.Int64) resolvers.OfferDirectoryFetcher {
	return func(_ context.Context, _ string) (*rampv1.WBAFile, error) {
		calls.Add(1)
		return dir, nil
	}
}

func TestCachedOfferKeyResolver_CachesWithinTTL(t *testing.T) {
	t.Parallel()
	pub, jwk := activeWindowJWK("ex1")
	var calls atomic.Int64
	now := wbaAnchor
	r := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch: countingFetch(wbaDirectory(jwk), &calls),
		TTL:   time.Minute,
		Now:   func() time.Time { return now },
	})
	got, err := r.Resolve(context.Background(), "exchange.example")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("resolved key must be the directory's active key")
	}
	// A second resolve within the TTL is a cache hit — no second fetch.
	if _, err := r.Resolve(context.Background(), "exchange.example"); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one fetch within the TTL, got %d", calls.Load())
	}
}

func TestCachedOfferKeyResolver_RefetchesAfterTTL(t *testing.T) {
	t.Parallel()
	_, jwk := activeWindowJWK("ex-ttl")
	var calls atomic.Int64
	now := wbaAnchor
	r := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch: countingFetch(wbaDirectory(jwk), &calls),
		TTL:   time.Minute,
		Now:   func() time.Time { return now },
	})
	if _, err := r.Resolve(context.Background(), "ex"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	// Advance past the TTL (still inside the key window): the entry is stale → refetch.
	now = wbaAnchor.Add(2 * time.Minute)
	if _, err := r.Resolve(context.Background(), "ex"); err != nil {
		t.Fatalf("post-TTL Resolve: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected a refetch after the TTL, got %d fetches", calls.Load())
	}
}

func TestCachedOfferKeyResolver_ClampsExpiryToNotAfter(t *testing.T) {
	t.Parallel()
	// The TTL is far longer than the key's remaining window, so the entry must expire
	// at not_after (anchor+1h), NOT at now+TTL — otherwise a key would keep verifying
	// up to a full TTL past its validity window.
	_, jwk := activeWindowJWK("ex-clamp") // not_after = anchor + 1h
	var calls atomic.Int64
	now := wbaAnchor
	r := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch: countingFetch(wbaDirectory(jwk), &calls),
		TTL:   1000 * time.Hour,
		Now:   func() time.Time { return now },
	})
	if _, err := r.Resolve(context.Background(), "ex"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	// Just before not_after: still a cache hit (no refetch).
	now = wbaAnchor.Add(time.Hour - time.Minute)
	if _, err := r.Resolve(context.Background(), "ex"); err != nil {
		t.Fatalf("pre-not_after Resolve: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("entry must stay cached until not_after, got %d fetches", calls.Load())
	}
	// At not_after the entry expires → refetch. The key is now also outside its
	// window, so selection fails closed — proving the clamp evicted at not_after
	// rather than at the far-future now+TTL.
	now = wbaAnchor.Add(time.Hour)
	_, err := r.Resolve(context.Background(), "ex")
	if !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired once the window closed, got %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected a refetch at not_after, got %d fetches", calls.Load())
	}
}

func TestCachedOfferKeyResolver_SkipsRevokedKey(t *testing.T) {
	t.Parallel()
	// The first window-active key is revoked; the resolver must serve the next
	// active, non-revoked key — the cache is on a verification path, so it MUST
	// screen revocation (unlike the bare selector).
	pub1, k1 := activeWindowJWK("rev-a")
	pub2, k2 := activeWindowJWK("rev-b")
	revokedTP := mustThumbprint(t, pub1)
	var calls atomic.Int64
	r := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch:   countingFetch(wbaDirectory(k1, k2), &calls),
		Now:     func() time.Time { return wbaAnchor },
		Revoked: func(tp string) bool { return tp == revokedTP },
	})
	got, err := r.Resolve(context.Background(), "ex")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Equal(pub1) {
		t.Fatal("a revoked active key must never be served")
	}
	if !got.Equal(pub2) {
		t.Fatal("the next active, non-revoked key must be selected")
	}
}

func TestCachedOfferKeyResolver_PropagatesFetchError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("directory unreachable")
	r := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch: func(context.Context, string) (*rampv1.WBAFile, error) { return nil, sentinel },
		Now:   func() time.Time { return wbaAnchor },
	})
	_, err := r.Resolve(context.Background(), "ex")
	if !errors.Is(err, sentinel) {
		t.Fatalf("fetch error must propagate fail-closed, got %v", err)
	}
}

func TestCachedOfferKeyResolver_RejectsWhenNoActiveKey(t *testing.T) {
	t.Parallel()
	// An all-retired directory yields no active key: the resolver surfaces
	// ErrKeyExpired (fail-closed) rather than caching a nil key.
	r := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch: func(context.Context, string) (*rampv1.WBAFile, error) {
			return wbaDirectory(expiredWindowJWK("dead")), nil
		},
		Now: func() time.Time { return wbaAnchor },
	})
	if _, err := r.Resolve(context.Background(), "ex"); !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired, got %v", err)
	}
}

func TestNewCachedOfferKeyResolver_PanicsWithoutFetch(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic when Fetch is nil")
		}
	}()
	resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{})
}

// compile-time assertion: CachedOfferKeyResolver implements helpers.KeyResolver
// (domain-keyed), so it drops into core.Verifier where the app resolvers do.
var _ interface {
	Resolve(context.Context, string) (ed25519.PublicKey, error)
} = (*resolvers.CachedOfferKeyResolver)(nil)
