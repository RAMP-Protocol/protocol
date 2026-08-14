package resolvers

// The per-domain offer-key cache, tested from inside the package.
//
// Eviction itself is pinned once on the shared bounded map this cache is built
// from. What is left here is the resolver's own layer: that it is bounded at all,
// and that a refresh of a known domain does not consume a second slot.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// oneKeyDirectory returns a fetcher that answers every domain with a directory
// carrying one window-active key, so a Resolve reaches the cache write.
func oneKeyDirectory(t *testing.T, now time.Time) OfferDirectoryFetcher {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := &rampv1.WBAFile{Keys: []*rampv1.JsonWebKey{{
		Kty:       "OKP",
		Crv:       "Ed25519",
		Use:       "sig",
		Alg:       "EdDSA",
		X:         base64.RawURLEncoding.EncodeToString(pub),
		NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  now.Add(time.Hour).UTC().Format(time.RFC3339),
	}}}
	return func(context.Context, string) (*rampv1.WBAFile, error) { return dir, nil }
}

func TestOfferKeyCache_IsBoundedAtTheCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := NewCachedOfferKeyResolver(CachedOfferKeyResolverConfig{
		Fetch: oneKeyDirectory(t, now),
		TTL:   time.Hour,
		Now:   func() time.Time { return now },
	})
	for i := range maxCachedOfferKeys + 10 {
		if _, err := r.Resolve(context.Background(), fmt.Sprintf("ex%d.test", i)); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	// EXACTLY the cap, not merely at-or-under it: this is what pins that the
	// resolver passed its own constant to the shared cache rather than some other
	// bound. Ordering is pinned once, on the shared type.
	if got := r.cache.Len(); got != maxCachedOfferKeys {
		t.Errorf("cache size = %d, want exactly %d", got, maxCachedOfferKeys)
	}
}

// Re-resolving a known domain after its TTL lapses refreshes it in place rather
// than consuming a second slot — otherwise every refresh would evict an unrelated
// exchange.
func TestOfferKeyCache_RefreshingAKnownDomainKeepsOneSlot(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := NewCachedOfferKeyResolver(CachedOfferKeyResolverConfig{
		Fetch: oneKeyDirectory(t, now),
		TTL:   time.Minute,
		Now:   func() time.Time { return now },
	})
	if _, err := r.Resolve(context.Background(), "ex.test"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	now = now.Add(2 * time.Minute) // expire the entry, forcing the write path again
	if _, err := r.Resolve(context.Background(), "ex.test"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := r.cache.Len(); got != 1 {
		t.Errorf("cache size = %d, want 1", got)
	}
}
