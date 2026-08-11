package resolvers

// The per-host endpoint cache, tested from inside the package.
//
// Eviction itself is pinned once on the shared bounded map this cache is built
// from. What is left here is the resolver's own layer: that it is bounded at all,
// and that TTL freshness sits correctly on top of a structure that knows nothing
// about time.

import (
	"testing"
	"time"
)

func TestEndpointCache_IsBoundedAtTheCap(t *testing.T) {
	r := NewWellKnownEndpointResolver(WellKnownOptions{TTL: time.Hour})
	for i := range maxCachedEndpoints + 10 {
		r.store(string(rune('a'+i%26))+string(rune('0'+i/26))+".test", "https://ep.test")
	}
	if got := r.cache.Len(); got > maxCachedEndpoints {
		t.Errorf("cache size = %d, want it to hold at %d", got, maxCachedEndpoints)
	}
}

// Re-storing a known host refreshes it in place rather than consuming a second
// slot — otherwise every TTL refresh would evict an unrelated host.
func TestEndpointCache_RefreshingAKnownHostKeepsOneSlot(t *testing.T) {
	r := NewWellKnownEndpointResolver(WellKnownOptions{TTL: time.Hour})
	r.store("ex.test", "https://one.test")
	r.store("ex.test", "https://two.test")
	if got := r.cache.Len(); got != 1 {
		t.Errorf("cache size = %d, want 1", got)
	}
	ep, ok := r.cached("ex.test")
	if !ok || ep != "https://two.test" {
		t.Errorf("cached = %q/%v, want the refreshed endpoint", ep, ok)
	}
}

// A stale entry is not served, and the slot it holds is reclaimable — the cache
// must not pin an expired host forever just because nothing asked for it again.
func TestEndpointCache_StaleEntryIsNotServedAndItsSlotIsReusable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := NewWellKnownEndpointResolver(WellKnownOptions{
		TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	r.store("ex.test", "https://one.test")
	now = now.Add(2 * time.Minute)
	if _, ok := r.cached("ex.test"); ok {
		t.Error("an expired entry was served")
	}
	r.store("ex.test", "https://two.test")
	if got := r.cache.Len(); got != 1 {
		t.Errorf("cache size = %d, want the expired slot reused", got)
	}
}
