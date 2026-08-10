package resolvers

// The per-host endpoint cache's bound, tested from inside the package.
//
// The bound has no public observable other than a fetch count, and a fetch count
// cannot tell an eviction from a TTL expiry. The bound itself is the security
// property worth pinning: the key is an Offer.exchange host, so the key space is
// open-ended and caller-influenced.

import (
	"fmt"
	"testing"
	"time"
)

// storeOnly builds a resolver with no HTTP client: these tests drive the cache
// directly, so nothing dials.
func storeOnly(t *testing.T) *WellKnownEndpointResolver {
	t.Helper()
	return NewWellKnownEndpointResolver(WellKnownOptions{TTL: time.Hour})
}

func TestEndpointCache_EvictsLeastRecentlyUsedAtTheCap(t *testing.T) {
	r := storeOnly(t)

	// Fill the cache exactly to the cap.
	for i := range maxCachedEndpoints {
		r.store(fmt.Sprintf("ex%d.test", i), "https://ep.test")
	}
	if got := r.size(); got != maxCachedEndpoints {
		t.Fatalf("cache size = %d, want %d", got, maxCachedEndpoints)
	}

	// Read the oldest entry so it becomes the most recently used. If eviction were
	// "drop the whole map", this would not survive the next insert — and which
	// entries survived would be a function of the order a caller named hosts,
	// which is a property the caller controls.
	const oldest = "ex0.test"
	if _, ok := r.cached(oldest); !ok {
		t.Fatalf("%s should still be cached", oldest)
	}

	r.store("overflow.test", "https://ep.test")

	if got := r.size(); got != maxCachedEndpoints {
		t.Errorf("cache size = %d, want the cap to hold at %d", got, maxCachedEndpoints)
	}
	if !r.holds(oldest) {
		t.Error("the most-recently-used host was evicted; eviction must be least-recently-used")
	}
	if !r.holds("overflow.test") {
		t.Error("the newly stored host is missing")
	}
	// ex1 was the least recently used once ex0 was read.
	if r.holds("ex1.test") {
		t.Error("the least-recently-used host survived; it should have been evicted")
	}
}

// Re-storing a known host refreshes it in place rather than consuming a second
// slot — otherwise every TTL refresh would evict an unrelated host.
func TestEndpointCache_RefreshingAKnownHostKeepsOneSlot(t *testing.T) {
	r := storeOnly(t)
	r.store("ex.test", "https://one.test")
	r.store("ex.test", "https://two.test")
	if got := r.size(); got != 1 {
		t.Errorf("cache size = %d, want 1", got)
	}
	ep, ok := r.cached("ex.test")
	if !ok || ep != "https://two.test" {
		t.Errorf("cached = %q/%v, want the refreshed endpoint", ep, ok)
	}
}

// A stale entry is not returned, and the slot it holds is reclaimable — the cache
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
	// The slot is still accounted for, and a fresh store reuses it rather than
	// growing the cache.
	r.store("ex.test", "https://two.test")
	if got := r.size(); got != 1 {
		t.Errorf("cache size = %d, want the expired slot reused", got)
	}
}
