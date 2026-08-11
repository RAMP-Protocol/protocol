package lrucache_test

import (
	"fmt"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/internal/lrucache"
)

// The bound is the security property worth pinning: both callers key on a host an
// incoming offer named, so the key space is open-ended and caller-influenced.
//
// One test now covers what two near-identical copies covered before, which is the
// point of having one implementation.

func TestCache_EvictsLeastRecentlyUsedAtTheCap(t *testing.T) {
	const cap = 8
	c := lrucache.New[string, int](cap)

	for i := range cap {
		c.Put(fmt.Sprintf("k%d", i), i)
	}
	if got := c.Len(); got != cap {
		t.Fatalf("Len() = %d, want %d", got, cap)
	}

	// Read the oldest so it becomes the most recently used. If eviction were
	// "drop the whole map", this would not survive the next insert — and which
	// entries survived would be a function of the order a caller named keys.
	if _, ok := c.Get("k0"); !ok {
		t.Fatal("k0 should still be held")
	}

	c.Put("overflow", 99)

	if got := c.Len(); got != cap {
		t.Errorf("Len() = %d, want the cap to hold at %d", got, cap)
	}
	if !c.Has("k0") {
		t.Error("the most-recently-used key was evicted; eviction must be least-recently-used")
	}
	if !c.Has("overflow") {
		t.Error("the newly stored key is missing")
	}
	if c.Has("k1") {
		t.Error("the least-recently-used key survived; it should have been evicted")
	}
}

// Re-putting a known key refreshes it in place rather than consuming a second
// slot — otherwise every TTL refresh would evict an unrelated entry.
func TestCache_PutOnAKnownKeyKeepsOneSlot(t *testing.T) {
	c := lrucache.New[string, string](4)
	c.Put("a", "one")
	c.Put("a", "two")
	if got := c.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
	if v, ok := c.Get("a"); !ok || v != "two" {
		t.Errorf("Get() = %q/%v, want the refreshed value", v, ok)
	}
}

// GetOrCreate builds once per key and reuses thereafter — the pool's contract,
// where the value is transport plumbing that must not be rebuilt per call.
func TestCache_GetOrCreateBuildsOncePerKey(t *testing.T) {
	c := lrucache.New[string, *int](4)
	builds := 0
	make := func(string) *int { builds++; n := builds; return &n }

	first := c.GetOrCreate("a", make)
	second := c.GetOrCreate("a", make)
	if first != second {
		t.Error("a known key must reuse its built value")
	}
	if builds != 1 {
		t.Errorf("builds = %d, want the loader to run once", builds)
	}
	if c.GetOrCreate("b", make); builds != 2 {
		t.Errorf("builds = %d, want a fresh key to build", builds)
	}
}

// A cap below one would evict what it just stored, making every lookup a miss.
func TestCache_CapBelowOneStillHoldsAnEntry(t *testing.T) {
	c := lrucache.New[string, int](0)
	c.Put("a", 1)
	if _, ok := c.Get("a"); !ok {
		t.Error("a zero cap must be treated as one, not as a cache that stores nothing")
	}
}
