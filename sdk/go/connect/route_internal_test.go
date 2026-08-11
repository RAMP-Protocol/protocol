package connect

import (
	"net/http"
	"testing"
)

// The per-origin client pool, tested from inside the package.
//
// Eviction itself is pinned once on the shared bounded map this pool is built
// from; what is left to prove here is the wiring — that the pool is bounded at
// all, and that a known origin reuses its client rather than rebuilding the
// plumbing on every call.

func TestExchangePool_ReusesTheClientForAKnownOrigin(t *testing.T) {
	pool := newExchangePool(&http.Client{})
	first := pool.clientFor("https://ex.test")
	second := pool.clientFor("https://ex.test")
	if first != second {
		t.Error("a known origin must reuse its cached client")
	}
	if got := pool.clients.Len(); got != 1 {
		t.Errorf("pool size = %d, want 1", got)
	}
}

// The bound is the security property: which Exchanges appear is driven by
// incoming offers, so the key space is open-ended and caller-influenced.
func TestExchangePool_IsBoundedAtTheCap(t *testing.T) {
	pool := newExchangePool(&http.Client{})
	for i := range maxPooledExchanges + 10 {
		pool.clientFor(string(rune('a'+i%26)) + string(rune('0'+i/26)))
	}
	// EXACTLY the cap, not merely at-or-under it: this is what pins that the
	// pool passed its own constant to the shared cache rather than some other
	// bound. Ordering is pinned once, on the shared type.
	if got := pool.clients.Len(); got != maxPooledExchanges {
		t.Errorf("pool size = %d, want exactly %d", got, maxPooledExchanges)
	}
}
