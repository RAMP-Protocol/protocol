package connect

import (
	"fmt"
	"net/http"
	"testing"
)

// The per-origin client pool, tested from inside the package.
//
// Eviction has no public observable other than a dial count, and counting dials
// would mean mocking the transport — which the suite's doctrine forbids. The
// bound itself is the security property worth pinning: which Exchanges appear is
// driven by incoming offers, so the key space is open-ended and
// caller-influenced.

func TestExchangePool_EvictsLeastRecentlyUsedAtTheCap(t *testing.T) {
	pool := newExchangePool(&http.Client{})

	// Fill the pool exactly to the cap.
	for i := range maxPooledExchanges {
		pool.clientFor(fmt.Sprintf("https://ex%d.test", i))
	}
	if got := pool.size(); got != maxPooledExchanges {
		t.Fatalf("pool size = %d, want %d", got, maxPooledExchanges)
	}

	// Touch the oldest entry so it becomes the most recently used. If eviction
	// were "drop the whole map", this would not survive the next insert — and
	// which entries survived would be a function of the order a caller named
	// hosts, which is a property the caller controls.
	const oldest = "https://ex0.test"
	pool.clientFor(oldest)

	pool.clientFor("https://overflow.test")

	if got := pool.size(); got != maxPooledExchanges {
		t.Errorf("pool size = %d, want the cap to hold at %d", got, maxPooledExchanges)
	}
	if !pool.holds(oldest) {
		t.Error("the most-recently-used origin was evicted; eviction must be least-recently-used")
	}
	if !pool.holds("https://overflow.test") {
		t.Error("the newly inserted origin is missing")
	}
	// ex1 was the least recently used once ex0 was touched.
	if pool.holds("https://ex1.test") {
		t.Error("the least-recently-used origin survived; it should have been evicted")
	}
}

// A cached origin returns the same client rather than re-dialing plumbing.
func TestExchangePool_ReusesTheClientForAKnownOrigin(t *testing.T) {
	pool := newExchangePool(&http.Client{})
	first := pool.clientFor("https://ex.test")
	second := pool.clientFor("https://ex.test")
	if first != second {
		t.Error("a known origin must reuse its cached client")
	}
	if got := pool.size(); got != 1 {
		t.Errorf("pool size = %d, want 1", got)
	}
}
