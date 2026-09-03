package core

import (
	"sync/atomic"
	"time"
)

// Window returns the RFC 9421 (created, expires) cutoffs (unix seconds) to
// stamp on the next outbound signature. It is invoked once per signed request.
// Both values matter: SignRequest/AppendSignature receive created and expires
// from the caller — the multisig verifier rejects any signature missing
// created. An implementation may return monotonically increasing values to
// keep each on-the-wire signature unique (the relay's replay-store uniqueness
// need — see MonotonicWindow) or a wall-clock instant plus a fixed TTL
// (ClockWindow); created and expires should derive from the same source so a
// deterministic-clock test stays inside the verifier's freshness window.
type Window func() (created, expires int64)

// ClockWindow returns the plain production Window: it stamps each outbound
// signature with wall-clock-derived created=now() and expires=now()+ttl. Both
// axes come from the single now() reading so created ≤ expires and both land
// in the verifier's window. To adapt an application clock interface with a
// Now() method, pass the method value: ClockWindow(clk.Now, ttl).
func ClockWindow(now func() time.Time, ttl time.Duration) Window {
	return func() (int64, int64) {
		n := now()
		return n.Unix(), n.Add(ttl).Unix()
	}
}

// MonotonicWindow returns a Window whose expires cutoff is strictly increasing
// across calls: it tracks now+ttl but, when a burst of requests lands in the
// same wall-clock second, bumps expires by one second per call so no two
// back-to-back signatures share a (keyid, expires) pair. This keeps identical
// relay requests from colliding in the server's replay store. created tracks
// now() — the pair stays clock-consistent for any caller that reads created.
// Safe for concurrent RoundTrips: the running maximum is held in an atomic
// updated by compare-and-swap. To adapt an application clock interface with a
// Now() method, pass the method value: MonotonicWindow(clk.Now, ttl).
//
// ONE INSTANCE PER CLIENT, never one per call. The running maximum is the whole
// mechanism: a window minted per request starts from zero, cannot see the
// previous signature, and provides exactly none of the uniqueness it was chosen
// for — while still looking correct at the call site.
func MonotonicWindow(now func() time.Time, ttl time.Duration) Window {
	var lastExpires atomic.Int64
	return func() (int64, int64) {
		n := now()
		floor := n.Unix() + int64(ttl.Seconds())
		for {
			prev := lastExpires.Load()
			next := floor
			if prev >= next {
				next = prev + 1
			}
			if lastExpires.CompareAndSwap(prev, next) {
				return n.Unix(), next
			}
		}
	}
}
