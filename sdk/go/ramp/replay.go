package ramp

import (
	"context"
	"time"
)

// ReplayStore is the narrow nonce-dedup interface the SERVER verify face
// orchestrates over. The SDK owns the replay-CHECK control-flow (it calls SeenOrAdd
// at the correct point in fail-closed verification, so replay protection is on by
// default), but owns NO replay state, TTL, or persistence — the application SUPPLIES
// the store and its TTL policy. This is the KeyResolver-shaped middle: the SDK
// orchestrates over injected state, exactly as it resolves keys over an injected
// KeyResolver without owning keys (ADR-020 §3 / Core Invariant; architect-review
// amendment MEDIUM-2).
//
// It lives in package ramp (not rampconnect) so the client and server faces share
// one interface name and an app defines its store once for both.
type ReplayStore interface {
	// SeenOrAdd reports whether nonce was already recorded (a replay → true) and
	// records it with ttl when it is new (→ false). The SDK decides WHEN to call it;
	// the app decides HOW long a nonce is remembered.
	SeenOrAdd(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
}
