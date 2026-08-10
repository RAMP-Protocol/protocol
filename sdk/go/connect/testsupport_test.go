package connect_test

// Shared test support for the sdk/go L2 connect suite: an in-memory ReplayStore
// test-double and a timestamp helper. The ReplayStore double implements the SDK's
// injected core.ReplayStore interface — it is an APPLICATION-supplied dependency
// the SDK orchestrates over (the KeyResolver-shaped middle), NOT a mock of the
// code under test. The SDK owns the replay-check control-flow; the app owns the
// store and its TTL policy (ADR-020 §3 / Core Invariant). Relocated verbatim from
// sdk/go/ramp on the core/connect split (ramp.ReplayStore → core.ReplayStore).

import (
	"context"
	"sync"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// memReplayStore is a minimal in-memory nonce store: SeenOrAdd reports whether a
// nonce has been observed and records it if not. It ignores TTL expiry (a test
// double); the SDK owns WHEN SeenOrAdd is called in fail-closed verification.
type memReplayStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newMemReplayStore() *memReplayStore {
	return &memReplayStore{seen: map[string]struct{}{}}
}

// SeenOrAdd returns true when nonce was already recorded (a replay), false when
// it is new (and records it). It satisfies the SDK's injected core.ReplayStore.
func (m *memReplayStore) Seen(_ context.Context, nonce string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[nonce]
	return ok, nil
}

func (m *memReplayStore) SeenOrAdd(_ context.Context, nonce string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[nonce]; ok {
		return true, nil
	}
	m.seen[nonce] = struct{}{}
	return false, nil
}

// Compile-time assertion that the double satisfies the injected SDK interface.
var _ core.ReplayStore = (*memReplayStore)(nil)

func timestampProto(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}

// testRequester is the agent identity the execute path requires. A purchase
// carries a detached acceptance covering the requester, so a client that has not
// been told who it is cannot buy — these tests supply one the way an application
// would.
func testRequester() *rampv1.Requester {
	return &rampv1.Requester{
		Id:     "https://agent.test",
		Domain: "agent.test",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
}
