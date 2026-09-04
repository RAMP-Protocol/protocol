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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// loopbackManifestServer stands up an Exchange that advertises ITSELF in its
// well-known manifest and serves everything else from rest.
//
// The manifest route and the late-bound origin are the same five lines wherever a
// test drives the offer-derived leg; only the catch-all differs — a redirect, a
// refusal, a real RPC handler. Parameterising the catch-all is what keeps the
// self-advertising part from being retyped per test, where it can quietly drift
// into advertising something else.
//
// Returns the BARE domain, which is what a UsageReport carries: the exchange
// field names a domain, never an origin.
// It also returns the well-known FETCH COUNT, which is how the caching tests tell
// a second resolve that hit the cache from one that went back to the network.
func loopbackManifestServer(t *testing.T, rest http.Handler) (string, *atomic.Int64) {
	t.Helper()
	return loopbackManifestServerWith(t, rest, nil)
}

// loopbackManifestServerWith is the same server with extra manifest members —
// terms_digest and the account_registration block, which the account verbs read
// and nothing else does. The extras are read per request rather than captured, so
// a test can revise the served document between calls and prove a read went back
// to the network.
//
// The body always names the Exchange role, because a real manifest does: the
// contract makes the field required, and the registration reader refuses a
// document that omits it.
func loopbackManifestServerWith(
	t *testing.T, rest http.Handler, extra func() map[string]any,
) (string, *atomic.Int64) {
	t.Helper()
	var (
		hits   atomic.Int64
		origin string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ramp.json", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		doc := map[string]any{
			"ver":      helpers.WellKnownManifestVersion,
			"endpoint": origin,
			"role":     "ROLE_EXCHANGE",
		}
		if extra != nil {
			for k, v := range extra() {
				doc[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.Handle("/", rest)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	origin = srv.URL
	return strings.TrimPrefix(srv.URL, "http://"), &hits
}

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
