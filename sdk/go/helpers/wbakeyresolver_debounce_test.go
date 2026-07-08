package helpers_test

// wbakeyresolver_debounce_test.go — RAMP-24 anti-amplification: the
// unknown-thumbprint force-refresh is throttled to one directory fetch per
// SyncDebounce window per host, and a concurrent burst coalesces to one
// in-flight fetch via singleflight. Because the resolver runs BEFORE the ed25519
// check and the fetch host is the caller-supplied Signature-Agent, an
// unauthenticated caller must not be able to drive N outbound GETs with N
// unknown-thumbprint requests.
//
// Parity contract (go/ts/python): a fetch-COUNTING origin + an INJECTED clock
// assert the SAME rate/count bound — a burst of N unknown lookups yields a
// bounded (independent-of-N) fetch count; the window resumes after SyncDebounce;
// a concurrent burst singleflights to one fetch. Reuses newSigningKey /
// mustThumbprint / marshalWBA / wbaAnchor / wbaDirPath from
// wbakeyresolver_test.go (same package).

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// ── countingOrigin ───────────────────────────────────────────────────────────

// countingOrigin serves a single WBA directory document and counts every fetch
// of it, so a test can assert HOW MANY outbound directory GETs a burst produced.
// An optional gate blocks each WBA response until released, and arrived signals
// each blocked arrival — together they hold the singleflight leader in-flight so
// a concurrent burst's coalescing is observable.
type countingOrigin struct {
	*httptest.Server
	doc     atomic.Pointer[[]byte]
	hits    atomic.Int32
	gate    chan struct{} // if non-nil, each WBA response blocks until closed
	arrived chan struct{} // if non-nil, receives one value per WBA arrival
}

func newCountingOrigin() *countingOrigin {
	o := &countingOrigin{}
	mux := http.NewServeMux()
	mux.HandleFunc(wbaDirPath, o.serve)
	o.Server = httptest.NewServer(mux)
	return o
}

func (o *countingOrigin) serve(w http.ResponseWriter, _ *http.Request) {
	o.hits.Add(1)
	if o.arrived != nil {
		o.arrived <- struct{}{}
	}
	if o.gate != nil {
		<-o.gate
	}
	p := o.doc.Load()
	if p == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = w.Write(*p)
}

func (o *countingOrigin) setWBA(b []byte) { o.doc.Store(&b) }
func (o *countingOrigin) resetHits()      { o.hits.Store(0) }
func (o *countingOrigin) count() int32    { return o.hits.Load() }

// ── Test: burst bound + window resume ────────────────────────────────────────

// TestWBAKeyResolver_UnknownThumbprintBurstDebounced pins the anti-amplification
// invariant: after the directory is primed, a burst of N unknown-thumbprint
// resolves for one host issues exactly ONE forced directory fetch (independent
// of N), and a further lookup after the SyncDebounce window fetches again.
//
// RED before the fix: the unknown path force-fetches on every miss, so the burst
// yields N (=50) fetches, not 1.
func TestWBAKeyResolver_UnknownThumbprintBurstDebounced(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("known.v1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	knownTP := mustThumbprint(t, priv.Public().(ed25519.PublicKey))

	origin := newCountingOrigin()
	defer origin.Close()
	origin.setWBA(marshalWBA(jwk))

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.URL)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme:       "http",
		TTL:          time.Hour,
		SyncDebounce: 5 * time.Second,
		Now:          func() time.Time { return now },
	})

	// Prime the directory cache with a known key (no force-refresh), then zero the
	// counter so the burst measures only forced fetches.
	if _, err := r.Resolve(ctx, knownTP); err != nil {
		t.Fatalf("prime resolve: %v", err)
	}
	origin.resetHits()

	const burst = 50
	for i := range burst {
		_, err := r.Resolve(ctx, fmt.Sprintf("unknown-thumbprint-%d", i))
		if !errors.Is(err, helpers.ErrUnknownKey) {
			t.Fatalf("burst[%d]: want ErrUnknownKey, got %v", i, err)
		}
	}
	if got := origin.count(); got != 1 {
		t.Fatalf("burst of %d unknown lookups must force exactly 1 directory fetch (anti-amplification); got %d",
			burst, got)
	}

	// Advance past the debounce window (still within TTL): the next unknown lookup
	// is allowed one more forced refresh.
	now = wbaAnchor.Add(6 * time.Second)
	if _, err := r.Resolve(ctx, "unknown-after-window"); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("post-window resolve: want ErrUnknownKey, got %v", err)
	}
	if got := origin.count(); got != 2 {
		t.Fatalf("a lookup after the debounce window must fetch again (count 2); got %d", got)
	}
}

// ── Test: concurrent burst singleflights to one fetch ────────────────────────

// TestWBAKeyResolver_ConcurrentRefreshSingleflight pins the singleflight bound:
// a concurrent burst of resolves for one host whose directory cache is cold
// coalesces to exactly ONE in-flight fetch. The origin holds the leader's fetch
// on a gate; the followers park inside singleflight until the leader completes,
// so the whole burst produces a single outbound GET.
func TestWBAKeyResolver_ConcurrentRefreshSingleflight(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("known.v1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	knownTP := mustThumbprint(t, priv.Public().(ed25519.PublicKey))

	origin := newCountingOrigin()
	defer origin.Close()
	origin.setWBA(marshalWBA(jwk))
	origin.gate = make(chan struct{})
	origin.arrived = make(chan struct{}, 1)

	ctx := helpers.WithSignatureAgent(context.Background(), origin.URL)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		TTL:    time.Hour,
		Now:    func() time.Time { return wbaAnchor },
	})

	const burst = 12
	var wg sync.WaitGroup
	errs := make([]error, burst)
	for i := range burst {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.Resolve(ctx, knownTP)
		}(i)
	}

	// The leader is parked in the origin holding the singleflight slot; the
	// followers coalesce onto it. Release only after the leader has arrived.
	<-origin.arrived
	close(origin.gate)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent resolve[%d]: %v", i, err)
		}
	}
	if got := origin.count(); got != 1 {
		t.Fatalf("a concurrent burst of %d cold resolves must singleflight to exactly 1 fetch; got %d",
			burst, got)
	}
}
