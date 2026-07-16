package resolvers_test

// wellknownkeyresolver_singleflight_test.go — single-flight coalescing parity for
// the WellKnownKeyResolver JWKS fetch. Mirrors the WBA concurrent-refresh test
// (wbakeyresolver_debounce_test.go) and the TS/Python coalescing cases: a
// fetch-COUNTING origin holds the leader's response on a gate while a concurrent
// burst of cold resolves piles onto the resolver's fetchSingle mutex, so the whole
// burst produces exactly ONE outbound JWKS GET.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// gatedJwksOrigin serves a single JWKS document and counts every fetch, with an
// optional gate that holds each response in-flight until released (and an arrived
// signal per blocked arrival) so a concurrent burst's single-flight coalescing is
// observable — the JWKS analogue of the WBA countingOrigin (kept distinct so the
// two live in the same test package without colliding).
type gatedJwksOrigin struct {
	*httptest.Server
	doc     atomic.Pointer[[]byte]
	hits    atomic.Int32
	gate    chan struct{} // if non-nil, each response blocks until closed
	arrived chan struct{} // if non-nil, receives one value per arrival
}

func newGatedJwksOrigin() *gatedJwksOrigin {
	o := &gatedJwksOrigin{}
	o.Server = httptest.NewServer(http.HandlerFunc(o.serve))
	return o
}

func (o *gatedJwksOrigin) serve(w http.ResponseWriter, _ *http.Request) {
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

func (o *gatedJwksOrigin) setKey(kid string, pub ed25519.PublicKey) {
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{Keys: []map[string]string{{
		"kid": kid,
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}}}
	b, _ := json.Marshal(doc)
	o.doc.Store(&b)
}

func (o *gatedJwksOrigin) count() int32 { return o.hits.Load() }

// TestWellKnownKeyResolver_ConcurrentRefreshSingleflight pins the single-flight
// bound: a concurrent burst of resolves whose JWKS cache is cold coalesces to
// exactly ONE outbound fetch. The origin holds the leader's fetch on a gate; the
// followers park on fetchSingle until the leader fills the cache, so the whole
// burst produces a single GET.
func TestWellKnownKeyResolver_ConcurrentRefreshSingleflight(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	origin := newGatedJwksOrigin()
	defer origin.Close()
	origin.setKey("ex.v1", pub)
	origin.gate = make(chan struct{})
	origin.arrived = make(chan struct{}, 1)

	r := resolvers.NewWellKnownKeyResolver(origin.URL, resolvers.WellKnownOptions{
		HTTP: origin.Client(),
		TTL:  time.Hour,
		Now:  func() time.Time { return wbaAnchor },
	})

	const burst = 12
	var wg sync.WaitGroup
	errs := make([]error, burst)
	got := make([]ed25519.PublicKey, burst)
	for i := range burst {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = r.Resolve(context.Background(), "ex.v1")
		}(i)
	}

	// The leader is parked in the origin holding fetchSingle; the followers coalesce
	// onto it. Release only after the leader has arrived.
	<-origin.arrived
	close(origin.gate)
	wg.Wait()

	for i := range burst {
		if errs[i] != nil {
			t.Fatalf("concurrent resolve[%d]: %v", i, errs[i])
		}
		if !got[i].Equal(pub) {
			t.Fatalf("concurrent resolve[%d] returned the wrong key", i)
		}
	}
	if c := origin.count(); c != 1 {
		t.Fatalf("a concurrent burst of %d cold resolves must singleflight to exactly 1 JWKS fetch; got %d",
			burst, c)
	}
}
