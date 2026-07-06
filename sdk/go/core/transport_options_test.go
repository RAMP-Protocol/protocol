package core_test

// TDD-red suite for the new SigningTransport options and the sigwindow
// constructors (yxaeb Step 1). Every test MUST fail today because the API
// does not exist yet — the compile error is the red state.
//
// Behavioral expectations are ported from:
//   - internal/signingtransport/transport.go  (WithAppendSigner, Signature-Agent
//     set-if-absent, path predicate, window injection)
//   - internal/sigwindow/window.go             (ClockWindow, MonotonicWindow)
//
// Transport-neutrality rule (TestCoreConnectrpcFree): this file imports NO
// connectrpc.com/* — core must stay Connect-free.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// ---------------------------------------------------------------------------
// Test doubles / factories.
// ---------------------------------------------------------------------------

// captureTransport records the last request it forwarded so tests can inspect
// headers stamped by the signing transport without needing a real server.
type captureTransport struct {
	req *http.Request
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req.Clone(req.Context())
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

// bodiedRequest builds a minimal POST request with a non-empty body directed
// at the given path. The body must be non-nil for the signing transport to sign.
func bodiedRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example.com"+path,
		io.NopCloser(bytes.NewReader([]byte(`{"test":true}`))))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header = make(http.Header)
	return req
}

// testSigner returns a fresh signing keypair and its helpers.Signer for use in
// tests. The keyID is derived from the thumbprint so the signer is realistically
// constructed (not a fake string).
func testSigner(t *testing.T) helpers.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyID, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// fixedWindow returns a core.Window that always supplies the same pair of
// unix-seconds values. Used to assert that WithWindow injects the supplied
// values into the emitted Signature-Input.
func fixedWindow(created, expires int64) core.Window {
	return func() (int64, int64) { return created, expires }
}

// ---------------------------------------------------------------------------
// (a) WithWindow — injects created/expires into the produced Signature-Input.
// ---------------------------------------------------------------------------

// TestWithWindow_InjectsCreatedExpiresIntoSignatureInput pins that a transport
// constructed with WithWindow(fixedWindow(c,e)) produces a Signature-Input
// header whose created and expires values match c and e respectively.
func TestWithWindow_InjectsCreatedExpiresIntoSignatureInput(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	const wantCreated int64 = 1_700_000_000
	const wantExpires int64 = 1_700_000_300

	tr := core.NewSigningTransport(testSigner(t), cap,
		core.WithWindow(fixedWindow(wantCreated, wantExpires)),
	)

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	sigInput := cap.req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("Signature-Input must be present on a signed /ramp.* request")
	}
	wantC := `created=1700000000`
	wantE := `expires=1700000300`
	if !strings.Contains(sigInput, wantC) {
		t.Errorf("Signature-Input = %q; want it to contain %q", sigInput, wantC)
	}
	if !strings.Contains(sigInput, wantE) {
		t.Errorf("Signature-Input = %q; want it to contain %q", sigInput, wantE)
	}
}

// ---------------------------------------------------------------------------
// (b) WithAppendSigner — always appends regardless of existing Signature.
// ---------------------------------------------------------------------------

// TestWithAppendSigner_AppendsSigOnPreSignedRequest pins that a transport built
// with WithAppendSigner always calls helpers.AppendSignature — even on a
// request that already carries an incoming Signature header — so the relayed
// chain grows by one, never replacing sig1.
func TestWithAppendSigner_AppendsSigOnPreSignedRequest(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithAppendSigner())

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	// Pre-stamp a synthetic sig1 to simulate a relayed request.
	req.Header.Set("Signature-Input", `sig1=("@method" "@target-uri");created=1700000000`)
	req.Header.Set("Signature", `sig1=:AAAA:`)
	req.Header.Set("Content-Digest", "sha-256=:AAAA:")

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	sigInput := cap.req.Header.Get("Signature-Input")
	sig := cap.req.Header.Get("Signature")
	// AppendSignature produces sig2; both sig1= and sig2= must appear.
	if !strings.Contains(sigInput, "sig1=") {
		t.Errorf("Signature-Input = %q; original sig1= must be preserved", sigInput)
	}
	if !strings.Contains(sigInput, "sig2=") {
		t.Errorf("Signature-Input = %q; appended sig2= must be present", sigInput)
	}
	if !strings.Contains(sig, "sig1=") || !strings.Contains(sig, "sig2=") {
		t.Errorf("Signature = %q; must contain both sig1 and sig2", sig)
	}
}

// TestWithAppendSigner_AppendsSigOnFreshRequest pins that WithAppendSigner on a
// fresh (unsigned) request still produces a valid sig1 — AppendSignature
// degrades to a fresh sig1 when no incoming signature is present.
func TestWithAppendSigner_AppendsSigOnFreshRequest(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithAppendSigner())

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	sigInput := cap.req.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, "sig1=") {
		t.Errorf("Signature-Input = %q; fresh AppendSigner request must produce sig1", sigInput)
	}
}

// ---------------------------------------------------------------------------
// (c) WithSignatureAgent — set-if-absent; preserves existing header.
// ---------------------------------------------------------------------------

// TestWithSignatureAgent_SetsHeaderWhenAbsent pins that a transport built with
// WithSignatureAgent("https://broker.example.com") stamps the Signature-Agent
// header when the request does not already carry one, so the directory origin
// is in the covered component set.
func TestWithSignatureAgent_SetsHeaderWhenAbsent(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	const dir = "https://broker.example.com"
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(dir))

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	got := cap.req.Header.Get("Signature-Agent")
	if got != dir {
		t.Errorf("Signature-Agent = %q; want %q (set-if-absent must stamp the directory)", got, dir)
	}
}

// TestWithSignatureAgent_PreservesExistingHeader pins that a transport built
// with WithSignatureAgent does NOT overwrite a Signature-Agent header that the
// originating agent already set — the relay must not clobber the agent's header,
// which is covered by sig1 and would break sig1 verification at the Exchange.
func TestWithSignatureAgent_PreservesExistingHeader(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap,
		core.WithSignatureAgent("https://broker.example.com"),
	)

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	const agentDir = "https://agent.example.com"
	req.Header.Set("Signature-Agent", agentDir)

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	got := cap.req.Header.Get("Signature-Agent")
	if got != agentDir {
		t.Errorf("Signature-Agent = %q; want %q (originating agent's header must be preserved)", got, agentDir)
	}
}

// ---------------------------------------------------------------------------
// (d) WithSignPredicate — skips signing when predicate returns false.
// ---------------------------------------------------------------------------

// TestWithSignPredicate_SkipsSigningWhenFalse pins that a transport built with
// WithSignPredicate(neverSign) passes the request through unsigned when the
// predicate returns false, regardless of path or body presence.
func TestWithSignPredicate_SkipsSigningWhenFalse(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	neverSign := func(_ *http.Request) bool { return false }
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignPredicate(neverSign))

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Input"); got != "" {
		t.Errorf("Signature-Input = %q; want empty — predicate returned false so request must NOT be signed", got)
	}
}

// TestWithSignPredicate_SignsWhenTrue pins that a transport built with
// WithSignPredicate(alwaysSign) signs even a path that the default predicate
// would not sign (i.e. a non-/ramp.* path).
func TestWithSignPredicate_SignsWhenTrue(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	alwaysSign := func(_ *http.Request) bool { return true }
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignPredicate(alwaysSign))

	// /other.* path — default behavior would skip it, but predicate overrides.
	req := bodiedRequest(t, "/other.service/Method")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Input"); got == "" {
		t.Errorf("Signature-Input is empty; predicate returned true so request MUST be signed")
	}
}

// (e, compat) Default (no option) signs any bodied request — compat pin.
// ---------------------------------------------------------------------------

// TestDefaultBehavior_SignsBodiedRequest pins that a transport constructed with
// NO options still signs any bodied request, preserving the pre-option compat
// contract. This is the fail-open guard: adding new options must NOT change the
// default behavior.
func TestDefaultBehavior_SignsBodiedRequest(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap) // zero options

	req := bodiedRequest(t, "/ramp.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Input"); got == "" {
		t.Error("Signature-Input must be present on a bodied request with the default (no-option) transport")
	}
}

// ---------------------------------------------------------------------------
// (e) ClockWindow / MonotonicWindow semantics.
// ---------------------------------------------------------------------------

// TestClockWindow_TTLArithmetic pins that ClockWindow(now, ttl) returns
// created = now.Unix() and expires = now.Unix()+ttl.Seconds() — both derived
// from a single clock reading so created <= expires.
func TestClockWindow_TTLArithmetic(t *testing.T) {
	t.Parallel()
	const ttl = 5 * time.Minute
	fixed := time.Unix(1_700_000_000, 0)
	w := core.ClockWindow(func() time.Time { return fixed }, ttl)

	created, expires := w()
	if created != fixed.Unix() {
		t.Errorf("created = %d; want %d (now.Unix)", created, fixed.Unix())
	}
	wantExpires := fixed.Unix() + int64(ttl.Seconds())
	if expires != wantExpires {
		t.Errorf("expires = %d; want %d (now.Unix + ttl)", expires, wantExpires)
	}
}

// TestMonotonicWindow_UniqueUnderRepeatedCallsWithinSameSecond pins that
// MonotonicWindow's expires is strictly increasing across back-to-back calls
// even when the wall clock does not advance — no two calls in the same second
// share the same expires value, so identical relay requests do not collide in
// the server's replay store.
func TestMonotonicWindow_UniqueUnderRepeatedCallsWithinSameSecond(t *testing.T) {
	t.Parallel()
	const ttl = 5 * time.Minute
	// Freeze the clock so every call lands in the "same second" scenario.
	frozen := time.Unix(1_700_000_000, 0)
	w := core.MonotonicWindow(func() time.Time { return frozen }, ttl)

	_, expires1 := w()
	_, expires2 := w()
	_, expires3 := w()

	if expires2 <= expires1 {
		t.Errorf("call 2 expires=%d must be > call 1 expires=%d (monotonic uniqueness)", expires2, expires1)
	}
	if expires3 <= expires2 {
		t.Errorf("call 3 expires=%d must be > call 2 expires=%d (monotonic uniqueness)", expires3, expires2)
	}
}

// TestMonotonicWindow_CreatedTracksWallClock pins that the created value still
// tracks now() even when the monotonic bump adjusts expires upward — the
// created/expires pair stays clock-consistent for callers that read created.
func TestMonotonicWindow_CreatedTracksWallClock(t *testing.T) {
	t.Parallel()
	const ttl = 5 * time.Minute
	frozen := time.Unix(1_700_000_000, 0)
	w := core.MonotonicWindow(func() time.Time { return frozen }, ttl)

	created, _ := w()
	if created != frozen.Unix() {
		t.Errorf("created = %d; want %d (clock-consistent, tracks now)", created, frozen.Unix())
	}
}
