package connect_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// The knobs the tier below `connect` already had and the client had no way to
// reach. Each is asserted on the WIRE — the bytes the peer sees, or the outcome a
// bound produces — because an assertion that an option set a field would pass
// against a client that then dropped it, which is the defect these close.

// A supplied signing window reaches the emitted Signature-Input, so a deployment
// with its own freshness policy gets the TTL it configured rather than the SDK's
// five-minute default. The response is deliberately not a valid Connect reply:
// the request has already been signed and sent by the time it is read, which is
// the only thing under test.
func TestWithSignWindow_ReachesTheEmittedSignature(t *testing.T) {
	const created, expires = 1_700_000_000, 1_700_000_030

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Signature-Input")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sig := newSigningFixture(t)
	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithSignWindow(func() (int64, int64) { return created, expires }),
	)
	// The call fails at the response; the signature was already on the wire.
	_, _ = client.Discover(context.Background(), &rampv1.ResourceQuery{Uris: []string{"https://a.test/x"}})

	if got == "" {
		t.Fatal("no Signature-Input reached the peer; the request was not signed")
	}
	for _, want := range []string{"created=1700000000", "expires=1700000030"} {
		if !strings.Contains(got, want) {
			t.Errorf("Signature-Input = %q, want it to carry %s", got, want)
		}
	}
}

// Without the option the SDK's own default still applies, so the window is a
// default and not a requirement.
func TestSignWindow_DefaultsWhenUnset(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Signature-Input")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sig := newSigningFixture(t)
	client := rampconnect.NewClient(srv.URL, rampconnect.WithSigner(sig.signer))
	_, _ = client.Discover(context.Background(), &rampv1.ResourceQuery{Uris: []string{"https://a.test/x"}})

	if !strings.Contains(got, "created=") || !strings.Contains(got, "expires=") {
		t.Errorf("Signature-Input = %q, want a stamped window from the default", got)
	}
}

// A supplied body cap is what the fetch enforces. Asserted through the refusal a
// too-large body produces, because the fetcher exposes no getter — deliberately,
// so a test cannot pass by reading back what it just set.
func TestWithMaxContentBytes_BoundsTheFetchedBody(t *testing.T) {
	body := strings.Repeat("x", 512)
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer content.Close()

	sig := newSigningFixture(t)
	opts := append(allowLoopback(t),
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithAgentKey(sig.pub),
		rampconnect.WithMaxContentBytes(16),
	)
	client := rampconnect.NewClient("http://home.invalid", opts...)

	_, err := client.Fetch(context.Background(), content.URL+"/doc")
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallTooLarge {
		t.Errorf("kind = %v, want CallTooLarge under a 16-byte cap", cerr.Kind)
	}

	// The same body under the default cap succeeds, so the refusal above is the
	// supplied bound rather than something else about the response.
	relaxed := append(allowLoopback(t),
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithAgentKey(sig.pub),
	)
	if _, err := rampconnect.NewClient("http://home.invalid", relaxed...).
		Fetch(context.Background(), content.URL+"/doc"); err != nil {
		t.Fatalf("the same body under the default cap must succeed: %v", err)
	}
}

// A supplied fetch deadline is what bounds the call. The handler outlives it, so
// a client that ignored the option would block for the 30-second default and the
// test would time out rather than fail.
func TestWithContentTimeout_BoundsTheFetch(t *testing.T) {
	release := make(chan struct{})
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer content.Close()
	defer close(release)

	sig := newSigningFixture(t)
	opts := append(allowLoopback(t),
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithAgentKey(sig.pub),
		rampconnect.WithContentTimeout(50*time.Millisecond),
	)
	client := rampconnect.NewClient("http://home.invalid", opts...)

	start := time.Now()
	_, err := client.Fetch(context.Background(), content.URL+"/doc")
	if err == nil {
		t.Fatal("a fetch past its deadline must fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("fetch took %v; the supplied deadline was not applied", elapsed)
	}
}

// An idempotency key the caller put ON THE MESSAGE survives to the wire.
//
// The middle tier of the precedence rule, and the one with consequences: minting
// a default is intended, but overwriting a value the caller chose turns each of
// their retries into a fresh action, which is the double-counting the field
// exists to prevent. Fresh-mint and the per-call option are covered elsewhere;
// this is the branch a regression to "always mint" would slip past.
func TestReportUsage_KeepsAKeyTheCallerPutOnTheMessage(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &groupExchange{}
	domain, _ := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	const own = "app-owned-key-1"
	report := &rampv1.UsageReport{
		Exchange:       domain,
		TransactionId:  "txn-1",
		IdempotencyKey: own,
	}
	if _, err := client.ReportUsage(context.Background(), report); err != nil {
		t.Fatalf("ReportUsage: %v", err)
	}
	if got := origin.gotReport.GetIdempotencyKey(); got != own {
		t.Errorf("idempotency key = %q, want the caller's own %q", got, own)
	}
}

// A supplied proof window reaches the delivery request's signature, so the
// freshness of a bound fetch is the caller's policy rather than the SDK's
// 30-second default.
func TestWithProofWindow_ReachesTheFetchSignature(t *testing.T) {
	const created, expires = 1_700_000_000, 1_700_000_045

	var got string
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Signature-Input")
		_, _ = w.Write([]byte("bytes"))
	}))
	defer content.Close()

	sig := newSigningFixture(t)
	opts := append(allowLoopback(t),
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithAgentKey(sig.pub),
		rampconnect.WithProofWindow(func() (int64, int64) { return created, expires }),
	)
	if _, err := rampconnect.NewClient("http://home.invalid", opts...).
		Fetch(context.Background(), content.URL+"/doc"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, want := range []string{"created=1700000000", "expires=1700000045"} {
		if !strings.Contains(got, want) {
			t.Errorf("proof Signature-Input = %q, want it to carry %s", got, want)
		}
	}
}

// Without the option the proof still carries a window, so it is a default rather
// than something a caller must supply to fetch at all.
func TestProofWindow_DefaultsWhenUnset(t *testing.T) {
	var got string
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Signature-Input")
		_, _ = w.Write([]byte("bytes"))
	}))
	defer content.Close()

	sig := newSigningFixture(t)
	opts := append(allowLoopback(t),
		rampconnect.WithSigner(sig.signer), rampconnect.WithAgentKey(sig.pub))
	if _, err := rampconnect.NewClient("http://home.invalid", opts...).
		Fetch(context.Background(), content.URL+"/doc"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(got, "created=") || !strings.Contains(got, "expires=") {
		t.Errorf("proof Signature-Input = %q, want a stamped window from the default", got)
	}
}

// The defaults the two options move are the resolvers tier's own, so a caller
// reading either constant gets the value the client actually runs with.
func TestContentBounds_DefaultToTheResolversTierValues(t *testing.T) {
	if resolvers.DefaultContentTimeout != 30*time.Second {
		t.Errorf("DefaultContentTimeout = %v", resolvers.DefaultContentTimeout)
	}
	if resolvers.DefaultMaxContentBytes != 8<<20 {
		t.Errorf("DefaultMaxContentBytes = %d", resolvers.DefaultMaxContentBytes)
	}
}
