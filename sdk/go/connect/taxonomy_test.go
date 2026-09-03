package connect_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// The failure taxonomy, and the branches of it a caller is told to act on.
//
// The two vocabularies are separate types over separate tiers, bridged in one
// place. Nothing enforced that the tokens they share stay the same word, and the
// classifications a caller is told to branch on had no test at all — which is how
// a transient failure could have been reported as a permanent verdict without
// anything going red.

// The shared tokens must stay identical across the two tiers. A caller that logs
// a reason and greps for it should not have to know which tier produced it, and
// the bridge between them maps the classes 1:1 with nothing else holding the
// words together.
func TestFailureTokens_AgreeAcrossTheTwoTiers(t *testing.T) {
	pairs := []struct {
		call  rampconnect.CallErrorKind
		fetch resolvers.FetchFailure
	}{
		{rampconnect.CallRefused, resolvers.FetchRefused},
		{rampconnect.CallUnreachable, resolvers.FetchUnreachable},
		{rampconnect.CallTooLarge, resolvers.FetchTooLarge},
		{rampconnect.CallNotSignable, resolvers.FetchNotSignable},
		{rampconnect.CallMalformed, resolvers.FetchMalformed},
	}
	for _, p := range pairs {
		if got, want := p.call.String(), p.fetch.String(); got != want {
			t.Errorf("token drift: CallErrorKind %q vs FetchFailure %q", got, want)
		}
	}
	// The value outside either set renders the same way too, so an unmapped
	// classification never prints a bare integer.
	if got := rampconnect.CallErrorKind(99).String(); got != "unknown" {
		t.Errorf("unnamed kind = %q, want \"unknown\"", got)
	}
	if got := resolvers.FetchFailure(99).String(); got != "unknown" {
		t.Errorf("unnamed failure = %q, want \"unknown\"", got)
	}
}

// A transient failure to reach the manifest is UNREACHABLE, not a refusal to
// send. The distinction is the whole point of the classification: a caller
// following the documented handling for a refusal would drop a usage report for
// good over a momentary outage.
func TestReportUsage_TransientResolveFailureIsUnreachable(t *testing.T) {
	// A closed port: the manifest fetch fails at the transport, which is exactly
	// the shape of a DNS blip or a restarting Exchange.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	domain := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()

	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
	})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallUnreachable {
		t.Errorf("kind = %v, want CallUnreachable — a transport failure is retryable, "+
			"and reporting it as a refusal tells a caller to give up", cerr.Kind)
	}
}

// An Exchange that answers the manifest but advertises no endpoint is a VERDICT,
// not a transport failure: it was reached, and it has nothing to offer. The
// opposite branch of the same classification.
func TestReportUsage_NoAdvertisedEndpointIsNotSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`)) // a manifest with no endpoint
	}))
	defer srv.Close()

	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      strings.TrimPrefix(srv.URL, "http://"),
		TransactionId: "txn-1",
	})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallNotSent {
		t.Errorf("kind = %v, want CallNotSent — the Exchange answered and advertises nothing", cerr.Kind)
	}
	if !errors.Is(err, resolvers.ErrNoEndpoint) {
		t.Error("the resolver's sentinel must stay reachable through the classification")
	}
}

// A peer that refuses because the response exceeds the read cap surfaces as
// CallTooLarge rather than as a generic refusal, so a caller can tell "raise your
// budget" from "the Exchange said no".
func TestSendError_ResourceExhaustedIsTooLarge(t *testing.T) {
	sig := newSigningFixture(t)
	domain, _ := loopbackManifestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":"resource_exhausted","message":"too big"}`))
	}))

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
	})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallTooLarge {
		t.Errorf("kind = %v, want CallTooLarge for a resource-exhausted peer", cerr.Kind)
	}
	// The Connect error stays reachable underneath, so a caller that wants the
	// code rather than the SDK's class can still get it.
	var connErr *connectrpc.Error
	if !errors.As(err, &connErr) {
		t.Error("the Connect error must stay reachable through the wrapper")
	}
}

// A caller that cancels its own context has not been refused by anyone.
// connect-go stamps CodeCanceled on a locally cancelled call, and reporting that
// as CallRefused would tell the caller the Exchange declined a request the
// Exchange may never have finished reading — a final verdict, invented locally,
// about a peer that said nothing.
func TestSendError_CallerCancellationIsNotARefusal(t *testing.T) {
	sig := newSigningFixture(t)
	release, reached := make(chan struct{}), make(chan struct{})
	var once sync.Once
	domain, _ := loopbackManifestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(reached) })
		<-release
	}))
	// Registered AFTER the server's own cleanup so it runs BEFORE it: Close blocks
	// on the in-flight handler, which is parked on release until this fires.
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-reached // the RPC is on the wire; nothing has answered it
		cancel()
	}()

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)
	_, err := client.ReportUsage(ctx, &rampv1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
	})

	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallUnreachable {
		t.Errorf("kind = %v, want CallUnreachable — the caller gave up; the peer did not refuse", cerr.Kind)
	}
}

// The peer's own sentence reaches a caller as a VALUE, not as something to parse
// back out of a rendered error.
//
// A typed detail's developer message wins when it carries one; otherwise the
// transport envelope's does, because a peer may name a typed reason and leave the
// prose to the transport, and returning an empty string there would drop the only
// sentence that was sent.
func TestCallError_CarriesThePeersSentence(t *testing.T) {
	t.Run("a typed detail's message wins", func(t *testing.T) {
		sig := newSigningFixture(t)
		detail := rampserver.NewErrorDetail(
			"ramp.v1.ExchangeService", "the account is not active", nil)
		refusal := rampserver.AttachDetail(connectrpc.NewError(
			connectrpc.CodeFailedPrecondition, errors.New("envelope prose")), detail)
		domain, _ := selfAdvertisingExchange(t, sig, &recordingAccount{refuse: refusal})

		client := rampconnect.NewClient("http://home.invalid",
			append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)
		_, err := client.GetAccountStatus(context.Background(),
			&rampv1.GetAccountStatusRequest{Exchange: domain})

		assertPeerMessage(t, err, "the account is not active")
	})

	// An answer that did not come from a RAMP service carries no message of its
	// own. The text a transport synthesizes for one is that transport's — connect-go
	// writes a status line where a fetch-based client writes nothing — so carrying
	// it would make the field's value a property of the language. It stays
	// reachable through the cause, where it reads as what it is.
	t.Run("no typed detail leaves it empty", func(t *testing.T) {
		sig := newSigningFixture(t)
		domain, _ := loopbackManifestServer(t, http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"unavailable","message":"draining"}`))
			}))

		client := rampconnect.NewClient("http://home.invalid",
			append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)
		_, err := client.GetAccountStatus(context.Background(),
			&rampv1.GetAccountStatusRequest{Exchange: domain})

		assertPeerMessage(t, err, "")
		// The transport's own account is not lost, only kept out of the field that
		// claims to hold the peer's words.
		if !strings.Contains(err.Error(), "draining") {
			t.Fatalf("the transport's text is gone entirely: %v", err)
		}
	})
}

func assertPeerMessage(t *testing.T, err error, want string) {
	t.Helper()
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("not a typed failure: %v", err)
	}
	if cerr.PeerMessage != want {
		t.Fatalf("peer message = %q, want %q", cerr.PeerMessage, want)
	}
	// The token stays a token: prose never leaks into the field a caller branches
	// on, which is the mistake this SDK has already made once and reverted.
	if strings.Contains(cerr.Reason, " ") {
		t.Fatalf("reason %q is prose, not a machine token", cerr.Reason)
	}
}
