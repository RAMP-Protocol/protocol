package connect_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
)

// The transport guarantees the offer-derived leg claims, driven end to end.
//
// These sit apart from the verb tests because the verb tests deliberately opt out
// of the production dial posture to reach a loopback server. The point here is the
// opposite: leave the guard installed and prove it bites.

// fixedEndpoint is an EndpointResolver that answers with one endpoint, so a test
// can drive the dial without standing up a manifest server. It is the seam's
// stated purpose.
type fixedEndpoint struct{ endpoint string }

func (f fixedEndpoint) ResolveEndpoint(_ context.Context, _ string) (string, error) {
	return f.endpoint, nil
}

// A private address is refused at DIAL time even when it passes every routing
// check — the endpoint is anchored to the domain that advertised it, so the
// same-host rule is satisfied and only the address guard stands between a signed
// report and a host inside the caller's own network.
//
// The guard is deliberately NOT disabled here: an option cannot remove it, and
// this test is what proves the leg is guarded at all.
func TestReportUsage_GuardRefusesAPrivateEndpoint(t *testing.T) {
	sig := newSigningFixture(t)
	client := rampconnect.NewClient("https://home.invalid",
		rampconnect.WithSigner(sig.signer),
		// Anchored to the domain, so the check passes: localhost advertises
		// localhost. Only the dial-time address guard can refuse this.
		rampconnect.WithEndpointResolver(fixedEndpoint{endpoint: "https://localhost:1"}),
	)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      proto.String("localhost"),
		TransactionId: "txn-1",
	})
	if err == nil {
		t.Fatal("a signed report to a private address must be refused")
	}
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Errorf("error = %v, want the dial-time address guard to be the refusal", err)
	}
}

// A caller-supplied transport goes UNDER the guard, never in place of it. Passing
// one must not reopen the address guard — that coupling is the whole reason the
// seam takes a base rather than a whole round-tripper.
//
// The TLS-dialer case is the one that matters: net/http prefers a transport's own
// TLS dialer over DialContext on https, which is every RAMP leg, so a base
// carrying one would take the dial past the address pin entirely. An empty base
// cannot express that, which is why it alone proved less than it appeared to.
func TestReportUsage_GuardSurvivesACallerSuppliedTransport(t *testing.T) {
	bases := map[string]*http.Transport{
		"empty": {},
		"custom TLS dialer": {
			DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the point is that this dial must never happen
			},
		},
		"legacy TLS dialer": {
			DialTLS: func(network, addr string) (net.Conn, error) {
				return tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the point is that this dial must never happen
			},
		},
	}
	for name, base := range bases {
		t.Run(name, func(t *testing.T) {
			sig := newSigningFixture(t)
			client := rampconnect.NewClient("https://home.invalid",
				rampconnect.WithSigner(sig.signer),
				rampconnect.WithGuardedBaseTransport(base),
				rampconnect.WithEndpointResolver(fixedEndpoint{endpoint: "https://localhost:1"}),
			)

			_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
				Exchange:      proto.String("localhost"),
				TransactionId: "txn-1",
			})
			if err == nil || !strings.Contains(err.Error(), "SSRF guard") {
				t.Fatalf("error = %v, want the guard still installed under the injected transport", err)
			}
		})
	}
}

// The content fetch is the leg the SDK's own contract names — it "dials only
// through the SSRF-guarded client" — and it shares the same base-transport seam,
// so it inherits the same bypass. A delivery URL names a host another party
// chose, and the request carries a live proof of possession of the agent key, so
// this is the leg where a bypass costs the most.
func TestFetch_GuardSurvivesACallerSuppliedTLSDialer(t *testing.T) {
	sig := newSigningFixture(t)
	content := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal bytes"))
	}))
	defer content.Close()
	tlsCfg := content.Client().Transport.(*http.Transport).TLSClientConfig

	client := rampconnect.NewClient("https://home.invalid",
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithAgentKey(sig.pub),
		rampconnect.WithGuardedBaseTransport(&http.Transport{
			TLSClientConfig: tlsCfg,
			DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial(network, addr, tlsCfg)
			},
		}),
	)

	_, err := client.Fetch(context.Background(), content.URL+"/doc")
	if err == nil {
		t.Fatal("a bound fetch reached a loopback delivery host — the dial guard was bypassed")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Errorf("error = %v, want the dial-time address guard to be the refusal", err)
	}
}

// The client re-checks the endpoint an INJECTED resolver hands back, and it
// applies the whole rule — not the half of it that is about hosts.
//
// Credentials in the authority are the half that is easy to lose: the host
// comparison reads the host and ignores any user:password before it, so an
// endpoint carrying them passes an anchoring check and then has net/http stamp an
// Authorization header the SDK never chose, on a leg that already carries the
// agent's own signature. The resolver refuses this; so must the client, because
// the resolver is a seam a caller can replace.
func TestReportUsage_RefusesAnInjectedEndpointCarryingUserinfo(t *testing.T) {
	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t),
			rampconnect.WithSigner(sig.signer),
			// Anchored to the domain, so only the userinfo arm can refuse it.
			rampconnect.WithEndpointResolver(fixedEndpoint{
				endpoint: "http://agent:s3cret@exchange.test",
			}),
		)...)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      proto.String("exchange.test"),
		TransactionId: "txn-1",
	})
	if err == nil {
		t.Fatal("a signed report to an endpoint carrying credentials must be refused")
	}
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallNotSent {
		t.Errorf("kind = %v, want CallNotSent — nothing left the process", cerr.Kind)
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Errorf("error = %v, want it to name the credential as the reason", err)
	}
	// The refusal must not echo the credential it refused.
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("the refusal leaked the credential: %v", err)
	}
}

// A RAMP call is never legitimately redirected. Following one would re-sign the
// caller's request for a target the peer chose — after the endpoint check had
// already passed, which is the window that check exists to close.
func TestReportUsage_RefusesRedirectAndNeverContactsTheTarget(t *testing.T) {
	sig := newSigningFixture(t)

	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	// The Exchange answers the RPC with a redirect to somewhere else.
	domain := loopbackManifestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      proto.String(domain),
		TransactionId: "txn-1",
	})
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if !strings.Contains(err.Error(), "never redirected") {
		t.Errorf("error = %v, want the redirect refusal", err)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("redirect target contacted %d times; a signed call must never follow one", n)
	}
}

// A peer that answers and says no is a REFUSAL, and it reaches the caller as the
// same typed error the pre-send checks produce — one verb, one error type,
// however it failed. Before this the same method returned two unrelated types
// depending on where it failed.
func TestReportUsage_PeerRefusalIsATypedCallError(t *testing.T) {
	sig := newSigningFixture(t)
	domain := loopbackManifestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"permission_denied","message":"no"}`))
	}))

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &rampv1.UsageReport{
		Exchange:      proto.String(domain),
		TransactionId: "txn-1",
	})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError on the send path too", err)
	}
	if cerr.Kind != rampconnect.CallRefused {
		t.Errorf("kind = %v, want CallRefused for a peer that answered", cerr.Kind)
	}
	if cerr.ReasonOf() == "" {
		t.Error("a refusal must carry a machine-readable reason")
	}
}

// The accessors a caller is told to branch on, exercised directly: they are the
// public face of the type and were entirely uncovered.
func TestCallError_Accessors(t *testing.T) {
	cause := errors.New("underlying")
	full := &rampconnect.CallError{
		Kind: rampconnect.CallRefused, Op: "report usage",
		Status: http.StatusForbidden, Reason: "pop_expired", Err: cause,
	}
	msg := full.Error()
	for _, want := range []string{"report usage", "refused", "Forbidden", "pop_expired", "underlying"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to mention %q", msg, want)
		}
	}
	if !errors.Is(full, cause) {
		t.Error("Unwrap must keep the cause reachable")
	}
	if got := full.ReasonOf(); got != "pop_expired" {
		t.Errorf("ReasonOf() = %q, want the peer's own token", got)
	}

	// With no token from the peer, the class the SDK owns is the fallback.
	bare := &rampconnect.CallError{Kind: rampconnect.CallNotSent, Op: "dispute"}
	if got := bare.ReasonOf(); got != "not_sent" {
		t.Errorf("ReasonOf() = %q, want the failure class as the fallback", got)
	}
	if got := rampconnect.CallErrorKind(99).String(); got != "unknown" {
		t.Errorf("an unnamed kind renders as %q, want \"unknown\"", got)
	}
	// A status net/http does not know renders as the bare number rather than a
	// truncated-looking "(HTTP 599 )".
	odd := &rampconnect.CallError{Kind: rampconnect.CallRefused, Op: "fetch", Status: 599}
	if !strings.Contains(odd.Error(), "(HTTP 599)") {
		t.Errorf("Error() = %q, want the bare status number", odd.Error())
	}
}
