package connect_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// The four verbs this SDK was missing, plus the two shipped ones it had to fix,
// driven through the outermost public surface: an SDK-built client over real HTTP
// to a real Connect handler running the SDK's own server verify face.

// ---------------------------------------------------------------------------
// Origins
// ---------------------------------------------------------------------------

// groupExchange serves a ResourceResponse in whichever offer representation a
// test needs, and records the report and dispute it received.
type groupExchange struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	groups []*rampv1.OfferGroup
	flat   []*rampv1.Offer

	gotReport  *rampv1.UsageReport
	gotDispute *rampv1.DisputeRequest
}

func (g *groupExchange) DiscoverResources(
	_ context.Context, _ *connectrpc.Request[rampv1.ResourceQuery],
) (*connectrpc.Response[rampv1.ResourceResponse], error) {
	return connectrpc.NewResponse(&rampv1.ResourceResponse{
		Exchange:    "exchange.test",
		Offers:      g.flat,
		OfferGroups: g.groups,
	}), nil
}

func (g *groupExchange) ReportUsage(
	_ context.Context, req *connectrpc.Request[rampv1.UsageReport],
) (*connectrpc.Response[rampv1.UsageReportResponse], error) {
	g.gotReport = req.Msg
	return connectrpc.NewResponse(&rampv1.UsageReportResponse{
		Ver: helpers.ProtocolVersion, ReportId: "report-1",
	}), nil
}

func (g *groupExchange) DisputeTransaction(
	_ context.Context, req *connectrpc.Request[rampv1.DisputeRequest],
) (*connectrpc.Response[rampv1.DisputeResponse], error) {
	g.gotDispute = req.Msg
	return connectrpc.NewResponse(&rampv1.DisputeResponse{
		Ver: helpers.ProtocolVersion, DisputeId: proto.String("dispute-1"),
	}), nil
}

// stubBroker serves one DiscoveryResponse.
type stubBroker struct {
	rampv1connect.UnimplementedBrokerServiceHandler
	groups  []*rampv1.OfferGroup
	absence *rampv1.OfferAbsenceReason
}

func (b *stubBroker) Resolve(
	_ context.Context, _ *connectrpc.Request[rampv1.DiscoveryRequest],
) (*connectrpc.Response[rampv1.DiscoveryResponse], error) {
	return connectrpc.NewResponse(&rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion, OfferGroups: b.groups, AbsenceReason: b.absence,
	}), nil
}

func serveExchange(t *testing.T, sig signingFixture, svc rampv1connect.ExchangeServiceHandler) *httptest.Server {
	t.Helper()
	path, h := rampserver.NewExchangeServiceHandler(svc, rampserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func absenceReason(r rampv1.OfferAbsenceReason) *rampv1.OfferAbsenceReason { return &r }

// ---------------------------------------------------------------------------
// Discover: the two offer representations
// ---------------------------------------------------------------------------

// A grouped answer keeps every URI, including the ones that yielded nothing —
// which is the whole reason the result is grouped. A refused URI has no offer to
// carry it back, so flattening would erase it entirely.
func TestDiscover_KeepsPerURIGroupsAndReasons(t *testing.T) {
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	srv := serveExchange(t, sig, &groupExchange{groups: []*rampv1.OfferGroup{
		{Uri: "https://site.test/a", Offers: []*rampv1.Offer{offers.good}},
		{
			Uri:           "https://site.test/b",
			AbsenceReason: absenceReason(rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT),
		},
		{
			Uri:                "https://site.test/c",
			AbsenceReason:      absenceReason(rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_RESTRICTION_FILTERED),
			RestrictionFilters: []rampv1.RestrictionKind{rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY},
		},
	}})
	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithOfferKey(offers.exchangePub))

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Groups) != 3 {
		t.Fatalf("want a group per requested URI, got %d", len(res.Groups))
	}
	if got := res.Groups[0].URI; got != "https://site.test/a" {
		t.Errorf("group 0 URI = %q", got)
	}
	if len(res.Groups[0].Verified) != 1 {
		t.Errorf("group 0 must carry its verified offer, got %d", len(res.Groups[0].Verified))
	}
	// The refusal is an ANSWER: the agent can tell "acquire an entitlement and
	// retry" from "give up" only because the reason survived.
	if res.Groups[1].AbsenceReason == nil ||
		*res.Groups[1].AbsenceReason != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT {
		t.Errorf("group 1 absence reason = %v, want SCOPE_INSUFFICIENT", res.Groups[1].AbsenceReason)
	}
	if len(res.Groups[2].RestrictionFilters) != 1 {
		t.Errorf("group 2 must carry the filtered axis, got %v", res.Groups[2].RestrictionFilters)
	}
	if res.Exchange != "exchange.test" {
		t.Errorf("Exchange = %q, want the responding Exchange", res.Exchange)
	}
}

// A responder that populates BOTH representations must not have its offers
// counted twice: the flat list mirrors the grouped one.
func TestDiscover_GroupsWinOverTheFlatMirrorWithoutDoubleCounting(t *testing.T) {
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	srv := serveExchange(t, sig, &groupExchange{
		groups: []*rampv1.OfferGroup{{Uri: "https://site.test/a", Offers: []*rampv1.Offer{offers.good}}},
		flat:   []*rampv1.Offer{offers.good}, // the same offer, mirrored
	})
	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithOfferKey(offers.exchangePub))

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if n := len(res.Verified()); n != 1 {
		t.Fatalf("the mirrored offer must be counted once, got %d", n)
	}
	if len(res.Groups) != 1 || res.Groups[0].URI != "https://site.test/a" {
		t.Errorf("groups must win over the flat mirror, got %+v", res.Groups)
	}
}

// A responder that sends only the flat list still works, and a single-URI query
// lets the SDK attribute it. A multi-URI query does not, and the SDK does not
// invent an attribution the wire never made.
func TestDiscover_FlatFallback(t *testing.T) {
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	srv := serveExchange(t, sig, &groupExchange{flat: []*rampv1.Offer{offers.good}})
	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithOfferKey(offers.exchangePub))

	single, err := client.Discover(context.Background(),
		&rampv1.ResourceQuery{Uris: []string{"https://site.test/a"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(single.Groups) != 1 || single.Groups[0].URI != "https://site.test/a" {
		t.Errorf("a single-URI flat answer takes that URI, got %+v", single.Groups)
	}
	multi, err := client.Discover(context.Background(),
		&rampv1.ResourceQuery{Uris: []string{"https://site.test/a", "https://site.test/b"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(multi.Groups) != 1 || multi.Groups[0].URI != "" {
		t.Errorf("a multi-URI flat answer carries no attribution, got %+v", multi.Groups)
	}
}

// ---------------------------------------------------------------------------
// Execute: the acceptance the shipped verb never sent
// ---------------------------------------------------------------------------

// A purchase must carry the requester and a detached acceptance that VERIFIES —
// an Exchange checks it, so a request without one can only ever be refused.
func TestExecute_SendsRequesterAndAVerifyingAcceptance(t *testing.T) {
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	origin := &groupExchange{groups: []*rampv1.OfferGroup{
		{Uri: "https://site.test/a", Offers: []*rampv1.Offer{offers.good}},
	}}
	srv := serveExchange(t, sig, origin)

	// One key signs the transport, the acceptance and any later fetch proof — the
	// protocol carries a single agent identity, so the test uses a single key and
	// verifies the acceptance against its public half.
	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithOfferKey(offers.exchangePub),
		rampconnect.WithRequester(testRequester()),
	)
	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	verified := res.Verified()[0]

	execOrigin := &recordingExecute{}
	execSrv := serveExchange(t, sig, execOrigin)
	execClient := rampconnect.NewClient(execSrv.URL,
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithRequester(testRequester()),
	)
	if _, err = execClient.Execute(context.Background(), verified,
		rampconnect.WithIdempotencyKey("pinned-key")); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := execOrigin.req
	if got.GetRequester().GetId() != testRequester().GetId() {
		t.Errorf("requester = %+v, want the configured identity", got.GetRequester())
	}
	item := got.GetItems()[0]
	if item.GetAgentAcceptance().GetSignatureAlgorithm() != helpers.AcceptanceSignatureAlgorithm {
		t.Errorf("acceptance algorithm = %q", item.GetAgentAcceptance().GetSignatureAlgorithm())
	}
	if err = helpers.VerifyOfferAcceptance(
		item.GetOffer(), got.GetRequester(), got.GetIdempotencyKey(),
		item.GetAgentAcceptance().GetSignature(), sig.pub,
	); err != nil {
		t.Errorf("the acceptance an Exchange would check does not verify: %v", err)
	}
	// The request-level acceptance travels beside the per-item one, and the
	// receiving Exchange checks it as the complete in-order projection for
	// itself — so the test verifies exactly what that Exchange would.
	ra := got.GetAgentRequestAcceptance()
	if ra.GetSignatureAlgorithm() != helpers.AcceptanceSignatureAlgorithm {
		t.Errorf("request-acceptance algorithm = %q", ra.GetSignatureAlgorithm())
	}
	if _, err = helpers.VerifyRequestAcceptanceProjection(got, ra, "exchange.test", sig.pub); err != nil {
		t.Errorf("the request acceptance an Exchange would check does not verify: %v", err)
	}
}

// An offer that names no exchange cannot appear in a request-acceptance item
// (the item requires a recipient), so the client sends the request without the
// field instead of constructing an acceptance no verifier could accept.
func TestExecute_SkipsRequestAcceptanceWhenTheOfferNamesNoExchange(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingExecute{}
	srv := serveExchange(t, sig, origin)

	_, exchangePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer := sampleOffer("offer-no-exchange")
	offer.Exchange = ""
	offerSig, err := helpers.SignOffer(exchangePriv, offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = offerSig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()))
	if _, err := client.Execute(context.Background(),
		core.RejectedOffer{Offer: offer}.Unsafe()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if origin.req.GetAgentRequestAcceptance() != nil {
		t.Error("an exchange-less offer must not carry a request acceptance")
	}
}

// Every precondition refuses BEFORE anything leaves the process — an unsigned
// offer is reachable through the two named opt-outs, and an acceptance floating
// free of a concrete offer is meaningless.
func TestExecute_FailsClosedWithoutSendingAnything(t *testing.T) {
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	origin := &recordingExecute{}
	srv := serveExchange(t, sig, origin)

	unsigned := core.RejectedOffer{Offer: sampleOffer("offer-unsigned")}.Unsafe()
	signedOffer := core.RejectedOffer{Offer: offers.good}.Unsafe()

	tests := map[string]struct {
		opts  []rampconnect.ClientOption
		offer core.VerifiedOffer
	}{
		"no requester": {
			[]rampconnect.ClientOption{rampconnect.WithSigner(sig.signer)}, signedOffer,
		},
		"unsigned offer": {
			[]rampconnect.ClientOption{
				rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()),
			}, unsigned,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client := rampconnect.NewClient(srv.URL, tc.opts...)
			if _, err := client.Execute(context.Background(), tc.offer); err == nil {
				t.Fatal("expected a refusal")
			}
			if origin.req != nil {
				t.Error("the origin was contacted; the refusal must be local")
			}
		})
	}
}

type recordingExecute struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	req *rampv1.TransactionRequest
}

func (r *recordingExecute) ExecuteTransaction(
	_ context.Context, req *connectrpc.Request[rampv1.TransactionRequest],
) (*connectrpc.Response[rampv1.TransactionResponse], error) {
	r.req = req.Msg
	return connectrpc.NewResponse(&rampv1.TransactionResponse{Ver: helpers.ProtocolVersion}), nil
}

// ---------------------------------------------------------------------------
// Resolve: the broker face
// ---------------------------------------------------------------------------

func TestBrokerResolve_SplitsThroughTheSameVerifier(t *testing.T) {
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	path, h := rampserver.NewBrokerServiceHandler(
		&stubBroker{groups: []*rampv1.OfferGroup{{
			Uri:    "https://site.test/a",
			Offers: []*rampv1.Offer{offers.good, offers.doctored},
		}}},
		rampserver.WithKeyResolver(sig.resolver),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	broker := rampconnect.NewBrokerClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithOfferKey(offers.exchangePub),
		rampconnect.WithRequester(testRequester()))
	res, err := broker.Resolve(context.Background(),
		&rampv1.DiscoveryRequest{Ver: helpers.ProtocolVersion})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// A relayed offer is exactly the case the fail-closed rule exists for: the
	// Broker forwards offers it did not mint.
	if len(res.Groups) != 1 {
		t.Fatalf("want one group, got %d", len(res.Groups))
	}
	if len(res.Groups[0].Verified) != 1 || len(res.Groups[0].Rejected) != 1 {
		t.Errorf("want the doctored offer rejected in its own group, got %d verified / %d rejected",
			len(res.Groups[0].Verified), len(res.Groups[0].Rejected))
	}
}

// A resolve that finds nothing is a successful answer carrying a typed reason,
// never an error.
func TestBrokerResolve_WholeCallRefusalIsAnAnswer(t *testing.T) {
	sig := newSigningFixture(t)
	path, h := rampserver.NewBrokerServiceHandler(
		&stubBroker{absence: absenceReason(rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED)},
		rampserver.WithKeyResolver(sig.resolver),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	broker := rampconnect.NewBrokerClient(srv.URL, rampconnect.WithSigner(sig.signer),
		rampconnect.WithRequester(testRequester()))
	res, err := broker.Resolve(context.Background(),
		&rampv1.DiscoveryRequest{Ver: helpers.ProtocolVersion})
	if err != nil {
		t.Fatalf("a refusal must not be raised as an error: %v", err)
	}
	if res.AbsenceReason == nil ||
		*res.AbsenceReason != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Errorf("whole-call absence reason = %v, want NOT_AUTHORIZED", res.AbsenceReason)
	}
	if len(res.Groups) != 0 {
		t.Errorf("a refusal carries no groups, got %d", len(res.Groups))
	}
}

// A Broker resolves who is asking from the requester and declines a request that
// names none, so the client refuses it HERE rather than spending a round trip to
// be told — and names the remedy, which a relayed "requester required" cannot.
// Execute refuses the same way and that arm is covered; without this one the
// whole check could be deleted with every test still green.
func TestBrokerResolve_RefusesARequesterlessRequestLocally(t *testing.T) {
	sig := newSigningFixture(t)
	var hits atomic.Int64
	path, h := rampserver.NewBrokerServiceHandler(
		&stubBroker{}, rampserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Every option the face uses EXCEPT WithRequester.
	broker := rampconnect.NewBrokerClient(srv.URL, rampconnect.WithSigner(sig.signer))
	_, err := broker.Resolve(context.Background(),
		&rampv1.DiscoveryRequest{Ver: helpers.ProtocolVersion})

	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != rampconnect.CallMalformed {
		t.Errorf("kind = %v, want CallMalformed — the request is unsendable, not refused", cerr.Kind)
	}
	if !strings.Contains(err.Error(), "WithRequester") {
		t.Errorf("the refusal must name the remedy, got %q", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the Broker was contacted %d time(s); this refusal must be local", n)
	}
}

// ---------------------------------------------------------------------------
// ReportUsage: offer-driven routing and the checks before the send
// ---------------------------------------------------------------------------

// selfAdvertisingExchange stands up ONE host serving both the Exchange's RPC
// endpoint and its own /.well-known/ramp.json — which is what a real Exchange
// does, and what the same-host check requires. The manifest advertises the
// server's own origin, so the endpoint is anchored to the domain it was resolved
// from. It returns the bare domain a report routes on, plus the well-known fetch
// counter.
func selfAdvertisingExchange(t *testing.T, sig signingFixture, svc rampv1connect.ExchangeServiceHandler) (string, *atomic.Int64) {
	t.Helper()
	return selfAdvertisingExchangeWith(t, sig, svc, nil)
}

// selfAdvertisingExchangeWith is the same host with extra manifest members, for
// the account verbs, which read terms_digest and the published data_schema out of
// the very document that advertises the endpoint.
func selfAdvertisingExchangeWith(
	t *testing.T, sig signingFixture, svc rampv1connect.ExchangeServiceHandler,
	extra func() map[string]any,
) (string, *atomic.Int64) {
	t.Helper()
	path, h := rampserver.NewExchangeServiceHandler(svc, rampserver.WithKeyResolver(sig.resolver))
	rpc := http.NewServeMux()
	rpc.Handle(path, h)
	// The manifest half is loopbackManifestServer's, so the self-advertising part
	// is written once. This is the "a real RPC handler" case its catch-all takes.
	return loopbackManifestServerWith(t, rpc, extra)
}

// crossHost serves a manifest advertising SOMEONE ELSE's origin — the case the
// same-host check exists to refuse.
//
// The advertised name is a foreign hostname rather than another loopback server:
// anchoring compares hostnames, and every httptest server shares 127.0.0.1, so
// two local servers are the same host by the rule under test. A refusal must be
// driven by a genuinely different NAME, which is also the production shape.
func crossHost(t *testing.T, endpoint string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ver": helpers.WellKnownManifestVersion, "endpoint": endpoint})
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// allowLoopback opts this test out of the production dial posture the way a
// deployment does — through the two documented env flags, read when the client is
// built. There is deliberately no option that removes the guard: injecting a
// transport puts it UNDER the guard, never in place of it, so a test that wants a
// loopback Exchange has to say so the same way an on-prem deployment would.
//
// The well-known resolver is still injected, because reading a manifest over http
// is a scheme choice rather than a guard opt-out.
func allowLoopback(t *testing.T) []rampconnect.ClientOption {
	t.Helper()
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")
	return []rampconnect.ClientOption{
		rampconnect.WithEndpointResolver(resolvers.NewWellKnownEndpointResolver(
			resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})),
		// The registration reader dials the same manifest over the same scheme, so
		// it takes the same loopback posture. Inert for every verb but Register.
		rampconnect.WithRegistrationRequirements(resolvers.NewWellKnownRequirementsReader(
			resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})),
	}
}

func TestReportUsage_RoutesThroughTheIssuingExchangesOwnManifest(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &groupExchange{}
	domain, wkHits := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	report := &rampv1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
		Usage:         &rampv1.Usage{Function: []string{"ai-input"}},
	}
	resp, err := client.ReportUsage(context.Background(), report)
	if err != nil {
		t.Fatalf("ReportUsage: %v", err)
	}
	if resp.GetReportId() != "report-1" {
		t.Errorf("report id = %q", resp.GetReportId())
	}
	if origin.gotReport.GetVer() != helpers.ProtocolVersion {
		t.Errorf("ver = %q, want it stamped from the one constant", origin.gotReport.GetVer())
	}
	if origin.gotReport.GetIdempotencyKey() == "" {
		t.Error("a fresh idempotency key must be minted by default")
	}
	// The caller's message crossed a package boundary as an argument, not a buffer.
	if report.GetVer() != "" || report.GetIdempotencyKey() != "" {
		t.Errorf("the caller's report was mutated: %+v", report)
	}
	// A second report to the same Exchange reuses the cached manifest.
	if _, err = client.ReportUsage(context.Background(), report); err != nil {
		t.Fatalf("second ReportUsage: %v", err)
	}
	if n := wkHits.Load(); n != 1 {
		t.Errorf("well-known fetched %d times, want it cached per host", n)
	}
}

// Every routing refusal happens before anything is sent, and says so: a caller
// must be able to tell "we refused to dial it" from "it did not answer".
func TestReportUsage_RefusesUnroutableAddressesWithoutSending(t *testing.T) {
	sig := newSigningFixture(t)

	tests := map[string]string{
		"no exchange on the report": "",
		"scheme is not a bare host": "https://exchange.test",
		"path is not a bare host":   "exchange.test/reports",
		"query is not a bare host":  "exchange.test?x=1",
		"trailing colon":            "exchange.test:",
		// A manifest advertising an unrelated host — the case anchoring exists for.
		"endpoint on another host": crossHost(t, "http://evil.invalid/v1"),
	}
	for name, domain := range tests {
		t.Run(name, func(t *testing.T) {
			client := rampconnect.NewClient("http://home.invalid",
				append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)
			report := &rampv1.UsageReport{TransactionId: "txn-1"}
			if domain != "" {
				report.Exchange = domain
			}
			_, err := client.ReportUsage(context.Background(), report)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			var cerr *rampconnect.CallError
			if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallNotSent {
				t.Fatalf("error = %v, want a CallNotSent CallError", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Dispute
// ---------------------------------------------------------------------------

func TestDispute_RoutesLikeAReportAndStampsTheEnvelope(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &groupExchange{}
	domain, _ := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	req := &rampv1.DisputeRequest{
		TransactionId: "txn-1",
		ReportId:      "report-1",
		Exchange:      domain,
		Reason:        rampv1.DisputeReason_DISPUTE_REASON_DELIVERY_FAILED,
	}
	resp, err := client.Dispute(context.Background(), req,
		rampconnect.WithIdempotencyKey("pinned"))
	if err != nil {
		t.Fatalf("Dispute: %v", err)
	}
	if resp.GetDisputeId() != "dispute-1" {
		t.Errorf("dispute id = %q", resp.GetDisputeId())
	}
	if origin.gotDispute.GetIdempotencyKey() != "pinned" {
		t.Errorf("idempotency key = %q, want the pinned one", origin.gotDispute.GetIdempotencyKey())
	}
	if origin.gotDispute.GetVer() != helpers.ProtocolVersion {
		t.Errorf("ver = %q", origin.gotDispute.GetVer())
	}
	if req.GetVer() != "" || req.GetIdempotencyKey() != "" {
		t.Errorf("the caller's request was mutated: %+v", req)
	}
}

// The same vetting guards both verbs, so a dispute cannot be aimed at an
// unroutable address either.
func TestDispute_SharesTheRoutingRefusals(t *testing.T) {
	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.Dispute(context.Background(),
		&rampv1.DisputeRequest{TransactionId: "txn-1", Exchange: "https://exchange.test"})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallNotSent {
		t.Fatalf("error = %v, want a CallNotSent CallError", err)
	}
}

// A dispute that names no recipient cannot be routed at all. The field is
// required on the wire, so this refusal happens before anything is signed or
// sent — the same shape ReportUsage already had, now reachable for disputes too.
func TestDispute_RefusesAnUnaddressedRequest(t *testing.T) {
	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.Dispute(context.Background(),
		&rampv1.DisputeRequest{TransactionId: "txn-1", ReportId: "report-1"})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallNotSent {
		t.Fatalf("error = %v, want a CallNotSent CallError for a request with no exchange", err)
	}
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

func TestFetch_PresentsTheProofAndSurfacesATypedRefusal(t *testing.T) {
	sig := newSigningFixture(t)

	var sawProof atomic.Bool
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(helpers.AgentKeyHeader) != "" && r.Header.Get("Signature") != "" {
			sawProof.Store(true)
		}
		if r.URL.Query().Get("refuse") == "1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"reason":"pop_expired"}`))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("licensed bytes"))
	}))
	defer content.Close()

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t),
			rampconnect.WithSigner(sig.signer),
			rampconnect.WithAgentKey(sig.pub),
		)...)

	got, err := client.Fetch(context.Background(), content.URL+"/doc?agent_id=tp")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got.Body) != "licensed bytes" || got.MIMEType != "text/plain" {
		t.Errorf("content = %+v", got)
	}
	if !sawProof.Load() {
		t.Error("the fetch presented no proof of possession")
	}

	// A refusal the edge names in its own vocabulary reaches the caller as the
	// SAME typed reason an RPC refusal would, through the same accessor.
	_, err = client.Fetch(context.Background(), content.URL+"/doc?refuse=1")
	if err == nil {
		t.Fatal("expected the edge refusal to surface")
	}
	detail, ok := rampconnect.ErrorDetailFrom(err)
	if !ok {
		t.Fatalf("no typed detail on a refused fetch: %v", err)
	}
	if got := detail.GetRetrievalAuthFailure().GetReason(); got !=
		rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED {
		t.Errorf("typed reason = %v, want PROOF_EXPIRED", got)
	}
	// The domain names the failing SURFACE, not the fetched URL: it is a grouping
	// key for tooling, and a per-URL value has unbounded cardinality and groups
	// nothing. Asserted as the exact value the cross-language error-detail corpus
	// uses, so a change here has to be a deliberate one.
	if got := detail.GetDomain(); got != "ramp.v1.Edge" {
		t.Errorf("detail domain = %q, want the delivery edge as the failing surface", got)
	}
}

// A client that can buy but was never given the public half of its agent key
// cannot fetch, and says so rather than presenting a proof the edge will refuse.
func TestFetch_RefusesWithoutTheAgentPublicKey(t *testing.T) {
	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.Fetch(context.Background(), "http://cdn.invalid/doc")
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallNotSignable {
		t.Fatalf("error = %v, want a CallNotSignable CallError", err)
	}
}

// ---------------------------------------------------------------------------
// Signature-Agent: the directory a peer resolves the caller's key from
// ---------------------------------------------------------------------------

// The configured directory must reach the WIRE, covered by the signature.
//
// signature-agent is one of the five REQUIRED covered components, so the header is
// signed whether or not a value was supplied — an unset client signs an EMPTY one.
// A peer that resolves the caller's key by fetching the WBA directory at that
// origin then has nothing to resolve and refuses the call at verification, after
// it was routed, signed and sent. That failure mode is why asserting the option
// sets a field would prove nothing: what matters is the bytes that leave.
func TestWithSignatureAgent_ReachesTheWireCovered(t *testing.T) {
	const dir = "https://agent.example"
	sig := newSigningFixture(t)

	var gotAgent, gotSigInput string
	path, h := rampserver.NewExchangeServiceHandler(
		&groupExchange{}, rampserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent, gotSigInput = r.Header.Get("Signature-Agent"), r.Header.Get("Signature-Input")
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithSignatureAgent(dir),
		rampconnect.WithRequester(testRequester()))

	// The call must SUCCEED: the header participates in the signature, so a value
	// that reached the wire without being covered correctly would fail here.
	if _, err := client.Discover(context.Background(), &rampv1.ResourceQuery{
		Uris: []string{"https://site.test/a"}, Ver: helpers.ProtocolVersion,
	}); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if gotAgent != dir {
		t.Errorf("Signature-Agent = %q, want %q", gotAgent, dir)
	}
	// Present is not enough — an uncovered header is one any intermediary may
	// rewrite, which is the whole reason the component is in the required set.
	if !strings.Contains(gotSigInput, `"signature-agent"`) {
		t.Errorf("Signature-Input = %q; want it to cover signature-agent", gotSigInput)
	}
}

// The Broker face stamps it too. Both clients reach the wire through the same
// plumbing, and that is the property worth pinning rather than assuming — a
// second construction path is exactly where one knob gets dropped.
func TestWithSignatureAgent_BrokerClientStampsItToo(t *testing.T) {
	const dir = "https://agent.example"
	sig := newSigningFixture(t)

	var gotAgent string
	path, h := rampserver.NewBrokerServiceHandler(
		&stubBroker{}, rampserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent = r.Header.Get("Signature-Agent")
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	broker := rampconnect.NewBrokerClient(srv.URL,
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithSignatureAgent(dir),
		rampconnect.WithRequester(testRequester()))
	if _, err := broker.Resolve(context.Background(),
		&rampv1.DiscoveryRequest{Ver: helpers.ProtocolVersion}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotAgent != dir {
		t.Errorf("Signature-Agent = %q, want %q", gotAgent, dir)
	}
}

// WithRequestIDFunc reaches the DELIVERY leg, not only the RPC legs.
//
// The two RPC legs correlate through an interceptor; a delivery fetch is a plain
// GET that never reaches one, so the option had to be threaded to the fetcher
// separately. A caller that passes one mint reasonably expects one id across every
// leg of a call, and a delivery edge that mints its own when the header is absent
// is where the gap surfaces — as two log lines under two ids and nothing joining
// them.
func TestFetch_CarriesTheClientsCorrelationID(t *testing.T) {
	sig := newSigningFixture(t)

	var got string
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(helpers.RequestIDHeader)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("licensed bytes"))
	}))
	defer content.Close()

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t),
			rampconnect.WithSigner(sig.signer),
			rampconnect.WithAgentKey(sig.pub),
			rampconnect.WithRequestIDFunc(func() string { return "req-from-the-caller" }),
		)...)

	if _, err := client.Fetch(context.Background(), content.URL+"/doc?agent_id=tp"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got != "req-from-the-caller" {
		t.Errorf("%s = %q, want the client's own mint", helpers.RequestIDHeader, got)
	}
}

// And with no mint configured the leg still correlates: the client falls back to
// the same default source the RPC legs use, so the id is present rather than left
// for the edge to invent.
func TestFetch_CorrelatesEvenWithNoMintConfigured(t *testing.T) {
	sig := newSigningFixture(t)

	var got string
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(helpers.RequestIDHeader)
		_, _ = w.Write([]byte("bytes"))
	}))
	defer content.Close()

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t),
			rampconnect.WithSigner(sig.signer), rampconnect.WithAgentKey(sig.pub),
		)...)

	if _, err := client.Fetch(context.Background(), content.URL+"/doc?agent_id=tp"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got == "" {
		t.Errorf("%s is empty; the client must fall back to the default mint", helpers.RequestIDHeader)
	}
}
