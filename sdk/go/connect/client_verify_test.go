package connect_test

// Integration suite for the sdk/go L2 low-tier CLIENT face (connect.Client +
// core.Verifier + the fail-closed {verified, rejected} contract + the VerifiedOffer
// compile guard + WithVerification opt-out). The Client and its options live in
// sdk/go/connect, the Verifier / Result / VerifiedOffer / Mode in sdk/go/core, and
// the server handler the closed round-trip verifies against in sdk/go/connectserver.
//
// TESTING DOCTRINE: these tests drive behavior through the OUTERMOST public
// surface — a real Connect ExchangeService client built by the SDK, talking over
// real HTTP (net/http/httptest) to a real Connect handler that runs the SDK's
// server verify face — and assert back through that same surface. The transport
// is never mocked. The only injected app dependencies are the L1 Signer, the L1
// KeyResolver, and (server-side) an in-memory ReplayStore test-double: those are
// application-supplied holders the SDK orchestrates over, not mocks of the code
// under test.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// ---------------------------------------------------------------------------
// Factories (no inline test-data construction in the test bodies).
// ---------------------------------------------------------------------------

// signingFixture holds the request-signing keypair the L2 client injects as a
// Signer and the resolver the server verify face resolves it through.
type signingFixture struct {
	signer   helpers.Signer
	resolver *helpers.StaticKeyResolver
	keyID    string
	// pub is the public half of the same key. The protocol carries ONE agent
	// identity: the key that signs requests also signs the detached acceptance and
	// is the key a delivery URL is bound to, so tests that verify an acceptance or
	// present a fetch proof need it alongside the Signer.
	pub ed25519.PublicKey
}

// newSigningFixture builds a request-signing keypair, an L1 Signer over it, and a
// static resolver that knows exactly that key — the closed loop the client sign
// face and the server verify face share.
func newSigningFixture(t *testing.T) signingFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate request-signing key: %v", err)
	}
	// keyid IS the RFC 7638 thumbprint: it is the anchor of the three-way identity
	// an edge checks on a bound fetch, and the value an Exchange binds a delivery
	// URL to. A fixture that used an opaque label could never mint a fetch proof.
	keyID, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint request-signing key: %v", err)
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signingFixture{
		signer:   signer,
		resolver: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub}),
		keyID:    keyID,
		pub:      pub,
	}
}

// offerFixture is a discovery-scenario worth of offers: an offer signed by the
// exchange's genuine offer-signing key (good) and one signed by a foreign key
// (doctored). The server returns both; the SDK Verifier must sort them.
type offerFixture struct {
	exchangePub ed25519.PublicKey
	good        *rampv1.Offer
	doctored    *rampv1.Offer
}

// newOfferFixture mints two offers, signs the first with the exchange key and the
// second with an attacker key, and returns the exchange public key the client's
// KeyResolver will resolve for offer verification.
func newOfferFixture(t *testing.T) offerFixture {
	t.Helper()
	exPub, exPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate exchange offer key: %v", err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	good := sampleOffer("offer-good")
	goodSig, err := helpers.SignOffer(exPriv, good)
	if err != nil {
		t.Fatalf("sign good offer: %v", err)
	}
	good.Signature = goodSig
	good.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	doctored := sampleOffer("offer-doctored")
	badSig, err := helpers.SignOffer(attackerPriv, doctored) // wrong key
	if err != nil {
		t.Fatalf("sign doctored offer: %v", err)
	}
	doctored.Signature = badSig
	doctored.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	return offerFixture{exchangePub: exPub, good: good, doctored: doctored}
}

// sampleOffer builds a minimal, valid Offer carrying a future expiry so it is not
// rejected on freshness grounds.
func sampleOffer(id string) *rampv1.Offer {
	return &rampv1.Offer{
		OfferId:   id,
		ExpiresAt: timestampProto(time.Now().Add(1 * time.Hour)),
		Pricing:   &rampv1.Pricing{Rate: "0.05", Currency: "USD"},
	}
}

// ---------------------------------------------------------------------------
// Test server: a real Connect ExchangeService handler, wrapped by the SDK's
// server verify face, returning a fixed offer set from Discover.
// ---------------------------------------------------------------------------

// stubExchange is a minimal ExchangeService that echoes a fixed offer set from
// Discover and a fixed TransactionResponse from Execute. It is the ORIGIN behind
// the SDK's server verify face — not a mock of the SDK, but the app service the
// SDK wraps. Like a real platform handler it OWNS the unauthenticated rejection:
// the seam verifies only requests that present a signature, and an unsigned
// request reaches the handler, which rejects before acting.
type stubExchange struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	offers []*rampv1.Offer
	// gotExecute records the last TransactionRequest the origin observed, so a test
	// can assert what the CLIENT put on the wire rather than only that the call
	// succeeded. The SSOT guard bans a bare Ver literal but cannot see an OMITTED
	// one, so this is what stops ver silently going missing again.
	//
	// Guarded, like every other recording double in this SDK: the handler runs on
	// the httptest server's goroutine and the assertion reads from the test's, so
	// the write and the read are only ordered by luck today — one test issuing two
	// calls, or a run under -race, is enough to lose that.
	mu         sync.Mutex
	gotExecute *rampv1.TransactionRequest
}

// lastExecute returns the last request the origin observed.
func (s *stubExchange) lastExecute() *rampv1.TransactionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gotExecute
}

// requireVerified mirrors the platform handlers' auth guard: no verified
// signature in context → typed Unauthenticated, before any side effect.
func requireVerified(ctx context.Context) error {
	if helpers.FromContext(ctx) == nil {
		return connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	return nil
}

func (s *stubExchange) DiscoverResources(
	ctx context.Context, _ *connectrpc.Request[rampv1.ResourceQuery],
) (*connectrpc.Response[rampv1.ResourceResponse], error) {
	if err := requireVerified(ctx); err != nil {
		return nil, err
	}
	return connectrpc.NewResponse(&rampv1.ResourceResponse{Offers: s.offers}), nil
}

func (s *stubExchange) ExecuteTransaction(
	ctx context.Context, req *connectrpc.Request[rampv1.TransactionRequest],
) (*connectrpc.Response[rampv1.TransactionResponse], error) {
	s.mu.Lock()
	s.gotExecute = req.Msg
	s.mu.Unlock()
	if err := requireVerified(ctx); err != nil {
		return nil, err
	}
	return connectrpc.NewResponse(&rampv1.TransactionResponse{Ver: helpers.ProtocolVersion}), nil
}

// newVerifyingServer stands up an httptest server whose ExchangeService handler is
// wrapped by the SDK server verify face (connectserver), resolving request-signing
// keys through the injected resolver and deduping through the injected replay store.
// This is the server side of the closed round-trip.
func newVerifyingServer(t *testing.T, sig signingFixture, replay core.ReplayStore, offers []*rampv1.Offer) *httptest.Server {
	t.Helper()
	srv, _ := newVerifyingServerStub(t, sig, replay, offers)
	return srv
}

// newVerifyingServerStub is newVerifyingServer plus a handle on the origin, for
// the tests that assert what the client actually SENT rather than only that the
// round-trip succeeded.
func newVerifyingServerStub(t *testing.T, sig signingFixture, replay core.ReplayStore, offers []*rampv1.Offer) (*httptest.Server, *stubExchange) {
	t.Helper()
	origin := &stubExchange{offers: offers}
	path, h := rampserver.NewExchangeServiceHandler(
		origin,
		rampserver.WithKeyResolver(sig.resolver),
		rampserver.WithReplayStore(replay),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, origin
}

// ---------------------------------------------------------------------------
// 1. Client sign round-trips through the verifier (guards the RoundTripper decision).
// ---------------------------------------------------------------------------

// TestClientSign_RoundTripsThroughServerVerify pins that a request signed by the
// L2 client sign face verifies byte-identically through the SDK server verify
// face (helpers.VerifyRequestResolved under the hood). This is the #1 interop
// guard: sign MUST be realized as a signing http.RoundTripper (Content-Digest
// over marshaled body bytes), NOT a connect.Interceptor. A client built with the
// injected Signer and pointed at the verifying server is ACCEPTED.
//
// Round-trip: client sign(RoundTripper) → real HTTP → server verify face →
// origin handler → response back through the same client. Full protocol
// round-trip, every leg.
func TestClientSign_RoundTripsThroughServerVerify(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, nil)

	client := rampconnect.NewClient(srv.URL, rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()))

	// Execute needs a VerifiedOffer; but this test only asserts transport
	// acceptance, so a discover round-trip (empty offer set) is the minimal
	// signed call. It must be accepted (no Unauthenticated).
	_, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("signed client Discover must be accepted by the verify face, got: %v", err)
	}
}

// TestClientSign_NakedClientRejected pins the negative path: a client with NO
// signer (naked http, unsigned request) is rejected by the server verify face
// with connect.CodeUnauthenticated — and the origin handler never runs.
func TestClientSign_NakedClientRejected(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, nil)

	// A naked Connect client built directly over the generated stub — no SDK sign
	// face, so the request carries no RFC 9421 signature.
	naked := rampv1connect.NewExchangeServiceClient(http.DefaultClient, srv.URL)
	_, err := naked.DiscoverResources(context.Background(), connectrpc.NewRequest(&rampv1.ResourceQuery{}))
	if err == nil {
		t.Fatal("unsigned request must be rejected by the verify face")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("unsigned request: want CodeUnauthenticated, got %v (err=%v)", got, err)
	}
}

// ---------------------------------------------------------------------------
// 2. Fail-closed {verified, rejected}: Discover sorts offers by authenticity.
// ---------------------------------------------------------------------------

// TestDiscover_SortsVerifiedAndRejected pins the fail-closed contract: Discover
// verifies EVERY returned offer against the exchange's offer-signing key (resolved
// through the injected KeyResolver), landing a genuinely-signed offer in Verified
// and a wrong-key offer in Rejected — with a reason. Neither is silently dropped.
func TestDiscover_SortsVerifiedAndRejected(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, []*rampv1.Offer{off.good, off.doctored})

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()),
		rampconnect.WithOfferKey(off.exchangePub), // exchange offer-verifying key
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified()) != 1 {
		t.Fatalf("want exactly 1 verified offer, got %d", len(res.Verified()))
	}
	if got := res.Verified()[0].Offer().GetOfferId(); got != "offer-good" {
		t.Fatalf("verified offer id: want offer-good, got %q", got)
	}
	if len(res.Rejected()) != 1 {
		t.Fatalf("want exactly 1 rejected offer, got %d", len(res.Rejected()))
	}
	if got := res.Rejected()[0].Offer.GetOfferId(); got != "offer-doctored" {
		t.Fatalf("rejected offer id: want offer-doctored, got %q", got)
	}
	if res.Rejected()[0].Reason == nil {
		t.Fatal("rejected offer must carry a non-nil reason")
	}
	if !errors.Is(res.Rejected()[0].Reason, helpers.ErrOfferSignatureInvalid) {
		t.Fatalf("rejected reason: want ErrOfferSignatureInvalid, got %v", res.Rejected()[0].Reason)
	}
}

// TestExecute_AcceptsVerifiedOffer pins that Execute succeeds on a genuinely
// verified offer produced by Discover — the positive half of the compile guard,
// exercised at runtime through the full client→server→origin round-trip.
func TestExecute_AcceptsVerifiedOffer(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, []*rampv1.Offer{off.good})

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()),
		rampconnect.WithOfferKey(off.exchangePub),
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified()) != 1 {
		t.Fatalf("want 1 verified offer, got %d", len(res.Verified()))
	}
	// Execute takes ONLY a VerifiedOffer — this compiles because res.Verified()[0]
	// is one. Passing res.Rejected()[0] (a RejectedOffer) or a raw *rampv1.Offer
	// here would NOT compile; that guard is documented in doc_compileguard_test.go.
	if _, err := client.Execute(context.Background(), res.Verified()[0]); err != nil {
		t.Fatalf("Execute on a verified offer must succeed, got: %v", err)
	}
}

// TestExecute_StampsProtocolVersion pins the send-side half of the ver contract
// ("Protocol version" in ramp.proto): a sender MUST stamp ver, from the single
// constant. Execute builds the whole TransactionRequest, so the SDK is the sender
// and owns the field — before this it shipped ver "" on every transaction.
//
// This asserts an OMISSION cannot return. The sdk/go SSOT guard scans source for a
// bare `Ver: "…"` literal, which catches the wrong VALUE but is blind to a missing
// field; only observing the request at the origin can catch that.
func TestExecute_StampsProtocolVersion(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	srv, origin := newVerifyingServerStub(t, sig, newMemReplayStore(), []*rampv1.Offer{off.good})

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()),
		rampconnect.WithOfferKey(off.exchangePub),
	)

	// Discover sends the caller's query unmodified, so this test is the sender for
	// the discovery leg and stamps ver from the constant, as the contract requires.
	res, err := client.Discover(context.Background(),
		&rampv1.ResourceQuery{Ver: helpers.ProtocolVersion})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified()) != 1 {
		t.Fatalf("want 1 verified offer, got %d", len(res.Verified()))
	}
	if _, err := client.Execute(context.Background(), res.Verified()[0]); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	sent := origin.lastExecute()
	if sent == nil {
		t.Fatal("origin observed no TransactionRequest — the capture is wired wrong, so this test would pass vacuously")
	}
	if got := sent.GetVer(); got != helpers.ProtocolVersion {
		t.Errorf("TransactionRequest.ver = %q, want %q — Execute must stamp the version from helpers.ProtocolVersion",
			got, helpers.ProtocolVersion)
	}
}

// ---------------------------------------------------------------------------
// 3. Compile-guard escape hatch: acting on a RejectedOffer requires .Unsafe().
// ---------------------------------------------------------------------------

// TestRejectedOffer_RequiresUnsafeToExecute pins the runtime half of the compile
// guard: a RejectedOffer cannot be handed to Execute directly (that is a compile
// error, documented separately), and the ONLY way to obtain an executable
// VerifiedOffer from it is the explicit .Unsafe() escape. The escape yields the
// executable shape; the request still round-trips the signed transport.
func TestRejectedOffer_RequiresUnsafeToExecute(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, []*rampv1.Offer{off.doctored})

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()),
		rampconnect.WithOfferKey(off.exchangePub),
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Rejected()) != 1 {
		t.Fatalf("want 1 rejected offer, got %d", len(res.Rejected()))
	}
	// The explicit escape: .Unsafe() converts a RejectedOffer into the executable
	// VerifiedOffer shape. This is the single documented bypass; without it
	// Execute(ctx, rejected) does not compile.
	forced := res.Rejected()[0].Unsafe()
	if _, err := client.Execute(context.Background(), forced); err != nil {
		t.Fatalf("Execute on an explicitly-unsafed offer must reach the server, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 4. WithVerification(Off) is the single loud named opt-out.
// ---------------------------------------------------------------------------

// TestWithVerification_StrictRejectsUnverifiable pins that the DEFAULT (Strict)
// verification lands an offer with no resolvable exchange key in Rejected — it is
// never silently promoted to Verified.
func TestWithVerification_StrictRejectsUnverifiable(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, []*rampv1.Offer{off.good})

	// No WithOfferKey → the client cannot resolve the exchange offer key, so even
	// the genuinely-signed offer is UNVERIFIABLE and must be rejected under Strict.
	client := rampconnect.NewClient(srv.URL, rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()))

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified()) != 0 {
		t.Fatalf("Strict with no resolvable offer key must verify nothing, got %d verified", len(res.Verified()))
	}
	if len(res.Rejected()) != 1 {
		t.Fatalf("Strict must surface the unverifiable offer as rejected, got %d rejected", len(res.Rejected()))
	}
}

// TestWithVerification_OffSurfacesUnverified pins that WithVerification(Off) — the
// single named, loud opt-out — surfaces offers WITHOUT verification: the same
// unverifiable offer that Strict rejects now lands in Verified because
// verification was explicitly disabled.
func TestWithVerification_OffSurfacesUnverified(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, []*rampv1.Offer{off.good})

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(sig.signer), rampconnect.WithRequester(testRequester()),
		rampconnect.WithVerification(core.Off), // loud, named opt-out
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified()) != 1 {
		t.Fatalf("WithVerification(Off) must surface the offer without verification, got %d verified", len(res.Verified()))
	}
	if len(res.Rejected()) != 0 {
		t.Fatalf("WithVerification(Off) must not reject, got %d rejected", len(res.Rejected()))
	}
}
