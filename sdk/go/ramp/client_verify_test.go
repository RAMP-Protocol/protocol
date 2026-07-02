package ramp_test

// Integration TDD-red suite for the sdk/go L2 low-tier CLIENT face (ramp.Client
// + Verifier + the fail-closed {verified, rejected} contract + the VerifiedOffer
// compile guard + WithVerification opt-out).
//
// TESTING DOCTRINE: these tests drive behavior through the OUTERMOST public
// surface — a real Connect ExchangeService client built by the SDK, talking over
// real HTTP (net/http/httptest) to a real Connect handler that runs the SDK's
// server verify face — and assert back through that same surface. The transport
// is never mocked. The only injected app dependencies are the L1 Signer, the L1
// KeyResolver, and (server-side) an in-memory ReplayStore test-double: those are
// application-supplied holders the SDK orchestrates over, not mocks of the code
// under test.
//
// RED STATUS: this file does not compile today because package
// github.com/RAMP-Protocol/protocol/sdk/go/ramp does not exist yet (sdk/go holds
// only helpers). A greenfield L2 package that does not build IS the intended red
// artifact — the implement step (jjksa.7) creates ramp.NewClient / ramp.Verifier
// / ramp.Result / ramp.VerifiedOffer / ramp.WithVerification and turns this green.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramp"
	"github.com/RAMP-Protocol/protocol/sdk/go/rampconnect"
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
	const keyID = "agent.test.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signingFixture{
		signer:   signer,
		resolver: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub}),
		keyID:    keyID,
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
// SDK wraps.
type stubExchange struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	offers []*rampv1.Offer
}

func (s *stubExchange) DiscoverResources(
	_ context.Context, _ *connect.Request[rampv1.ResourceQuery],
) (*connect.Response[rampv1.ResourceResponse], error) {
	return connect.NewResponse(&rampv1.ResourceResponse{Offers: s.offers}), nil
}

func (s *stubExchange) ExecuteTransaction(
	_ context.Context, _ *connect.Request[rampv1.TransactionRequest],
) (*connect.Response[rampv1.TransactionResponse], error) {
	return connect.NewResponse(&rampv1.TransactionResponse{Ver: "1.0"}), nil
}

// newVerifyingServer stands up an httptest server whose ExchangeService handler is
// wrapped by the SDK server verify face (rampconnect), resolving request-signing
// keys through the injected resolver and deduping through the injected replay
// store. This is the server side of the closed round-trip.
func newVerifyingServer(t *testing.T, sig signingFixture, replay ramp.ReplayStore, offers []*rampv1.Offer) *httptest.Server {
	t.Helper()
	path, h := rampconnect.NewExchangeServiceHandler(
		&stubExchange{offers: offers},
		rampconnect.WithKeyResolver(sig.resolver),
		rampconnect.WithReplayStore(replay),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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

	client := ramp.NewClient(srv.URL, ramp.WithSigner(sig.signer))

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
	_, err := naked.DiscoverResources(context.Background(), connect.NewRequest(&rampv1.ResourceQuery{}))
	if err == nil {
		t.Fatal("unsigned request must be rejected by the verify face")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
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

	client := ramp.NewClient(srv.URL,
		ramp.WithSigner(sig.signer),
		ramp.WithOfferKey(off.exchangePub), // exchange offer-verifying key
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified) != 1 {
		t.Fatalf("want exactly 1 verified offer, got %d", len(res.Verified))
	}
	if got := res.Verified[0].Offer().GetOfferId(); got != "offer-good" {
		t.Fatalf("verified offer id: want offer-good, got %q", got)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("want exactly 1 rejected offer, got %d", len(res.Rejected))
	}
	if got := res.Rejected[0].Offer.GetOfferId(); got != "offer-doctored" {
		t.Fatalf("rejected offer id: want offer-doctored, got %q", got)
	}
	if res.Rejected[0].Reason == nil {
		t.Fatal("rejected offer must carry a non-nil reason")
	}
	if !errors.Is(res.Rejected[0].Reason, helpers.ErrOfferSignatureInvalid) {
		t.Fatalf("rejected reason: want ErrOfferSignatureInvalid, got %v", res.Rejected[0].Reason)
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

	client := ramp.NewClient(srv.URL,
		ramp.WithSigner(sig.signer),
		ramp.WithOfferKey(off.exchangePub),
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified) != 1 {
		t.Fatalf("want 1 verified offer, got %d", len(res.Verified))
	}
	// Execute takes ONLY a VerifiedOffer — this compiles because res.Verified[0]
	// is one. Passing res.Rejected[0] (a RejectedOffer) or a raw *rampv1.Offer
	// here would NOT compile; that guard is documented in doc_compileguard.go.
	if _, err := client.Execute(context.Background(), res.Verified[0]); err != nil {
		t.Fatalf("Execute on a verified offer must succeed, got: %v", err)
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

	client := ramp.NewClient(srv.URL,
		ramp.WithSigner(sig.signer),
		ramp.WithOfferKey(off.exchangePub),
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("want 1 rejected offer, got %d", len(res.Rejected))
	}
	// The explicit escape: .Unsafe() converts a RejectedOffer into the executable
	// VerifiedOffer shape. This is the single documented bypass; without it
	// Execute(ctx, rejected) does not compile.
	forced := res.Rejected[0].Unsafe()
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
	client := ramp.NewClient(srv.URL, ramp.WithSigner(sig.signer))

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified) != 0 {
		t.Fatalf("Strict with no resolvable offer key must verify nothing, got %d verified", len(res.Verified))
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("Strict must surface the unverifiable offer as rejected, got %d rejected", len(res.Rejected))
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

	client := ramp.NewClient(srv.URL,
		ramp.WithSigner(sig.signer),
		ramp.WithVerification(ramp.Off), // loud, named opt-out
	)

	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified) != 1 {
		t.Fatalf("WithVerification(Off) must surface the offer without verification, got %d verified", len(res.Verified))
	}
	if len(res.Rejected) != 0 {
		t.Fatalf("WithVerification(Off) must not reject, got %d rejected", len(res.Rejected))
	}
}
