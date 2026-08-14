package connectserver_test

// Integration suite for the sdk/go L2 low-tier SERVER face (connectserver):
// the verify http-seam wrapper around a generated Connect handler + the injected
// ReplayStore replay check + the OUTERMOST request-id stamp that must survive the
// reject path. The server handler + options live in sdk/go/connectserver; the client
// that drives the closed round-trip lives in sdk/go/connect.
//
// TESTING DOCTRINE: these tests drive behavior through the OUTERMOST public
// surface — a real Connect handler wrapped by the SDK server face, served over
// real HTTP (httptest), hit by a real Connect client. Assertions come back
// through that same surface (the connect.Code and the response headers). The
// transport is never mocked; the only injected app dependencies are the L1
// KeyResolver and an in-memory ReplayStore double.

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
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Test doubles / factories.
// ---------------------------------------------------------------------------

// echoExchange is the origin service behind the SDK server face. recordHit lets a
// test prove the handler never runs on a rejected request (the side effect that
// MUST be absent on the negative path).
type echoExchange struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	mu   sync.Mutex
	hits int
}

func (e *echoExchange) DiscoverResources(
	ctx context.Context, _ *connectrpc.Request[rampv1.ResourceQuery],
) (*connectrpc.Response[rampv1.ResourceResponse], error) {
	// Like a real platform handler: no verified signature in context → typed
	// Unauthenticated BEFORE any side effect (hits counts business effects only).
	if helpers.FromContext(ctx) == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	e.mu.Lock()
	e.hits++
	e.mu.Unlock()
	return connectrpc.NewResponse(&rampv1.ResourceResponse{}), nil
}

func (e *echoExchange) hitCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hits
}

// countingReplayStore is an in-memory ReplayStore double whose first SeenOrAdd per
// nonce returns false (new) and every subsequent one returns true (replay). It is
// an injected app dependency, not a mock of the SDK; the SDK decides WHEN to call
// it in fail-closed verification.
type countingReplayStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newCountingReplayStore() *countingReplayStore {
	return &countingReplayStore{seen: map[string]struct{}{}}
}

func (c *countingReplayStore) Seen(_ context.Context, nonce string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[nonce]
	return ok, nil
}

func (c *countingReplayStore) SeenOrAdd(_ context.Context, nonce string, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[nonce]; ok {
		return true, nil
	}
	c.seen[nonce] = struct{}{}
	return false, nil
}

var _ core.ReplayStore = (*countingReplayStore)(nil)

// alwaysReplayStore reports EVERY nonce as already seen — it forces the replay
// rejection path on the first request, so the test does not depend on the client
// minting a stable nonce across two calls.
type alwaysReplayStore struct{}

func (alwaysReplayStore) Seen(context.Context, string) (bool, error) {
	return true, nil
}

func (alwaysReplayStore) SeenOrAdd(context.Context, string, time.Duration) (bool, error) {
	return true, nil
}

var _ core.ReplayStore = alwaysReplayStore{}

// serverFixture wires a signing keypair, its resolver, and the echo origin behind
// the SDK server face.
type serverFixture struct {
	signer   helpers.Signer
	resolver *helpers.StaticKeyResolver
	origin   *echoExchange
}

func newServerFixture(t *testing.T) serverFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "agent.test.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return serverFixture{
		signer:   signer,
		resolver: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub}),
		origin:   &echoExchange{},
	}
}

// offerExchange is an origin that returns a single genuinely-signed offer from
// Discover and a fixed response from Execute — used by the two-call replay test so
// the client can obtain a real VerifiedOffer to Execute twice.
type offerExchange struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	offer *rampv1.Offer
}

func (o *offerExchange) DiscoverResources(
	_ context.Context, _ *connectrpc.Request[rampv1.ResourceQuery],
) (*connectrpc.Response[rampv1.ResourceResponse], error) {
	return connectrpc.NewResponse(&rampv1.ResourceResponse{Offers: []*rampv1.Offer{o.offer}}), nil
}

func (o *offerExchange) ExecuteTransaction(
	_ context.Context, _ *connectrpc.Request[rampv1.TransactionRequest],
) (*connectrpc.Response[rampv1.TransactionResponse], error) {
	return connectrpc.NewResponse(&rampv1.TransactionResponse{Ver: helpers.ProtocolVersion}), nil
}

// serve stands up the SDK-wrapped handler over httptest with the given replay
// store injected.
func (f serverFixture) serve(t *testing.T, replay core.ReplayStore) *httptest.Server {
	t.Helper()
	return serveHandler(t, f.origin, f.resolver, replay)
}

// serveHandler wraps an arbitrary origin with the SDK server face.
func serveHandler(
	t *testing.T, origin rampv1connect.ExchangeServiceHandler,
	resolver *helpers.StaticKeyResolver, replay core.ReplayStore,
) *httptest.Server {
	t.Helper()
	path, h := rampserver.NewExchangeServiceHandler(
		origin,
		rampserver.WithKeyResolver(resolver),
		rampserver.WithReplayStore(replay),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// 5. Server interceptor order + replay.
// ---------------------------------------------------------------------------

// TestServerVerify_RejectsReplayViaInjectedStore pins that the verify face calls
// the INJECTED ReplayStore.SeenOrAdd as part of fail-closed verification and
// rejects a replayed request with connect.CodeUnauthenticated — and the origin
// handler never runs (the side effect that MUST be absent). The store reporting
// "seen" forces the replay branch deterministically on a properly-signed request.
func TestServerVerify_RejectsReplayViaInjectedStore(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	srv := f.serve(t, alwaysReplayStore{}) // every nonce is a replay

	client := rampconnect.NewClient(srv.URL, rampconnect.WithSigner(f.signer))
	_, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err == nil {
		t.Fatal("a replayed request must be rejected by the verify face")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("replay: want CodeUnauthenticated, got %v (err=%v)", got, err)
	}
	if f.origin.hitCount() != 0 {
		t.Fatalf("origin handler must NOT run on a rejected replay, ran %d times", f.origin.hitCount())
	}
}

// TestServerVerify_FirstRequestAcceptedReplayRejected pins the two-call replay
// contract through the real client→server path: the client discovers a genuinely
// signed offer, obtains an SDK-minted VerifiedOffer, and Executes it twice reusing
// the SAME idempotency key. The first Execute is accepted (nonce new), the second
// is rejected as a replay by the injected store. First accepted, second rejected.
func TestServerVerify_FirstRequestAcceptedReplayRejected(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	off := signedOffer(t)
	replay := newCountingReplayStore()
	srv := serveHandler(t, &offerExchange{offer: off.offer}, f.resolver, replay)

	client := rampconnect.NewClient(srv.URL,
		rampconnect.WithSigner(f.signer),
		rampconnect.WithOfferKey(off.exchangePub),
		// A purchase carries a detached acceptance covering the requester, so a
		// client that has not been told who it is cannot buy.
		rampconnect.WithRequester(&rampv1.Requester{
			Id:     "https://agent.test",
			Domain: "agent.test",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		}),
	)
	res, err := client.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Verified()) != 1 {
		t.Fatalf("want 1 verified offer to Execute, got %d", len(res.Verified()))
	}
	verified := res.Verified()[0]

	// Fixed idempotency key pins the nonce across both Execute calls so the second
	// is a genuine replay of the first.
	if _, err := client.Execute(context.Background(), verified, rampconnect.WithIdempotencyKey("fixed-nonce")); err != nil {
		t.Fatalf("first Execute must be accepted: %v", err)
	}
	_, err = client.Execute(context.Background(), verified, rampconnect.WithIdempotencyKey("fixed-nonce"))
	if err == nil {
		t.Fatal("second Execute reusing the nonce must be rejected as a replay")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("replay: want CodeUnauthenticated, got %v (err=%v)", got, err)
	}
}

// TestServerVerify_RequestIDStampedOnRejectPath pins the amended interceptor
// order — request-id is OUTERMOST of the server face, so an auth-rejection
// response still carries the stamped X-Request-ID (reject-path log correlation
// must not regress). A replayed (rejected) request must come back with a
// non-empty X-Request-ID response header. The header is read directly off a real
// HTTP response through a spying RoundTripper wrapped around the SDK's signing
// transport, so the request is properly signed yet rejected on replay.
func TestServerVerify_RequestIDStampedOnRejectPath(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	srv := f.serve(t, alwaysReplayStore{})

	spy := &headerSpyTransport{next: core.NewSigningTransport(f.signer, http.DefaultTransport)}
	client := rampv1connect.NewExchangeServiceClient(&http.Client{Transport: spy}, srv.URL)

	_, err := client.DiscoverResources(context.Background(), connectrpc.NewRequest(&rampv1.ResourceQuery{}))
	if err == nil {
		t.Fatal("replay must be rejected")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("replay: want CodeUnauthenticated, got %v", got)
	}
	if spy.respRequestID == "" {
		t.Fatal("reject path must carry a stamped X-Request-ID (request-id is OUTERMOST)")
	}
}

// headerSpyTransport records the X-Request-ID from the response, letting the test
// assert the reject path is stamped. It wraps the SDK signing transport so the
// request is still properly signed.
type headerSpyTransport struct {
	next          http.RoundTripper
	respRequestID string
}

func (s *headerSpyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.next.RoundTrip(req)
	if resp != nil {
		s.respRequestID = resp.Header.Get("X-Request-ID")
	}
	return resp, err
}

// ---------------------------------------------------------------------------
// Helpers shared by the two-call replay test.
// ---------------------------------------------------------------------------

type serverOffer struct {
	exchangePub ed25519.PublicKey
	offer       *rampv1.Offer
}

func signedOffer(t *testing.T) serverOffer {
	t.Helper()
	exPub, exPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("exchange keygen: %v", err)
	}
	o := &rampv1.Offer{
		OfferId:   "offer-1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
		Pricing:   &rampv1.Pricing{Rate: "0.05", Currency: "USD"},
	}
	sig, err := helpers.SignOffer(exPriv, o)
	if err != nil {
		t.Fatalf("sign offer: %v", err)
	}
	o.Signature = sig
	o.SignatureAlgorithm = helpers.OfferSignatureAlgorithm
	return serverOffer{exchangePub: exPub, offer: o}
}
