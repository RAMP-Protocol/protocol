package connectserver_test

// The CatalogService handler binding: the exchange-operator role's starting point
// for the publisher-facing RPCs. It must compose the same request-id · verify ·
// validate · error-detail stack as the Exchange and Broker bindings — an unsigned
// push never reaches the origin, a signed one arrives with the proven signature in
// context, and a malformed entry is refused by the validate interceptor before the
// origin sees it.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// catalogEcho is a minimal CatalogServiceHandler that, like a real Exchange, refuses
// a caller the seam did not prove and otherwise counts the pushes it applied.
type catalogEcho struct {
	rampv1connect.UnimplementedCatalogServiceHandler
	mu      sync.Mutex
	hits    int
	callers []string
}

func (c *catalogEcho) PushResources(
	ctx context.Context, req *connectrpc.Request[rampv1.PushResourcesRequest],
) (*connectrpc.Response[rampv1.PushResourcesResponse], error) {
	sig := helpers.FromContext(ctx)
	if sig == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	c.mu.Lock()
	c.hits++
	c.callers = append(c.callers, sig.KeyID)
	c.mu.Unlock()
	return connectrpc.NewResponse(&rampv1.PushResourcesResponse{
		Ver: helpers.ProtocolVersion, Accepted: int32(len(req.Msg.GetEntries())),
	}), nil
}

func (c *catalogEcho) snapshot() (int, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, append([]string(nil), c.callers...)
}

func mountCatalog(t *testing.T, origin rampv1connect.CatalogServiceHandler, opts ...rampserver.ServerOption) *httptest.Server {
	t.Helper()
	path, h := rampserver.NewCatalogServiceHandler(origin, opts...)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func validPush() *rampv1.PushResourcesRequest {
	return &rampv1.PushResourcesRequest{
		Exchange: "exchange.test", TenantId: "tenant-1", CallerId: "publisher.test",
		Entries: []*rampv1.ResourceEntry{{Domain: "publisher.test", Path: "/x", Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"},
		}}}},
	}
}

func TestServerVerify_CatalogHandlerRejectsUnsigned(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"publisher.v1": pub})
	origin := &catalogEcho{}
	srv := mountCatalog(t, origin, rampserver.WithKeyResolver(resolver), rampserver.WithReplayStore(alwaysReplayStore{}))

	raw := rampv1connect.NewCatalogServiceClient(&http.Client{}, srv.URL)
	_, err = raw.PushResources(context.Background(), connectrpc.NewRequest(validPush()))
	if err == nil {
		t.Fatal("unsigned push must be rejected by the catalog server face")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("unsigned push: want CodeUnauthenticated, got %v (err=%v)", got, err)
	}
	if hits, _ := origin.snapshot(); hits != 0 {
		t.Fatalf("origin PushResources must NOT run on a rejected unsigned push; ran %d times", hits)
	}
}

func TestServerVerify_CatalogHandlerProvesTheSignerToTheOrigin(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "publisher.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub})
	origin := &catalogEcho{}
	srv := mountCatalog(t, origin, rampserver.WithKeyResolver(resolver), rampserver.WithReplayStore(newCountingReplayStore()))

	client := rampconnect.NewCatalogClient(srv.URL, rampconnect.WithSigner(signer))
	resp, err := client.PushResources(context.Background(), validPush())
	if err != nil {
		t.Fatalf("PushResources: %v", err)
	}
	if resp.GetAccepted() != 1 {
		t.Errorf("accepted = %d, want 1", resp.GetAccepted())
	}
	hits, callers := origin.snapshot()
	if hits != 1 || len(callers) != 1 || callers[0] != keyID {
		t.Errorf("origin saw hits=%d callers=%v, want one call proven as %q", hits, callers, keyID)
	}
}

// With strict validation the binding refuses a malformed entry before the origin
// runs, with the protovalidate violation on the InvalidArgument error — the wire
// tier of the two-tier check, applied at the seam as the contract states.
func TestServerVerify_CatalogHandlerValidatesTheEnvelope(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "publisher.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub})
	origin := &catalogEcho{}
	srv := mountCatalog(t, origin,
		rampserver.WithKeyResolver(resolver),
		rampserver.WithReplayStore(newCountingReplayStore()),
		rampserver.WithValidation(rampconnect.ValidationStrict),
	)

	client := rampconnect.NewCatalogClient(srv.URL, rampconnect.WithSigner(signer))
	bad := validPush()
	bad.Entries[0].Path = "no-leading-slash"
	_, err = client.PushResources(context.Background(), bad)
	if err == nil {
		t.Fatal("a malformed entry must be refused")
	}
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallRefused {
		t.Fatalf("error = %v, want a CallRefused CallError from the validate interceptor", err)
	}
	if hits, _ := origin.snapshot(); hits != 0 {
		t.Fatalf("origin ran %d times on a malformed push; the validate interceptor must refuse first", hits)
	}
}
