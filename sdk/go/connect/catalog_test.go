package connect_test

import (
	"context"
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

// The publisher's three verbs, driven through the outermost public surface: an
// SDK-built catalog client over real HTTP to a real Connect handler running the
// SDK's own server verify face.

// recordingCatalog answers every catalog RPC and records what reached it. Like a
// real Exchange it refuses a caller the verify seam did not prove.
type recordingCatalog struct {
	rampv1connect.UnimplementedCatalogServiceHandler
	mu      sync.Mutex
	push    *rampv1.PushResourcesRequest
	remove  *rampv1.RemoveResourcesRequest
	refresh *rampv1.RefreshCatalogRequest
	hits    int
	reject  *rampv1.ErrorDetail // when set, PushResources fails with this typed detail
}

func (c *recordingCatalog) PushResources(
	ctx context.Context, req *connectrpc.Request[rampv1.PushResourcesRequest],
) (*connectrpc.Response[rampv1.PushResourcesResponse], error) {
	if helpers.FromContext(ctx) == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits++
	c.push = req.Msg
	if c.reject != nil {
		cerr := connectrpc.NewError(connectrpc.CodeInvalidArgument, errors.New("push rejected"))
		return nil, rampserver.AttachDetail(cerr, c.reject)
	}
	return connectrpc.NewResponse(&rampv1.PushResourcesResponse{
		Ver: helpers.ProtocolVersion, Accepted: int32(len(req.Msg.GetEntries())),
		Warnings: []string{"unregistered RESTRICTION_KIND_FUNCTION restriction token \"flib\" (term accepted)"},
	}), nil
}

func (c *recordingCatalog) RemoveResources(
	ctx context.Context, req *connectrpc.Request[rampv1.RemoveResourcesRequest],
) (*connectrpc.Response[rampv1.RemoveResourcesResponse], error) {
	if helpers.FromContext(ctx) == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits++
	c.remove = req.Msg
	return connectrpc.NewResponse(&rampv1.RemoveResourcesResponse{
		Ver: helpers.ProtocolVersion, Removed: int32(len(req.Msg.GetPaths())),
	}), nil
}

func (c *recordingCatalog) RefreshCatalog(
	ctx context.Context, req *connectrpc.Request[rampv1.RefreshCatalogRequest],
) (*connectrpc.Response[rampv1.RefreshCatalogResponse], error) {
	if helpers.FromContext(ctx) == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits++
	c.refresh = req.Msg
	return connectrpc.NewResponse(&rampv1.RefreshCatalogResponse{Ver: helpers.ProtocolVersion, Started: true}), nil
}

func (c *recordingCatalog) hitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits
}

// serveCatalog mounts the origin behind the SDK's own Catalog server binding.
func serveCatalog(t *testing.T, sig signingFixture, svc rampv1connect.CatalogServiceHandler) *httptest.Server {
	t.Helper()
	path, h := rampserver.NewCatalogServiceHandler(svc, rampserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func catalogEntry() *rampv1.ResourceEntry {
	return &rampv1.ResourceEntry{Domain: "publisher.test", Path: "/premium/article-42.html", Terms: []*rampv1.LicenseTerm{{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"},
	}}}
}

// A signed push reaches the origin through the SDK's server verify face, with the
// version stamped and the caller's own addressing left alone, and the origin's
// counts and warnings come back as the typed response.
func TestCatalog_PushIsSignedStampedAndAnswered(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingCatalog{}
	srv := serveCatalog(t, sig, origin)
	client := rampconnect.NewCatalogClient(srv.URL, append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	req := &rampv1.PushResourcesRequest{
		Exchange: "exchange.test", TenantId: "tenant-1", CallerId: "publisher.test",
		Entries: []*rampv1.ResourceEntry{catalogEntry()},
	}
	resp, err := client.PushResources(context.Background(), req)
	if err != nil {
		t.Fatalf("PushResources: %v", err)
	}
	if resp.GetAccepted() != 1 || len(resp.GetWarnings()) != 1 {
		t.Errorf("response = %+v, want accepted=1 with one warning", resp)
	}
	if origin.push.GetVer() != helpers.ProtocolVersion {
		t.Errorf("ver on the wire = %q, want %q", origin.push.GetVer(), helpers.ProtocolVersion)
	}
	if origin.push.GetExchange() != "exchange.test" || origin.push.GetCallerId() != "publisher.test" {
		t.Errorf("addressing on the wire = %q/%q, want the caller's own", origin.push.GetExchange(), origin.push.GetCallerId())
	}
	if req.GetVer() != "" {
		t.Error("the caller's request was modified; the client must stamp a clone")
	}
}

// The caller's own version survives, and no idempotency key is ever minted: the
// catalog messages carry none.
func TestCatalog_RemoveAndRefreshKeepTheCallersVersion(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingCatalog{}
	srv := serveCatalog(t, sig, origin)
	client := rampconnect.NewCatalogClient(srv.URL, append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	if _, err := client.RemoveResources(context.Background(), &rampv1.RemoveResourcesRequest{
		Exchange: "exchange.test", TenantId: "tenant-1", Paths: []string{"/x"}, Ver: "9.9",
	}); err != nil {
		t.Fatalf("RemoveResources: %v", err)
	}
	if origin.remove.GetVer() != "9.9" {
		t.Errorf("remove ver = %q, want the caller's 9.9", origin.remove.GetVer())
	}
	resp, err := client.RefreshCatalog(context.Background(), &rampv1.RefreshCatalogRequest{
		Exchange: "exchange.test", TenantId: "tenant-1",
	})
	if err != nil {
		t.Fatalf("RefreshCatalog: %v", err)
	}
	if !resp.GetStarted() || origin.refresh.GetVer() != helpers.ProtocolVersion {
		t.Errorf("refresh: started=%v ver=%q", resp.GetStarted(), origin.refresh.GetVer())
	}
	if origin.hitCount() != 2 {
		t.Errorf("origin ran %d times, want 2", origin.hitCount())
	}
}

// A request that names no recipient, or names one that is not a bare host, is
// refused before anything is signed or sent — the same verdict a dispute with no
// exchange gets.
func TestCatalog_RefusesAnUnaddressedRequestBeforeSending(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingCatalog{}
	srv := serveCatalog(t, sig, origin)
	client := rampconnect.NewCatalogClient(srv.URL, append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	for name, exchange := range map[string]string{
		"empty":       "",
		"with_scheme": "https://exchange.test",
		"with_path":   "exchange.test/catalog",
		"userinfo":    "u:p@exchange.test",
	} {
		_, err := client.PushResources(context.Background(), &rampv1.PushResourcesRequest{
			Exchange: exchange, TenantId: "tenant-1", Entries: []*rampv1.ResourceEntry{catalogEntry()},
		})
		var cerr *rampconnect.CallError
		if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallNotSent {
			t.Errorf("%s: error = %v, want a CallNotSent CallError", name, err)
		}
	}
	if _, err := client.RemoveResources(context.Background(), &rampv1.RemoveResourcesRequest{Paths: []string{"/x"}}); err == nil {
		t.Error("remove with no exchange must be refused")
	}
	if _, err := client.RefreshCatalog(context.Background(), nil); err == nil {
		t.Error("a nil request must be refused")
	}
	if origin.hitCount() != 0 {
		t.Errorf("origin ran %d times; a refused request must never be sent", origin.hitCount())
	}
}

// An unsigned catalog client is refused by the server face before the origin
// runs: the binding gates every catalog procedure, fail-closed.
func TestCatalog_UnsignedPushNeverReachesTheOrigin(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingCatalog{}
	srv := serveCatalog(t, sig, origin)
	client := rampconnect.NewCatalogClient(srv.URL, allowLoopback(t)...)

	_, err := client.PushResources(context.Background(), &rampv1.PushResourcesRequest{
		Exchange: "exchange.test", TenantId: "tenant-1", Entries: []*rampv1.ResourceEntry{catalogEntry()},
	})
	if err == nil {
		t.Fatal("unsigned push must be refused")
	}
	if origin.hitCount() != 0 {
		t.Errorf("origin ran %d times on an unsigned push", origin.hitCount())
	}
}

// A push the Exchange refuses as a whole comes back as a non-OK call whose typed
// reason is readable through the same ErrorDetail bridge every other verb uses.
func TestCatalog_TypedRejectionIsReadable(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingCatalog{reject: helpers.CatalogRejectionDetail(
		"ramp.v1.CatalogService", "caller is not a contributor for publisher.test",
		rampv1.CatalogRejectionReason_CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR)}
	srv := serveCatalog(t, sig, origin)
	client := rampconnect.NewCatalogClient(srv.URL, append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.PushResources(context.Background(), &rampv1.PushResourcesRequest{
		Exchange: "exchange.test", TenantId: "tenant-1", Entries: []*rampv1.ResourceEntry{catalogEntry()},
	})
	if err == nil {
		t.Fatal("expected the rejection")
	}
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallRefused {
		t.Fatalf("error = %v, want a CallRefused CallError", err)
	}
	detail, ok := rampconnect.ErrorDetailFrom(err)
	if !ok {
		t.Fatal("no typed ErrorDetail on the refusal")
	}
	if got := detail.GetCatalogRejection().GetReason(); got != rampv1.CatalogRejectionReason_CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR {
		t.Errorf("reason = %v, want NOT_CATALOG_CONTRIBUTOR", got)
	}
}
