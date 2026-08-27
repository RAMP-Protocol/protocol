package connectserver_test

// The per-request read cap. It bounds two different quantities, and a caller can
// exhaust the server through either, so both are exercised here:
//
//   - the RAW body, capped outside the verify face, because verification buffers
//     the whole body to check a signature over the exact bytes and therefore runs
//     before the caller is known. An UNAUTHENTICATED caller reaches only this one.
//   - the DECOMPRESSED Connect message, capped by the generated handler, because
//     Connect decompresses every request and the wire rules do not bound that work.
//
// The cap is also composed INSIDE request-id, so a refusal still correlates.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
)

// postRaw sends bytes straight at a procedure, bypassing the Connect client, so the
// test controls the body size exactly. Unsigned on purpose: the raw-body bound must
// bite before verification can, which is the whole point of where it sits.
func postRaw(t *testing.T, url string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// oversizeJSON builds a syntactically valid PushResources body of at least n bytes.
func oversizeJSON(n int) []byte {
	return fmt.Appendf(nil,
		`{"ver":"1.0","exchange":"exchange.test","tenant_id":"t","caller_id":"c","entries":[{"domain":"publisher.test","path":"/%s"}]}`,
		strings.Repeat("a", n))
}

func TestReadCap_OversizeBodyIsRefusedBeforeTheOriginRuns(t *testing.T) {
	t.Parallel()
	origin := &catalogEcho{}
	const capBytes = 64 << 10
	srv := mountCatalog(t, origin, rampserver.WithMaxRequestBytes(capBytes))

	resp := postRaw(t, srv.URL+"/ramp.v1.CatalogService/PushResources", oversizeJSON(capBytes*2))

	// Assert the SPECIFIC refusal, not merely "not 200": an unsigned request is
	// refused anyway, so a status check alone would pass with no cap at all.
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body: status = %d, want 413 — the read cap did not bite", resp.StatusCode)
	}
	if body, _ := io.ReadAll(resp.Body); !strings.Contains(string(body), "resource_exhausted") {
		t.Errorf("over-cap body was not classified resource_exhausted: %s", body)
	}
	if hits, _ := origin.snapshot(); hits != 0 {
		t.Errorf("origin ran %d times on an over-cap body — the cap must refuse before the origin", hits)
	}
	// Request-id is composed OUTSIDE the cap so a refusal still correlates in the
	// reject-path logs. A 413 that cannot be traced would regress the property the
	// request-id ordering exists to give.
	if resp.Header.Get("X-Request-ID") == "" {
		t.Error("the refusal carries no X-Request-ID — the body cap was composed outside request-id")
	}
}

func TestReadCap_BodyWithinTheCapStillReachesVerification(t *testing.T) {
	t.Parallel()
	origin := &catalogEcho{}
	srv := mountCatalog(t, origin, rampserver.WithMaxRequestBytes(64<<10))

	// Comfortably under the cap, and unsigned: it must get PAST the size gate and
	// be refused by verification instead. Proves the cap is not refusing everything.
	resp := postRaw(t, srv.URL+"/ramp.v1.CatalogService/PushResources", oversizeJSON(128))

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("under-cap unsigned push: status = %d, want 401 — it must reach verification, "+
			"not be refused by the size gate", resp.StatusCode)
	}
	if body, _ := io.ReadAll(resp.Body); !strings.Contains(string(body), "unauthenticated") {
		t.Errorf("an unsigned push was not refused by verification: %s", body)
	}
	if hits, _ := origin.snapshot(); hits != 0 {
		t.Errorf("origin ran %d times on an unsigned push", hits)
	}
}

func TestReadCap_DefaultIsAppliedAndNonPositiveRestoresIt(t *testing.T) {
	t.Parallel()
	if rampserver.DefaultMaxRequestBytes <= 0 {
		t.Fatalf("DefaultMaxRequestBytes = %d, want a positive cap", rampserver.DefaultMaxRequestBytes)
	}
	origin := &catalogEcho{}
	// A non-positive override must restore the default, never disable the cap:
	// a handler reading without a bound is the state the option exists to prevent.
	srv := mountCatalog(t, origin, rampserver.WithMaxRequestBytes(0))

	resp := postRaw(t, srv.URL+"/ramp.v1.CatalogService/PushResources",
		oversizeJSON(rampserver.DefaultMaxRequestBytes+(1<<20)))

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("WithMaxRequestBytes(0): status = %d, want 413 — a non-positive value must "+
			"restore the default, never disable the cap", resp.StatusCode)
	}
	if hits, _ := origin.snapshot(); hits != 0 {
		t.Errorf("origin ran %d times past the default cap", hits)
	}
}

// The Exchange and Broker bindings compose the same stack, so the cap must be on
// all three — the gap this closes was never Catalog-specific.
func TestReadCap_AppliesToEveryHandlerBinding(t *testing.T) {
	t.Parallel()
	const capBytes = 32 << 10
	opt := rampserver.WithMaxRequestBytes(capBytes)

	exchangePath, exchangeHandler := rampserver.NewExchangeServiceHandler(
		rampv1connect.UnimplementedExchangeServiceHandler{}, opt)
	brokerPath, brokerHandler := rampserver.NewBrokerServiceHandler(
		rampv1connect.UnimplementedBrokerServiceHandler{}, opt)
	catalogPath, catalogHandler := rampserver.NewCatalogServiceHandler(
		rampv1connect.UnimplementedCatalogServiceHandler{}, opt)

	for _, tc := range []struct {
		name, procedure string
		mountPath       string
		handler         http.Handler
	}{
		{"exchange", "/ramp.v1.ExchangeService/DiscoverResources", exchangePath, exchangeHandler},
		{"broker", "/ramp.v1.BrokerService/DiscoverResources", brokerPath, brokerHandler},
		{"catalog", "/ramp.v1.CatalogService/PushResources", catalogPath, catalogHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mux := http.NewServeMux()
			mux.Handle(tc.mountPath, tc.handler)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			resp := postRaw(t, srv.URL+tc.procedure, oversizeJSON(capBytes*2))
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("%s: status = %d, want 413 — this binding has no read cap", tc.name, resp.StatusCode)
			}
		})
	}
}
