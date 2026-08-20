package connect

// Transport-failure cross-language golden-vector emitter.
//
// The connect-error corpus next door records what a RAMP SERVICE says when it refuses:
// a Connect envelope with a code and a typed detail. This one records the other half —
// what reaches a client when the answer did not come from the service at all.
//
// That half matters because the peers on three of these legs sit behind whatever a
// deployment puts in front of them. A load balancer draining, a gateway with no upstream,
// a proxy returning its own HTML page: none of those is a Connect envelope, and the
// difference between "the Exchange declined this" and "nothing answered" is exactly the
// distinction the failure classes exist to carry. Report a momentary 502 as a refusal and
// a caller stops retrying a usage report that would have succeeded a second later —
// the outcome route.go argues at length must not happen.
//
// connect-go already decides this, and it does not guess: for a body it cannot read as an
// envelope, and for an envelope carrying no code, it derives the code from the HTTP
// STATUS (protocol_connect.go, via httpToCode). So the vectors are CAPTURED the same way
// the envelope corpus is — a real connect-go client against a server that answers with
// raw bytes — rather than transcribing that table into three languages. Nothing here
// restates the mapping; if a future connect-go changes it, the drift gate reports it.
//
// Like the other emitters this is a verification no-op by default and (re)writes the file
// under RAMP_UPDATE_VECTORS=1. It is TEST INFRASTRUCTURE, not the code under test.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/vectorio"
)

const transportFailureVectorsPath = "testdata/transport-failure-vectors.json"

type transportFailureVector struct {
	Name string `json:"name"`
	// Status is what the thing in front of the service answered with.
	Status int `json:"status"`
	// Body is the bytes it sent. Not an envelope in most cases — that is the point.
	Body string `json:"body"`
	// ContentType as served, because a proxy's HTML page announces itself.
	ContentType string `json:"content_type"`
	// Kind is the failure class every SDK must report, as the Go client reports it.
	Kind string `json:"kind"`
	// Reason is the Connect code the client derived, or "" when it derived none.
	Reason string `json:"reason"`
	// Retryable restates the consequence the class carries, so a replay that only
	// compared the label would still be asserting the thing that matters.
	Retryable bool `json:"retryable"`
}

// The answers a deployment's own infrastructure gives, none of them from the service.
var transportFailureCases = []struct {
	name        string
	status      int
	body        string
	contentType string
}{
	{"gateway_502_html", http.StatusBadGateway, "<html><body>502 Bad Gateway</body></html>", "text/html"},
	{"gateway_503_empty", http.StatusServiceUnavailable, "", "text/plain"},
	{"gateway_504_text", http.StatusGatewayTimeout, "upstream timed out", "text/plain"},
	{"gateway_500_html", http.StatusInternalServerError, "<html>500</html>", "text/html"},
	{"throttled_429_empty", http.StatusTooManyRequests, "", "text/plain"},
	{"not_found_404_html", http.StatusNotFound, "<html>404</html>", "text/html"},
	{"unauthorized_401_empty", http.StatusUnauthorized, "", "text/plain"},
	{"bad_request_400_text", http.StatusBadRequest, "malformed", "text/plain"},
	// A JSON body that IS well-formed and carries no code: connect-go falls back to the
	// status for this one too, which is the case a reader looking only for `code` misses.
	{"json_envelope_without_a_code", http.StatusServiceUnavailable, `{"message":"draining"}`, "application/json"},
}

func buildTransportFailureVectors(t *testing.T) []transportFailureVector {
	t.Helper()
	out := make([]transportFailureVector, 0, len(transportFailureCases))
	for _, c := range transportFailureCases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", c.contentType)
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		client := NewClient(srv.URL)
		_, err := client.Discover(context.Background(), &rampv1.ResourceQuery{Exchange: "exchange.test"})
		srv.Close()
		if err == nil {
			t.Fatalf("%s: the client accepted a %d answer", c.name, c.status)
		}
		var callErr *CallError
		if !errors.As(err, &callErr) {
			t.Fatalf("%s: not a typed failure: %v", c.name, err)
		}
		out = append(out, transportFailureVector{
			Name:        c.name,
			Status:      c.status,
			Body:        c.body,
			ContentType: c.contentType,
			Kind:        callErr.Kind.String(),
			Reason:      callErr.Reason,
			Retryable:   callErr.Kind == CallUnreachable,
		})
	}
	return out
}

func TestGenerateTransportFailureVectors(t *testing.T) {
	doc := map[string]any{"transport_failures": buildTransportFailureVectors(t)}
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(transportFailureVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", transportFailureVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(transportFailureVectorsPath, doc)
	if err != nil {
		t.Fatalf("compare %s: %v", transportFailureVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale — regenerate with RAMP_UPDATE_VECTORS=1", transportFailureVectorsPath)
	}
}
