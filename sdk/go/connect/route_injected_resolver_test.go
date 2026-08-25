package connect

// The client re-checks whatever an injected EndpointResolver hands back — replay of the
// shared endpoint-vet corpus, driven through the CLIENT rather than through the resolver.
//
// Mirrors sdk/ts/tests/client-injected-resolver.parity.test.ts and
// sdk/python/tests/test_client_injected_resolver_parity.py.
//
// The corpus already pins WHAT the endpoint rule decides, and every language replays it
// against the resolver. What it did not pin is that the client applies the rule at all to
// a resolver it did not write — and EndpointResolver is a documented, encouraged seam, so
// "a caller supplied one" is the ordinary case rather than an exotic one. Go has always
// done this; the corpus replay is what stops the other two drifting away from it, and what
// would catch Go losing it.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const endpointVetVectorsPath = "../resolvers/testdata/endpoint-vet-vectors.json"

type endpointVetVector struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	Refused  bool   `json:"refused"`
}

// answeringResolver answers exactly what a vector says, checking nothing.
type answeringResolver struct{ endpoint string }

func (r answeringResolver) ResolveEndpoint(context.Context, string) (string, error) {
	return r.endpoint, nil
}

func TestInjectedResolverAnswerIsRecheckedAgainstTheEndpointRule(t *testing.T) {
	raw, err := os.ReadFile(endpointVetVectorsPath) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", endpointVetVectorsPath, err)
	}
	var doc struct {
		EndpointVet []endpointVetVector `json:"endpoint_vet"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", endpointVetVectorsPath, err)
	}
	var refused int
	for _, v := range doc.EndpointVet {
		if v.Refused {
			refused++
		}
	}
	if len(doc.EndpointVet) == 0 || refused == 0 {
		t.Fatalf("%s carries %d vectors, %d of them refusals — the replay would assert nothing",
			endpointVetVectorsPath, len(doc.EndpointVet), refused)
	}

	for _, v := range doc.EndpointVet {
		// A vector whose serving host is not a usable host is refused before the resolver
		// is reached, by the bare-host check; the resolver replay covers that path.
		if v.Host == "" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			got, err := vetExchangeEndpoint(
				context.Background(), answeringResolver{endpoint: v.Endpoint}, v.Host, "report usage")
			if !v.Refused {
				if err != nil {
					t.Fatalf("allowed endpoint refused: %v", err)
				}
				if got != v.Endpoint {
					t.Errorf("endpoint = %q, want %q", got, v.Endpoint)
				}
				return
			}
			if err == nil {
				t.Fatalf("refused endpoint %q was accepted", v.Endpoint)
			}
			// A verdict, not a transport failure: reporting it as transient would tell a
			// caller to retry something that can never succeed.
			var callErr *CallError
			if !errors.As(err, &callErr) || callErr.Kind != CallNotSent {
				t.Errorf("kind = %v, want CallNotSent", err)
			}
			// The refusal reaches a log; an endpoint carrying userinfo must not.
			if strings.Contains(err.Error(), "pass@") {
				t.Errorf("refusal echoed a credential: %v", err)
			}
		})
	}
}
