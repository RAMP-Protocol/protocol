package resolvers

// Endpoint-vet golden-vector emitter.
//
// The rule this locks is normative — WellKnownManifest.endpoint states it as a
// MUST — and it composes two things that are decided elsewhere: the anchor
// predicate (corpus-locked next door, in helpers/testdata/host-rule-vectors.json)
// and a refusal of userinfo. The composition needs its own corpus because the
// refusal is not the sum of its parts: an endpoint can be perfectly anchored and
// still be one no consumer may dial, and the shape that proved it is the one
// where the two halves used to read the reference differently.
//
// It sits in the resolvers package because the rule it emits is in an internal
// package this one already imports, and because the corpus directories the
// completeness gate walks are helpers/testdata and resolvers/testdata.
//
// Verification no-op by default (asserts the committed file matches a fresh
// emit); (re)writes under RAMP_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/internal/endpointrule"
)

// endpointVetVector is one Vet case: the host that SERVED the manifest, the
// endpoint that manifest advertised, and whether the rule refuses to hand it
// back. Refused carries no reason string on purpose — the three languages phrase
// their errors in their own vocabularies, and pinning prose would make the corpus
// a translation test instead of a rule test.
type endpointVetVector struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	Refused  bool   `json:"refused"`
}

// buildEndpointVetVectors enumerates what a manifest may advertise about itself.
//
// The credential cases are the reason this corpus exists in the shape it does.
// A consumer that refuses only the spelled-out https://user:pass@host form has
// refused a spelling, not a credential: the same value with no scheme is what a
// plain URL parse in all three languages reads as something other than an
// authority, and it reaches the anchor check as the very host it claims to be.
func buildEndpointVetVectors(t *testing.T) []endpointVetVector {
	t.Helper()
	const host = "exchange.example"
	cases := []struct {
		name     string
		host     string
		endpoint string
		want     bool
	}{
		// Accepted: the Exchange advertising itself, or one of its own subdomains.
		{"self", host, "https://exchange.example/v1", false},
		{"subdomain", host, "https://api.exchange.example/v1", false},
		{"default_port_written_out", host, "https://exchange.example:443/v1", false},
		{"non_default_port_on_both_sides", "exchange.example:8443", "https://exchange.example:8443/v1", false},
		{"schemeless_endpoint", host, "exchange.example/v1", false},
		{"plaintext_on_a_plaintext_anchor", "exchange.example:80", "http://exchange.example:80/v1", false},

		// Refused: not this Exchange.
		{"unrelated_host", host, "https://cdn.other.example/v1", true},
		{"label_boundary_trick", host, "https://evil-exchange.example/v1", true},
		{"parent_of_the_serving_host", "api.exchange.example", "https://exchange.example/v1", true},
		{"another_port", host, "https://exchange.example:8443/v1", true},
		{"subdomain_on_another_port", host, "https://api.exchange.example:8443/v1", true},

		// Refused: credentials. The host comparison reads past a user:password, so
		// without this the endpoint would pass and the HTTP client would stamp an
		// Authorization header the SDK never chose — on a leg that already carries
		// the caller's own signature.
		{"userinfo", host, "https://user:pass@exchange.example/v1", true},
		{"userinfo_without_a_password", host, "https://user@exchange.example/v1", true},
		{"schemeless_userinfo", host, "user:pass@exchange.example/v1", true},
		{"schemeless_userinfo_no_path", host, "user:pass@exchange.example", true},
		{"userinfo_on_a_subdomain", host, "https://user:pass@api.exchange.example/v1", true},

		// Refused: not a reference a host can be read out of at all.
		{"empty_endpoint", host, "", true},
		{"no_authority", host, "/v1", true},
		{"control_character", host, "https://exchange.example\n/v1", true},
		{"unusable_serving_host", "", "https://exchange.example/v1", true},
	}
	out := make([]endpointVetVector, 0, len(cases))
	for _, c := range cases {
		refused := endpointrule.Vet(c.host, c.endpoint) != nil
		if refused != c.want {
			t.Fatalf("endpoint_vet vector %s: oracle refused=%v, intended=%v (host=%q endpoint=%q)",
				c.name, refused, c.want, c.host, c.endpoint)
		}
		out = append(out, endpointVetVector{
			Name: c.name, Host: c.host, Endpoint: c.endpoint, Refused: refused,
		})
	}
	return out
}

// TestGenerateEndpointVetVectors emits the endpoint-vet golden corpus.
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateEndpointVetVectors(t *testing.T) {
	doc := map[string]any{"endpoint_vet": buildEndpointVetVectors(t)}
	path := filepath.Join("testdata", "endpoint-vet-vectors.json")
	want, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	want = append(want, '\n')
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil { //nolint:gosec // committed test vector
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", path)
	}
}
