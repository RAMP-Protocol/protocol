package resolvers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// requirementsManifest serves a manifest carrying the members the registration
// reader looks at. A nil digest or schema omits the member entirely, which is how
// "this Exchange publishes none" looks on the wire. It counts requests, because
// the reader's central promise is that every read is a fresh fetch.
func requirementsManifest(role string, digest *string, schema json.RawMessage, hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		doc := map[string]any{"role": role, "endpoint": "https://exchange.test"}
		if digest != nil {
			doc["terms_digest"] = *digest
		}
		if schema != nil {
			doc["account_registration"] = map[string]any{"data_schema": schema}
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
}

// loopbackReader builds a reader against a loopback manifest server. The default
// client is SSRF-guarded and would refuse the address, so the test injects an
// unguarded one exactly as the endpoint-resolver tests do.
func loopbackReader(allow func(string) bool) *resolvers.WellKnownRequirementsReader {
	return resolvers.NewWellKnownRequirementsReader(resolvers.WellKnownOptions{
		Scheme: "http",
		HTTP:   http.DefaultClient,
		Allow:  allow,
	})
}

const acceptedSchema = `{"type":"object","required":["legal_entity"],` +
	`"properties":{"legal_entity":{"type":"string"}}}`

func TestRequirements_readsDigestAndSchema(t *testing.T) {
	digest := "sha256:" + repeat64("ab")
	srv := httptest.NewServer(requirementsManifest(
		"ROLE_EXCHANGE", &digest, json.RawMessage(acceptedSchema), nil))
	defer srv.Close()

	got, err := loopbackReader(nil).ResolveRegistrationRequirements(
		context.Background(), hostOf(t, srv))
	if err != nil {
		t.Fatalf("resolve requirements: %v", err)
	}
	if got.TermsDigest == nil || *got.TermsDigest != digest {
		t.Fatalf("terms digest = %v, want %q", got.TermsDigest, digest)
	}
	if got.Verdict != helpers.SchemaAccepted {
		t.Fatalf("verdict = %v, want accepted", got.Verdict)
	}
	// The schema is not merely present, it is the one that was served: a payload
	// missing the required member must fail against it.
	if fails := got.Schema.Validate(map[string]any{}); len(fails) == 0 {
		t.Fatal("compiled schema accepted a payload missing a required member")
	}
	if fails := got.Schema.Validate(map[string]any{"legal_entity": "Acme"}); len(fails) != 0 {
		t.Fatalf("compiled schema refused a conforming payload: %v", fails)
	}
}

// The rule this reader exists for: a cached endpoint is fine, a cached digest is
// not. Two reads must produce two fetches, and the second must see the new value.
func TestRequirements_everyReadIsAFreshFetch(t *testing.T) {
	digest := "sha256:" + repeat64("ab")
	hits := 0
	srv := httptest.NewServer(requirementsManifest("ROLE_EXCHANGE", &digest, nil, &hits))
	defer srv.Close()
	r := loopbackReader(nil)
	host := hostOf(t, srv)

	if _, err := r.ResolveRegistrationRequirements(context.Background(), host); err != nil {
		t.Fatalf("first read: %v", err)
	}
	digest = "sha256:" + repeat64("cd")
	got, err := r.ResolveRegistrationRequirements(context.Background(), host)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if hits != 2 {
		t.Fatalf("manifest fetches = %d, want 2; the digest was served from a cache", hits)
	}
	if got.TermsDigest == nil || *got.TermsDigest != digest {
		t.Fatalf("second read returned %v, want the revised %q", got.TermsDigest, digest)
	}
}

func TestRequirements_publishingNeitherIsANormalAnswer(t *testing.T) {
	srv := httptest.NewServer(requirementsManifest("ROLE_EXCHANGE", nil, nil, nil))
	defer srv.Close()

	got, err := loopbackReader(nil).ResolveRegistrationRequirements(
		context.Background(), hostOf(t, srv))
	if err != nil {
		t.Fatalf("an Exchange publishing neither member is not an error: %v", err)
	}
	if got.TermsDigest != nil {
		t.Fatalf("terms digest = %q, want nil", *got.TermsDigest)
	}
	if got.Schema != nil || got.Verdict != helpers.SchemaNotPublished {
		t.Fatalf("schema = %v verdict = %v, want nil / not_published", got.Schema, got.Verdict)
	}
}

// A schema this SDK refuses is reported, never raised: the contract requires a
// client that cannot check locally to send anyway and let the Exchange decide.
func TestRequirements_aRefusedSchemaIsAVerdictNotAnError(t *testing.T) {
	wrongDialect := json.RawMessage(
		`{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object"}`)
	srv := httptest.NewServer(requirementsManifest("ROLE_EXCHANGE", nil, wrongDialect, nil))
	defer srv.Close()

	got, err := loopbackReader(nil).ResolveRegistrationRequirements(
		context.Background(), hostOf(t, srv))
	if err != nil {
		t.Fatalf("a refused schema must not fail the read: %v", err)
	}
	if got.Verdict != helpers.SchemaWrongDialect {
		t.Fatalf("verdict = %v, want wrong_dialect", got.Verdict)
	}
	if got.Schema != nil {
		t.Fatal("a refused schema must not be returned")
	}
	// And the nil schema must behave as "nothing to enforce" rather than as a veto.
	if fails := got.Schema.Validate(map[string]any{}); len(fails) != 0 {
		t.Fatalf("a refused schema became a local veto: %v", fails)
	}
}

func TestRequirements_refusesBeforeDialling(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(requirementsManifest("ROLE_EXCHANGE", nil, nil, &hits))
	defer srv.Close()
	host := hostOf(t, srv)

	t.Run("a value that is not a bare domain", func(t *testing.T) {
		// A path smuggled into the domain would choose WHAT is fetched, because the
		// URL is built by concatenation.
		_, err := loopbackReader(nil).ResolveRegistrationRequirements(
			context.Background(), host+"/evil")
		if !errors.Is(err, helpers.ErrInvalidHost) {
			t.Fatalf("err = %v, want ErrInvalidHost", err)
		}
	})

	t.Run("a domain the deployment excludes", func(t *testing.T) {
		_, err := loopbackReader(func(string) bool { return false }).
			ResolveRegistrationRequirements(context.Background(), host)
		if !errors.Is(err, resolvers.ErrExchangeNotPermitted) {
			t.Fatalf("err = %v, want ErrExchangeNotPermitted", err)
		}
	})

	if hits != 0 {
		t.Fatalf("manifest fetches = %d, want 0; a refusal reached the network", hits)
	}
}

// Registration requirements are an Exchange's to publish. A manifest claiming
// another role is refused rather than read for members it has no business
// carrying — and so is one naming no role at all, since the contract requires the
// field and reading silence as assent would leave the check advisory.
func TestRequirements_refusesAManifestThatIsNotAnExchange(t *testing.T) {
	for _, role := range []string{"ROLE_BROKER", "ROLE_AGENT", "ROLE_PUBLISHER", ""} {
		name := role
		if name == "" {
			name = "no role at all"
		}
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(requirementsManifest(role, nil, nil, nil))
			defer srv.Close()
			_, err := loopbackReader(nil).ResolveRegistrationRequirements(
				context.Background(), hostOf(t, srv))
			if !errors.Is(err, resolvers.ErrManifestNotExchange) {
				t.Fatalf("err = %v, want ErrManifestNotExchange", err)
			}
		})
	}
}

// proto-JSON lets an enum travel as its number, so a manifest that spells the
// role that way is the same manifest.
func TestRequirements_acceptsTheRoleAsANumber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"role":2,"endpoint":"https://exchange.test"}`))
	}))
	defer srv.Close()

	if _, err := loopbackReader(nil).ResolveRegistrationRequirements(
		context.Background(), hostOf(t, srv)); err != nil {
		t.Fatalf("numeric role refused: %v", err)
	}
}

// repeat64 builds a 64-character hex body for a sha256 digest from a 2-char unit.
func repeat64(unit string) string {
	out := ""
	for len(out) < 64 {
		out += unit
	}
	return out[:64]
}
