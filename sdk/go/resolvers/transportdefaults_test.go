package resolvers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// Which transport each resolver takes when the caller injects none.
//
// # Why this is a test and not a sentence
//
// The rule is that a resolver's default follows its URL's PROVENANCE: a fixed,
// operator-chosen address takes the plain client, a host another party named
// takes the guarded one. That rule is written down in three places — the
// WellKnownOptions.HTTP comment, docs/design-history.md, and the published
// threat model, which states it per language in a table.
//
// It has now drifted from the code twice. The scheme guard was added to the
// dial and not walked back through its callers, so a doc sentence beginning
// "every fetch" stayed standing after it stopped being true; and the two ports
// mirrored this package's options struct without mirroring the rule, then
// explained the result in a docstring that had also stopped being true. Prose
// cannot detect either. A socket can.
//
// SO: CHANGING ANY ROW BELOW OBLIGES AN EDIT TO THE PUBLISHED THREAT MODEL
// (website/src/content/docs/security/threat-model.mdx), which names these
// postures per language. That is the whole point of the gate — the failure is
// the reminder.
//
// # What is not here
//
// The WBA directory resolver's guarded default is pinned already, by
// wbakeyresolver_ssrf_internal_test.go and its two port mirrors; its guard is
// additionally not opt-outable, which those tests cover and this one would not.
// Asserting it a second time here would be one behaviour with two owners.
//
// This is deliberately NOT a shared corpus. A *-vectors.json has to be replayed
// by all three languages against the same expectations, and the expectations
// here legitimately DIFFER per language — that difference is the subject. The
// ports carry their own copy of this table for the same reason.

// dialObserved reports whether a resolver reached the loopback origin. A guarded
// default refuses the reserved address before the request leaves the process, so
// "the handler ran" is the observable that separates the two transports.
func dialObserved(t *testing.T, exercise func(host string) error) bool {
	t.Helper()
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		// Anchored to the host that served it, so the endpoint face's own
		// same-host rule cannot be what refuses.
		_, _ = fmt.Fprintf(w, `{"role":"ROLE_EXCHANGE","endpoint":"https://%s","keys":[%s]}`,
			r.Host, testJWK(t))
	}))
	defer srv.Close()
	// The error is deliberately ignored: a guarded refusal and a happy answer are
	// both expected outcomes here, and which one occurred is what `reached` says.
	_ = exercise(hostOf(t, srv))
	return reached
}

func testJWK(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return fmt.Sprintf(`{"kid":"ex.v1","kty":"OKP","crv":"Ed25519","x":%q}`,
		base64.RawURLEncoding.EncodeToString(pub))
}

func TestResolverTransportDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		// reaches is TRUE where the default is the plain client.
		reaches  bool
		why      string
		exercise func(host string) error
	}{
		{
			name:    "key resolver dials plain",
			reaches: true,
			why: "its URL is a fixed, operator-chosen JWKS address — nobody else can " +
				"point it, and an on-prem directory may legitimately be private",
			exercise: func(host string) error {
				r := resolvers.NewWellKnownKeyResolver(
					"http://"+host+"/.well-known/ramp.json", resolvers.WellKnownOptions{TTL: time.Hour})
				_, err := r.Resolve(context.Background(), "ex.v1")
				return err
			},
		},
		{
			name:    "endpoint resolver dials guarded",
			reaches: false,
			why: "its host is an Offer.exchange domain, so another party chose the " +
				"address. The two ports do NOT match this row yet — see their copies",
			exercise: func(host string) error {
				r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
					TTL: time.Hour, Scheme: "http",
				})
				_, err := r.ResolveEndpoint(context.Background(), host)
				return err
			},
		},
		{
			name:    "requirements reader dials guarded",
			reaches: false,
			why:     "its host is a RegisterRequest.exchange domain, named by the caller per call",
			exercise: func(host string) error {
				r := resolvers.NewWellKnownRequirementsReader(resolvers.WellKnownOptions{Scheme: "http"})
				_, err := r.ResolveRegistrationRequirements(context.Background(), host)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both guards are env-driven, so the flags are cleared rather than
			// inherited from whatever shell ran the suite: without this a developer
			// with SKIP_SSRF set sees the guarded rows fail for a reason that has
			// nothing to do with the defaults. t.Setenv restores them after the test.
			t.Setenv("SKIP_SSRF", "")
			t.Setenv("ALLOW_INSECURE", "")
			if got := dialObserved(t, tc.exercise); got != tc.reaches {
				verb := map[bool]string{true: "reached", false: "refused"}
				t.Fatalf("default transport %s the loopback origin, want %s — %s.\n"+
					"If this change is intended, the per-language table in the published "+
					"threat model has to change with it.",
					verb[got], verb[tc.reaches], tc.why)
			}
		})
	}
}
