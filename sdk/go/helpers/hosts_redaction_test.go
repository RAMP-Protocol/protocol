package helpers_test

import (
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// No refusal message carries a credential.
//
// Mirrors the two ports' suites — sdk/python/tests/test_hosts_credential_redaction.py
// and sdk/ts/tests/hosts-credential-redaction.test.ts. The message TEXT is per
// language by design, since the shared corpus records a verdict and never a message,
// so the property is asserted behaviourally in each language rather than as a vector.
//
// The refusals these predicates raise reach a log the moment a manifest names an
// endpoint with credentials in it, or an operator mistypes one. Naming the value
// there puts the credential in every consumer's logs, and the value arrives from a
// third party: an offer names the exchange domain, and the manifest that domain
// serves names the endpoint.

const secret = "s3cr3t" //nolint:gosec // a test fixture, not a credential

// Every shape that refuses a credential-bearing reference. The first parses and is
// refused by the endpoint rule; the rest fail to parse. The tail is the class a
// redactor gets wrong when it decides on ONE reading of the reference: a "://" that
// is not a scheme separator, an authority opened by a bare "//" with no "://"
// anywhere, and a scheme that may not begin with a digit.
var credentialRefs = []string{
	"https://u:" + secret + "@exchange.example/v1",
	"https://u:" + secret + "@exchange.example\n/v1",
	"https://u:" + secret + `\@evil.example/v1`,
	"https://u%zz:" + secret + "@exchange.example/v1",
	"u:" + secret + "@exchange.example",
	"https://u:" + secret + "@",
	"u:" + secret + "@evil.example/x://a.example",
	"ftp:" + secret + "@a.example://x",
	"u:" + secret + "@a.example?q=x://y",
	"u:" + secret + "@a.example#f://y",
	"//u:" + secret + "@a.example",
	"1https://u:" + secret + "@a.example/",
	"exchange.example::443@u:" + secret + "@a.example",
}

func TestHostPredicatesNeverEchoACredential(t *testing.T) {
	for _, ref := range credentialRefs {
		if _, err := helpers.HostOf(ref); err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("HostOf(%q) named the credential: %v", ref, err)
		}
		if _, err := helpers.IsBareHost(ref); err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("IsBareHost(%q) named the credential: %v", ref, err)
		}
		_, err := helpers.HostAnchored("exchange.example", ref)
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("HostAnchored(_, %q) named the credential: %v", ref, err)
		}
	}
}

// Redaction must not flatten every refusal into one shape, and must not swallow the
// part of a message that makes it useful. A reference with no credential in it is
// reported verbatim, and an "@" outside the authority is not a credential.
func TestRefusalsStillNameWhatTheyRefused(t *testing.T) {
	for _, tc := range []struct{ ref, want string }{
		{"exchange.example::443", "exchange.example::443"},
		{"[not-an-ip]", "[not-an-ip]"},
		{"https://exchange.example/p%zz@x", "p%zz@x"},
	} {
		_, err := helpers.HostOf(tc.ref)
		if err == nil {
			t.Fatalf("HostOf(%q) succeeded; the case is only meaningful on a refusal", tc.ref)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("HostOf(%q) = %v, want it to name %q", tc.ref, err, tc.want)
		}
	}
}
