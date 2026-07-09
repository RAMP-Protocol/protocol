package helpers_test

// TDD red tests for the signature-agent covered-component requirement (the app's
// internal/httpsig has always required it; the SDK gained it with the WBA
// identity work). Originally red on the pre-fix tree: the verifier ACCEPTED a
// covered set omitting signature-agent, and SignRequest never bound the header.
//
// The negative test hand-rolls its legacy four-component signature because the
// production sign path now ALWAYS binds and covers signature-agent — the only
// way such a signature can exist post-fix is an out-of-date or hostile signer,
// which is exactly what the verifier must reject.

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// legacyFourComponentSignature builds a real Ed25519 RFC 9421 signature whose
// covered set is the PRE-WBA four components (@method @target-uri content-digest
// authorization) — no signature-agent. The base replicates the SDK's canonical
// rendering so the signature is cryptographically valid; only the covered-set
// policy should reject it.
func legacyFourComponentSignature(t *testing.T, body []byte) (*http.Request, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/ramp.v1.ExchangeService/Execute", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Digest", helpers.ContentDigest(body))
	req.Header.Set("Authorization", "")

	inner := fmt.Sprintf(`("@method" "@target-uri" "content-digest" "authorization");keyid=%q;alg=%q;created=%d;expires=%d`,
		"agent.v1", helpers.AlgEd25519, tCreated, tExpires)
	base := "\"@method\": POST\n" +
		"\"@target-uri\": https://exchange.example/ramp.v1.ExchangeService/Execute\n" +
		"\"content-digest\": " + req.Header.Get("Content-Digest") + "\n" +
		"\"authorization\": \n" +
		"\"@signature-params\": " + inner
	sig := ed25519.Sign(priv, []byte(base))

	req.Header.Set("Signature-Input", "sig1="+inner)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return req, pub
}

// TestVerifyRequest_signatureAgentRequired asserts a cryptographically valid
// signature whose covered set omits signature-agent is rejected with
// ErrMissingRequiredComponent — never verified through to acceptance.
func TestVerifyRequest_signatureAgentRequired(t *testing.T) {
	body := []byte(`{"resource_id":"r1"}`)
	req, pub := legacyFourComponentSignature(t, body)

	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, helpers.ErrMissingRequiredComponent) {
		t.Errorf("VerifyRequest: got err=%v; want errors.Is(err, ErrMissingRequiredComponent) — "+
			"a signature omitting signature-agent must be rejected", err)
	}
}

// TestVerifyRequest_signatureAgentAcceptedWhenPresent is the complementary
// positive case: a signature that covers signature-agent (bound by the
// production sign path) is accepted. Guards against over-rejection.
func TestVerifyRequest_signatureAgentAcceptedWhenPresent(t *testing.T) {
	body := []byte(`{"resource_id":"r2"}`)
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set("Signature-Agent", "https://agent.example")
	})
	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest with Signature-Agent present: got err=%v; want nil "+
			"(a request covering signature-agent must be accepted)", err)
	}
	if vr == nil {
		t.Fatal("VerifyRequest returned nil VerifiedRequest without error")
	}
}
