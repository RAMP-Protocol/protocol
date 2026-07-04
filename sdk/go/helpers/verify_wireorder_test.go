package helpers_test

// RFC 9421 §2.5: the @signature-params line of the signature base is the
// VERBATIM inner list from the wire Signature-Input — parameter order is the
// signer's choice and the verifier must honor it. These tests pin that a
// signature whose parameter order differs from this SDK's own rendering
// (keyid;alg;created;expires) still verifies: the platform's other RFC 9421
// implementation emits created;expires;alg;keyid and its signatures must
// interoperate.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// wireOrderSignedRequest hand-rolls a cryptographically valid signature whose
// @signature-params tail uses the foreign parameter order
// created;expires;alg;keyid over the full five-component covered set.
func wireOrderSignedRequest(t *testing.T, body []byte) (*http.Request, ed25519.PublicKey) {
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
	req.Header.Set("Signature-Agent", "https://agent.example")

	// Foreign param order: created;expires;alg;keyid (NOT this SDK's order).
	inner := fmt.Sprintf(`("@method" "@target-uri" "content-digest" "authorization" "signature-agent");created=%d;expires=%d;alg=%q;keyid=%q`,
		tCreated, tExpires, helpers.AlgEd25519, "agent.v1")
	base := "\"@method\": POST\n" +
		"\"@target-uri\": https://exchange.example/ramp.v1.ExchangeService/Execute\n" +
		"\"content-digest\": " + req.Header.Get("Content-Digest") + "\n" +
		"\"authorization\": \n" +
		"\"signature-agent\": https://agent.example\n" +
		"\"@signature-params\": " + inner
	sig := ed25519.Sign(priv, []byte(base))

	req.Header.Set("Signature-Input", "sig1="+inner)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return req, pub
}

// TestVerifyRequest_honorsWireParamOrder asserts a valid signature whose
// signature-params order differs from the SDK's own rendering verifies. The
// verifier must rebuild the base from the wire-verbatim inner, never from a
// re-rendering in its own parameter order.
func TestVerifyRequest_honorsWireParamOrder(t *testing.T) {
	body := []byte(`{"resource_id":"r-order"}`)
	req, pub := wireOrderSignedRequest(t, body)

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest must honor the wire param order (RFC 9421 §2.5 verbatim inner); got %v", err)
	}
	if vr.KeyID != "agent.v1" || vr.Created != tCreated || vr.Expires != tExpires {
		t.Errorf("verified metadata mismatch: keyid=%q created=%d expires=%d", vr.KeyID, vr.Created, vr.Expires)
	}
}
