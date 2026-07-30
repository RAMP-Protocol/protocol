package helpers_test

// Signature-Agent wire forms. Web Bot Auth defines the header value as an RFC
// 8941 String, so the conformant form is QUOTED — quoting is not optional in
// structured fields, a String has exactly one serialization. RAMP itself emits
// the value bare, which is a Token rather than a String.
//
// Both forms must yield the same directory URI, on the VerifiedRequest and in the
// resolver context. Reading the quoted form verbatim is what made a conformant
// signer unresolvable: the quotes travelled into the directory URI, no host could
// be parsed out of it, and key resolution failed the request.
//
// The spec's sf-dictionary form and its data: URI scheme are deliberately NOT
// supported; see TestSignatureAgent_dictionaryFormNotUnwrapped.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

const wantDirectory = "https://agent.example"

// TestSignatureAgent_formsYieldSameDirectory pins that the quoted and bare forms
// both verify and both surface the same bare URI. Verification passing is half
// the assertion: the signature base is built from the header's raw bytes, so a
// quoted value must be signed and verified WITH its quotes while the value read
// off the result has them stripped. If those two ever collapsed into one
// treatment, one of these subtests would fail.
func TestSignatureAgent_formsYieldSameDirectory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"quoted sf-string (Web Bot Auth conformant)", `"` + wantDirectory + `"`},
		{"bare token (RAMP's own emission)", wantDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"resource_id":"r1"}`)
			req, pub := signFixture(t, body, func(r *http.Request) {
				r.Header.Set(helpers.SignatureAgentHeader, tc.header)
			})

			vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
			if err != nil {
				t.Fatalf("VerifyRequest with Signature-Agent %s: %v", tc.header, err)
			}
			if vr.SignatureAgent != wantDirectory {
				t.Errorf("SignatureAgent = %q; want %q (header on the wire was %s)",
					vr.SignatureAgent, wantDirectory, tc.header)
			}
			// The wire bytes are untouched: a relay forwards this header verbatim so
			// the agent's signature still verifies at the next hop.
			if got := req.Header.Get(helpers.SignatureAgentHeader); got != tc.header {
				t.Errorf("header mutated to %q; want %q left on the wire", got, tc.header)
			}
		})
	}
}

// TestSignatureAgent_quotedFormReachesResolver covers the failure that made this
// a 401 rather than a cosmetic storage-format wart: the resolver fetches the
// signer's directory from the value threaded into its context. Given the quotes
// verbatim it can parse no host, reports the key unknown, and the request is
// rejected.
func TestSignatureAgent_quotedFormReachesResolver(t *testing.T) {
	body := []byte(`{"resource_id":"r2"}`)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "thumbprint.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/Execute", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(helpers.SignatureAgentHeader, `"`+wantDirectory+`"`)
	if err := helpers.SignRequest(context.Background(), req, body, signer,
		helpers.SignOptions{Created: tCreated, Expires: tExpires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	var captured string
	spy := &signatureAgentSpyResolver{
		delegate: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub}),
		onResolve: func(ctx context.Context, _ string) {
			captured = helpers.SignatureAgentFromContext(ctx)
		},
	}

	if _, err := helpers.VerifyRequestResolved(
		context.Background(), req, body, spy, helpers.VerifyOptions{Now: tNow},
	); err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	if captured != wantDirectory {
		t.Errorf("resolver context directory = %q; want %q — a resolver cannot fetch a directory whose URI still carries quotes",
			captured, wantDirectory)
	}
}

// TestSignatureAgent_dictionaryFormNotUnwrapped pins a deliberate refusal, not an
// oversight. The current directory draft makes Signature-Agent an sf-dictionary
// (`agent2="https://…"`), and RAMP does not read it: the member value would have
// to be selected by the covered component's key param, and the same draft admits
// a data: member that inlines an entire key directory into the header. Key
// resolution here rests on FETCHING the directory from a location the signer had
// to control, so an inline directory removes the boundary it depends on.
//
// The dictionary form therefore falls through verbatim and is rejected downstream
// where a directory has to resolve to a real host. The assertion is that no
// unwrapping happens — a future decision to support the form should break this
// test and be made deliberately.
func TestSignatureAgent_dictionaryFormNotUnwrapped(t *testing.T) {
	const dictForm = `agent2="` + wantDirectory + `"`
	body := []byte(`{"resource_id":"r3"}`)
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set(helpers.SignatureAgentHeader, dictForm)
	})

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.SignatureAgent == wantDirectory {
		t.Fatalf("SignatureAgent = %q: the sf-dictionary form was unwrapped, but RAMP does not support it", vr.SignatureAgent)
	}
	if vr.SignatureAgent != dictForm {
		t.Errorf("SignatureAgent = %q; want the value passed through verbatim as %q", vr.SignatureAgent, dictForm)
	}
}

// TestSignatureAgent_emptyStaysEmpty guards the static bootstrap path, where the
// signer binds an empty Signature-Agent so the covered set is uniform. An empty
// value must not be turned into anything by the structured-field parsing.
func TestSignatureAgent_emptyStaysEmpty(t *testing.T) {
	body := []byte(`{"resource_id":"r4"}`)
	req, pub := signFixture(t, body, nil)

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.SignatureAgent != "" {
		t.Errorf("SignatureAgent = %q; want empty (empty-bind bootstrap path)", vr.SignatureAgent)
	}
}

// TestSignatureAgent_unparseableValuePreserved pins the fallback. A host that no
// structured-field parser admits must still reach the caller unchanged rather than
// becoming empty, so values that worked before this parsing was added keep
// working. The draft permits ignoring a malformed field but does not require it,
// and every consumer already has to cope with a directory it cannot resolve.
func TestSignatureAgent_unparseableValuePreserved(t *testing.T) {
	const unparseable = `"unterminated`
	body := []byte(`{"resource_id":"r5"}`)
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set(helpers.SignatureAgentHeader, unparseable)
	})

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.SignatureAgent != unparseable {
		t.Errorf("SignatureAgent = %q; want %q preserved verbatim", vr.SignatureAgent, unparseable)
	}
}
