package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func newSignedReq(t *testing.T, body []byte, mutate func(*http.Request)) (*http.Request, ed25519.PublicKey, sigParams) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("agent.v1", priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://broker.example/ramp.v1.BrokerService/Resolve", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	if err := SignRequest(context.Background(), req, body, signer, SignOptions{Created: 1700000000, Expires: 1700000300}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	params := sigParams{
		Label: "sig1", Covered: coveredFor(req), KeyID: "agent.v1",
		Alg: AlgEd25519, Created: 1700000000, Expires: 1700000300,
	}
	return req, pub, params
}

func TestSignRequest_producesVerifiableSignature(t *testing.T) {
	body := []byte(`{"uri":"https://site.example/a"}`)
	req, pub, params := newSignedReq(t, body, nil)

	if got := req.Header.Get("Content-Digest"); got != ContentDigest(body) {
		t.Errorf("Content-Digest = %q, want %q", got, ContentDigest(body))
	}
	si := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(si, "sig1=(") || !strings.Contains(si, `keyid="agent.v1"`) ||
		!strings.Contains(si, `alg="ed25519"`) || !strings.Contains(si, "created=1700000000") ||
		!strings.Contains(si, "expires=1700000300") {
		t.Errorf("Signature-Input malformed: %q", si)
	}

	sigHdr := req.Header.Get("Signature")
	b64 := strings.TrimSuffix(strings.TrimPrefix(sigHdr, "sig1=:"), ":")
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(base), sig) {
		t.Error("signature does not verify against the signed base")
	}
}

func TestSignRequest_bindsAuthorizationAbsence(t *testing.T) {
	_, _, _ = newSignedReq(t, []byte("x"), nil)
	req, _, params := newSignedReq(t, []byte("x"), nil)
	if _, ok := req.Header["Authorization"]; !ok {
		t.Error("Authorization should be set (empty) to bind its absence")
	}
	found := false
	for _, c := range params.Covered {
		if c.Name == "authorization" {
			found = true
		}
	}
	if !found {
		t.Error("authorization must be in the covered set")
	}
}

func TestSignRequest_bindsBiscuitWhenPresent(t *testing.T) {
	req, pub, params := newSignedReq(t, []byte("x"), func(r *http.Request) {
		r.Header.Set(entitlementHeader, "biscuit-token")
	})
	found := false
	for _, c := range params.Covered {
		if c.Name == entitlementHeaderLower {
			found = true
		}
	}
	if !found {
		t.Fatalf("entitlement header not covered: %v", params.Covered)
	}
	// And it actually verifies with the biscuit bound.
	sigHdr := req.Header.Get("Signature")
	b64 := strings.TrimSuffix(strings.TrimPrefix(sigHdr, "sig1=:"), ":")
	sig, _ := base64.StdEncoding.DecodeString(b64)
	base, _ := buildSignatureBase(req, params)
	if !ed25519.Verify(pub, []byte(base), sig) {
		t.Error("signature with bound biscuit does not verify")
	}
}

func TestSignRequest_tamperedMethodBreaksSignature(t *testing.T) {
	body := []byte("x")
	req, pub, params := newSignedReq(t, body, nil)
	req.Method = http.MethodGet // tamper after signing
	sigHdr := req.Header.Get("Signature")
	b64 := strings.TrimSuffix(strings.TrimPrefix(sigHdr, "sig1=:"), ":")
	sig, _ := base64.StdEncoding.DecodeString(b64)
	base, _ := buildSignatureBase(req, params)
	if ed25519.Verify(pub, []byte(base), sig) {
		t.Error("signature must not verify after the method is tampered")
	}
}

func TestNewEd25519Signer_validation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := NewEd25519Signer("", priv); err == nil {
		t.Error("empty keyID should error")
	}
	if _, err := NewEd25519Signer("k", priv[:10]); err == nil {
		t.Error("short key should error")
	}
	if _, err := NewEd25519SignerFromSeed("k", make([]byte, 10)); err == nil {
		t.Error("short seed should error")
	}
	s, err := NewEd25519SignerFromSeed("k", make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID() != "k" || s.Algorithm() != AlgEd25519 {
		t.Errorf("signer metadata wrong: %q %q", s.KeyID(), s.Algorithm())
	}
}
