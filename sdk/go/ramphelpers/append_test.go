package ramphelpers_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

// Ported from the v2 internal/httpsig/append_test.go behavioral spec, re-expressed
// in the L1 idiom: the Signer interface (not a raw ed25519 key) and
// VerifyOptions.Now (not a clock package). These pin AppendSignature's chain
// semantics: empty→sig1, sig1→sig2, twice→sig3, and header preservation.

func appendReq(t *testing.T, target string, body []byte, auth string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", auth)
	return req
}

func mustSigner(t *testing.T, keyID string) (ramphelpers.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	s, err := ramphelpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s, pub
}

// TestAppendSignature_EmptyHeaders: appending to a request with no existing
// signatures behaves exactly like SignRequest (a sig1) — the N=1 hard guard.
func TestAppendSignature_EmptyHeaders(t *testing.T) {
	ctx := context.Background()
	signer, pub := mustSigner(t, "agent.test")
	body := []byte(`{"hello":"world"}`)
	req := appendReq(t, "https://broker.example/ramp.v1.BrokerService/Resolve", body, "Bearer token123")

	now := time.Unix(1700000000, 0)
	opts := ramphelpers.SignOptions{Created: now.Unix(), Expires: now.Add(100 * time.Second).Unix()}
	if err := ramphelpers.AppendSignature(ctx, req, body, signer, opts); err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}

	if si := req.Header.Get("Signature-Input"); !strings.HasPrefix(si, "sig1=") {
		t.Fatalf("want Signature-Input starting with sig1=, got %q", si)
	}
	if sig := req.Header.Get("Signature"); !strings.HasPrefix(sig, "sig1=") {
		t.Fatalf("want Signature starting with sig1=, got %q", sig)
	}

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"agent.test": pub})
	v, err := ramphelpers.VerifyRequestResolved(ctx, req, body, resolver, ramphelpers.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	if v.KeyID != "agent.test" || v.Label != "sig1" {
		t.Fatalf("verified = (%q,%q), want (agent.test, sig1)", v.KeyID, v.Label)
	}
}

// appendEqualsSignRequest: an AppendSignature to empty headers must produce the
// EXACT Signature-Input/Signature bytes a SignRequest would, given the same
// (deterministic) signer. Proves single-sig is byte-identical to the N=1 append.
func TestAppendSignature_ByteIdenticalToSignRequest(t *testing.T) {
	ctx := context.Background()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	signerA, err := ramphelpers.NewEd25519SignerFromSeed("agent.test", seed)
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := ramphelpers.NewEd25519SignerFromSeed("agent.test", seed)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"hello":"world"}`)
	now := time.Unix(1700000000, 0)
	opts := ramphelpers.SignOptions{Created: now.Unix(), Expires: now.Add(100 * time.Second).Unix()}

	reqSign := appendReq(t, "https://broker.example/ramp.v1.BrokerService/Resolve", body, "Bearer t")
	if err := ramphelpers.SignRequest(ctx, reqSign, body, signerA, opts); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	reqAppend := appendReq(t, "https://broker.example/ramp.v1.BrokerService/Resolve", body, "Bearer t")
	if err := ramphelpers.AppendSignature(ctx, reqAppend, body, signerB, opts); err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}

	for _, h := range []string{"Signature-Input", "Signature", "Content-Digest"} {
		if reqSign.Header.Get(h) != reqAppend.Header.Get(h) {
			t.Fatalf("%s differs:\n SignRequest:   %q\n AppendSignature: %q",
				h, reqSign.Header.Get(h), reqAppend.Header.Get(h))
		}
	}
}

// TestAppendSignature_ExistingSig1: appending when sig1 already exists creates
// sig2, and both verify.
func TestAppendSignature_ExistingSig1(t *testing.T) {
	ctx := context.Background()
	agentSigner, agentPub := mustSigner(t, "agent.test")
	brokerSigner, brokerPub := mustSigner(t, ramphelpers.BrokerKeyIDPrefix+"test")
	body := []byte(`{"url":"https://publisher.example/content"}`)
	req := appendReq(t, "https://broker.example/ramp.v1.BrokerService/Resolve", body, "Bearer agent-token")

	now := time.Unix(1700000000, 0)
	opts := ramphelpers.SignOptions{Created: now.Unix(), Expires: now.Add(100 * time.Second).Unix()}
	if err := ramphelpers.SignRequest(ctx, req, body, agentSigner, opts); err != nil {
		t.Fatalf("agent SignRequest: %v", err)
	}
	opts2 := ramphelpers.SignOptions{Created: now.Unix() + 1, Expires: now.Add(101 * time.Second).Unix()}
	if err := ramphelpers.AppendSignature(ctx, req, body, brokerSigner, opts2); err != nil {
		t.Fatalf("broker AppendSignature: %v", err)
	}

	si := req.Header.Get("Signature-Input")
	if !strings.Contains(si, "sig1=") || !strings.Contains(si, "sig2=") {
		t.Fatalf("Signature-Input missing sig1/sig2: %q", si)
	}

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent.test":                           agentPub,
		ramphelpers.BrokerKeyIDPrefix + "test": brokerPub,
	})
	verified, err := ramphelpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, ramphelpers.VerifyOptions{Now: now.Add(time.Second)})
	if err != nil {
		t.Fatalf("VerifyMultisigRequestResolved: %v", err)
	}
	if len(verified) != 2 || verified[0].Label != "sig1" || verified[1].Label != "sig2" {
		t.Fatalf("verified = %+v, want sig1,sig2", verified)
	}
}

// TestAppendSignature_TwiceAppends: two appends after a sig1 produce sig2 then
// sig3; all three verify in order.
func TestAppendSignature_TwiceAppends(t *testing.T) {
	ctx := context.Background()
	s1, p1 := mustSigner(t, "signer1.test")
	s2, p2 := mustSigner(t, ramphelpers.BrokerKeyIDPrefix+"signer2")
	s3, p3 := mustSigner(t, ramphelpers.BrokerKeyIDPrefix+"signer3")
	body := []byte(`{"relay":"chain"}`)
	req := appendReq(t, "https://exchange.example/ramp.v1.ExchangeService/CreateOffer", body, "")

	now := time.Unix(1700000000, 0)
	mk := func(d int64) ramphelpers.SignOptions {
		return ramphelpers.SignOptions{Created: now.Unix() + d, Expires: now.Add(100*time.Second).Unix() + d}
	}
	if err := ramphelpers.SignRequest(ctx, req, body, s1, mk(0)); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if err := ramphelpers.AppendSignature(ctx, req, body, s2, mk(1)); err != nil {
		t.Fatalf("append sig2: %v", err)
	}
	if err := ramphelpers.AppendSignature(ctx, req, body, s3, mk(2)); err != nil {
		t.Fatalf("append sig3: %v", err)
	}

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"signer1.test": p1,
		ramphelpers.BrokerKeyIDPrefix + "signer2": p2,
		ramphelpers.BrokerKeyIDPrefix + "signer3": p3,
	})
	verified, err := ramphelpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, ramphelpers.VerifyOptions{Now: now.Add(3 * time.Second)})
	if err != nil {
		t.Fatalf("VerifyMultisigRequestResolved: %v", err)
	}
	wantLabels := []string{"sig1", "sig2", "sig3"}
	if len(verified) != 3 {
		t.Fatalf("got %d verified, want 3", len(verified))
	}
	for i, want := range wantLabels {
		if verified[i].Label != want {
			t.Fatalf("verified[%d].Label = %q, want %q", i, verified[i].Label, want)
		}
	}
}

// TestAppendSignature_PreservesExistingHeaders: appending does NOT modify the
// existing Content-Digest or Authorization headers, and sig1 still verifies.
func TestAppendSignature_PreservesExistingHeaders(t *testing.T) {
	ctx := context.Background()
	s1, p1 := mustSigner(t, "first.test")
	s2, _ := mustSigner(t, ramphelpers.BrokerKeyIDPrefix+"second")
	body := []byte(`{"test":"preserve"}`)
	req := appendReq(t, "https://broker.example/ramp.v1.BrokerService/Resolve", body, "Bearer original-token")

	now := time.Unix(1700000000, 0)
	opts := ramphelpers.SignOptions{Created: now.Unix(), Expires: now.Add(100 * time.Second).Unix()}
	if err := ramphelpers.SignRequest(ctx, req, body, s1, opts); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	originalDigest := req.Header.Get("Content-Digest")
	originalAuth := req.Header.Get("Authorization")

	opts2 := ramphelpers.SignOptions{Created: now.Unix() + 1, Expires: now.Add(101 * time.Second).Unix()}
	if err := ramphelpers.AppendSignature(ctx, req, body, s2, opts2); err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	if req.Header.Get("Content-Digest") != originalDigest {
		t.Fatalf("Content-Digest changed: want %q, got %q", originalDigest, req.Header.Get("Content-Digest"))
	}
	if req.Header.Get("Authorization") != originalAuth {
		t.Fatalf("Authorization changed: want %q, got %q", originalAuth, req.Header.Get("Authorization"))
	}

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"first.test": p1})
	v, err := ramphelpers.VerifyRequestResolved(ctx, req, body, resolver, ramphelpers.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("VerifyRequestResolved sig1 after append: %v", err)
	}
	if v.Label != "sig1" {
		t.Fatalf("want label sig1, got %q", v.Label)
	}
}
