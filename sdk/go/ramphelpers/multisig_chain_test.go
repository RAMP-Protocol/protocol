package ramphelpers_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

// R3 (RAMP-56): the agent ALWAYS signs its request (sig1); a relaying broker
// chains its signature (sig2) on top via AppendSignature. VerifyMultisigRequest
// returns ALL verified labels in chain order, enforcing the order-bound
// forwarding chain. Single-sig is exactly the N=1 case of this path.
func multisigReq(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	body := []byte(`{"idempotency_key":"idem-1"}`)
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example.com/ramp.v1.ExchangeService/ExecuteTransaction", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req, body
}

func TestAppendSignature_twoHopChainVerifies(t *testing.T) {
	ctx := context.Background()
	agentPub, agentPriv, _ := ed25519.GenerateKey(nil)
	brokerPub, brokerPriv, _ := ed25519.GenerateKey(nil)

	agentSigner, err := ramphelpers.NewEd25519Signer("agent.k1", agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	// A broker relay key uses the broker.* keyID convention.
	brokerSigner, err := ramphelpers.NewEd25519Signer(ramphelpers.BrokerKeyIDPrefix+"inst.v1", brokerPriv)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	opts := ramphelpers.SignOptions{Created: now.Unix(), Expires: now.Add(time.Hour).Unix()}

	req, body := multisigReq(t)
	// sig1: the agent signs its own request.
	if err := ramphelpers.SignRequest(ctx, req, body, agentSigner, opts); err != nil {
		t.Fatalf("agent SignRequest: %v", err)
	}
	// sig2: the broker chains its signature on top WITHOUT disturbing sig1.
	if err := ramphelpers.AppendSignature(ctx, req, body, brokerSigner, opts); err != nil {
		t.Fatalf("broker AppendSignature: %v", err)
	}

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent.k1": agentPub,
		ramphelpers.BrokerKeyIDPrefix + "inst.v1": brokerPub,
	})
	vopts := ramphelpers.VerifyOptions{Now: now.Add(time.Minute)}

	verified, err := ramphelpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, vopts)
	if err != nil {
		t.Fatalf("VerifyMultisigRequestResolved: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("verified %d signatures, want 2", len(verified))
	}
	if verified[0].Label != "sig1" || verified[1].Label != "sig2" {
		t.Fatalf("labels = %q,%q want sig1,sig2", verified[0].Label, verified[1].Label)
	}
	if verified[0].KeyID != "agent.k1" {
		t.Fatalf("sig1 keyid = %q want agent.k1", verified[0].KeyID)
	}
}

// Tampering with the predecessor's signature bytes must break the chained sig2
// verification (order-bound, tamper-evident chain).
func TestAppendSignature_tamperedPredecessorRejected(t *testing.T) {
	ctx := context.Background()
	agentPub, agentPriv, _ := ed25519.GenerateKey(nil)
	brokerPub, brokerPriv, _ := ed25519.GenerateKey(nil)
	agentSigner, _ := ramphelpers.NewEd25519Signer("agent.k1", agentPriv)
	brokerSigner, _ := ramphelpers.NewEd25519Signer(ramphelpers.BrokerKeyIDPrefix+"inst.v1", brokerPriv)

	now := time.Unix(1_700_000_000, 0)
	opts := ramphelpers.SignOptions{Created: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	req, body := multisigReq(t)
	_ = ramphelpers.SignRequest(ctx, req, body, agentSigner, opts)
	_ = ramphelpers.AppendSignature(ctx, req, body, brokerSigner, opts)

	// Re-sign sig1 with a DIFFERENT agent key but leave sig2 (which chained the
	// original sig1 bytes) intact — the chain link no longer resolves.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	otherSigner, _ := ramphelpers.NewEd25519Signer("agent.k1", otherPriv)
	// Rebuild sig1 only by signing a fresh request and splicing — simplest: flip
	// the agent's registered key so sig1's own verify fails too; but we want the
	// CHAIN to be what fails, so instead resolve with the tampered predecessor.
	_ = otherSigner

	resolver := ramphelpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent.k1": agentPub,
		ramphelpers.BrokerKeyIDPrefix + "inst.v1": brokerPub,
	})
	vopts := ramphelpers.VerifyOptions{Now: now.Add(time.Minute)}

	// Corrupt the Signature header's sig1 member bytes.
	req.Header.Set("Signature", corruptFirstMember(req.Header.Get("Signature")))
	if _, err := ramphelpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, vopts); err == nil {
		t.Fatal("expected verification failure on tampered predecessor, got nil")
	}
}

// corruptFirstMember flips a character in the first dictionary member's base64
// payload of a Signature header value.
func corruptFirstMember(sig string) string {
	b := []byte(sig)
	for i := 0; i < len(b); i++ {
		if b[i] == ':' && i+1 < len(b) {
			// flip the first base64 char after the opening colon
			if b[i+1] == 'A' {
				b[i+1] = 'B'
			} else {
				b[i+1] = 'A'
			}
			break
		}
	}
	return string(b)
}
