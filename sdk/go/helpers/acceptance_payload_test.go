package helpers_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// R1 (RAMP-102): the agent offer-acceptance wire envelope and its canonical
// signing payload exist on the modern execute shape. The acceptance must travel
// WITH the reflected Offer on both single-mode (TransactionRequest) and batch
// (TransactionItem), and the canonical payload must marshal deterministically
// (byte-identical across the SDK signer (R2) and the Exchange verifier (R4)).
func TestAgentAcceptance_wireFieldsExist(t *testing.T) {
	acc := &rampv1.AgentAcceptance{
		Signature:          "deadbeef",
		SignatureAlgorithm: "EdDSA",
	}

	// Items-only (6afpc): each item carries a per-item acceptance alongside its
	// reflected Offer (single-offer mode removed — a single offer is a 1-item list).
	item := &rampv1.TransactionItem{
		Offer:           &rampv1.Offer{OfferId: "of_2"},
		AgentAcceptance: acc,
	}
	if got := item.GetAgentAcceptance().GetSignature(); got != "deadbeef" {
		t.Fatalf("item agent_acceptance.signature = %q, want deadbeef", got)
	}
	if got := item.GetAgentAcceptance().GetSignatureAlgorithm(); got != "EdDSA" {
		t.Fatalf("item agent_acceptance.signature_algorithm = %q, want EdDSA", got)
	}
}

// The canonical signing structure is a dedicated message so the signer (R2) and
// verifier (R4) derive byte-identical signed bytes from the same proto. It MUST
// marshal deterministically.
func TestAgentAcceptancePayload_deterministicMarshal(t *testing.T) {
	payload := &rampv1.AgentAcceptancePayload{
		OfferSig:        "ex-offer-sig-hex",
		RequesterId:     "req-1",
		RequesterDomain: "agent.example.com",
		IdempotencyKey:  "idem-1",
	}
	a, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal (2): %v", err)
	}
	if len(a) == 0 {
		t.Fatal("canonical payload marshalled to zero bytes")
	}
	if string(a) != string(b) {
		t.Fatal("deterministic marshal is not stable across calls")
	}
}
