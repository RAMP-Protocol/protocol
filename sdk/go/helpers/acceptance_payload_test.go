package helpers_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// The agent offer-acceptance wire envelope and its canonical signing payload
// exist on the modern execute shape. The acceptance must travel WITH the
// reflected Offer on both single-mode (TransactionRequest) and batch
// (TransactionItem), so the Exchange can bind the agent to the exact offer it
// is executing no matter how many brokers relayed the request.
func TestAgentAcceptance_wireFieldsExist(t *testing.T) {
	acc := &rampv1.AgentAcceptance{
		Signature:          "deadbeef",
		SignatureAlgorithm: "EdDSA",
	}

	// Items-only: each item carries a per-item acceptance alongside its
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

// AgentAcceptancePayload fixes the FIELD SET the acceptance signature covers;
// the byte layout is the canonical signing form defined on Offer.signature (RFC
// 8785 JCS over canonical proto-JSON). The two halves are pinned separately, and
// only this one is pinned by the message.
//
// Canonical proto-JSON omits unpopulated fields, so a field added to this message
// without a matching assignment in CanonicalAcceptanceBytes drops out of the
// signed bytes entirely: the golden vectors stay byte-identical and every gate
// stays green while the agent silently commits to less than the message claims.
// The set is therefore asserted here rather than left to review.
func TestAgentAcceptancePayload_fieldSetIsPinned(t *testing.T) {
	want := []string{"offer_sig", "requester_id", "requester_domain", "idempotency_key"}

	fields := (&rampv1.AgentAcceptancePayload{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != len(want) {
		t.Fatalf("AgentAcceptancePayload has %d fields, want %d %v; a field the "+
			"canonicalizer does not assign is omitted from the signed bytes",
			fields.Len(), len(want), want)
	}
	for i, name := range want {
		if got := string(fields.Get(i).Name()); got != name {
			t.Errorf("field %d = %q, want %q", i+1, got, name)
		}
	}
}
