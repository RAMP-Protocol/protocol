package helpers_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func requestAcceptanceFixture() *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{
		IdempotencyKey: "idem-1",
		Requester:      &rampv1.Requester{Id: "agent-1", Domain: "agent.example"},
		Items: []*rampv1.TransactionItem{
			{Offer: &rampv1.Offer{Signature: "sig-a", Exchange: "one.example"}},
			{Offer: &rampv1.Offer{Signature: "sig-b", Exchange: "two.example"}},
			{Offer: &rampv1.Offer{Signature: "sig-c", Exchange: "one.example"}},
		},
	}
}

func TestRequestAcceptanceProjection_roundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	projected := &rampv1.TransactionRequest{
		IdempotencyKey: original.GetIdempotencyKey(),
		Requester:      original.GetRequester(),
		Items:          []*rampv1.TransactionItem{original.GetItems()[0], original.GetItems()[2]},
	}
	if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, "one.example", pub); err != nil {
		t.Fatalf("verify exact projection: %v", err)
	}
}

func TestRequestAcceptanceProjection_membershipAndOrderAreClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]*rampv1.TransactionItem{
		"removed":   {original.GetItems()[0]},
		"reordered": {original.GetItems()[2], original.GetItems()[0]},
		"appended":  {original.GetItems()[0], original.GetItems()[2], original.GetItems()[0]},
	}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) {
			projected := &rampv1.TransactionRequest{
				IdempotencyKey: original.GetIdempotencyKey(),
				Requester:      original.GetRequester(),
				Items:          items,
			}
			if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, "one.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
				t.Fatalf("expected invalid request acceptance, got %v", err)
			}
		})
	}
}

func TestRequestAcceptance_tamperRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, req)
	if err != nil {
		t.Fatal(err)
	}
	acceptance.Payload.Items[0].Exchange = "evil.example"
	if _, err := helpers.VerifyRequestAcceptance(req, acceptance, pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
		t.Fatalf("expected invalid request acceptance, got %v", err)
	}
}

func TestAgentRequestAcceptancePayload_fieldSetIsPinned(t *testing.T) {
	want := []string{"items", "requester_id", "requester_domain", "idempotency_key"}
	fields := (&rampv1.AgentRequestAcceptancePayload{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != len(want) {
		t.Fatalf("AgentRequestAcceptancePayload has %d fields, want %d", fields.Len(), len(want))
	}
	for i, name := range want {
		if got := string(fields.Get(i).Name()); got != name {
			t.Errorf("field %d = %q, want %q", i+1, got, name)
		}
	}
}

func TestAgentRequestAcceptanceItem_fieldSetIsPinned(t *testing.T) {
	want := []string{"offer_sig", "exchange"}
	fields := (&rampv1.AgentRequestAcceptanceItem{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != len(want) {
		t.Fatalf("AgentRequestAcceptanceItem has %d fields, want %d", fields.Len(), len(want))
	}
	for i, name := range want {
		if got := string(fields.Get(i).Name()); got != name {
			t.Errorf("field %d = %q, want %q", i+1, got, name)
		}
	}
}
