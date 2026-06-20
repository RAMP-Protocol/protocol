package ramphelpers_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

// Regression test for agentic-content-access-0d0jk.1 / RAMP-103.
//
// Core Invariant: a redeemed offer is a self-contained bearer token — the agent
// presents the WHOLE signed Offer in the execute request (TransactionRequest in
// single mode, TransactionItem in batch mode), so the verifier checks
// Offer.signature over the exact reflected bytes rather than reconstructing them
// from the catalog.
//
// The proto contract change this test pins:
//   - TransactionRequest gains `Offer offer` (single mode), NOT field-required.
//   - TransactionItem gains `Offer offer` (batch mode), field-required.
//   - A message-level CEL on TransactionRequest enforces exactly-one-mode:
//     `offer` set XOR `items` non-empty (rule id transaction_request.offer_xor_items).
//
// TDD-red note: until 0d0jk.1 regenerates gen/, TransactionRequest.Offer and
// TransactionItem.Offer do not exist on the generated Go types, so this file
// will NOT COMPILE. That compile failure is the valid red for a schema addition.
//
// xorRuleID is the stable message-CEL rule id the implementation plan assigns to
// the single-vs-batch XOR (Implementation Plan step 3). Asserted when the error
// carries rule ids; absence of the id is reported but does not by itself pass the
// case — the rejection (err != nil) is the load-bearing assertion.
const xorRuleID = "transaction_request.offer_xor_items"

// validOffer returns a minimal Offer that passes protovalidate. While the Offer
// message itself carries no field-level buf.validate rules, its nested Pricing
// does (per_unit requires unit; free requires rate 0), so the embedded Pricing
// must itself be valid. FREE/0 is the simplest valid pricing and matches the
// corpusgen Offer seed. (sampleOffer() in offer_test.go is shaped for SIGNATURE
// tests — PER_UNIT without a unit — which protovalidate rejects.)
func validOffer() *rampv1.Offer {
	return &rampv1.Offer{
		OfferId: "of_valid_1",
		Pricing: &rampv1.Pricing{
			Model: rampv1.PricingModel_PRICING_MODEL_FREE,
			Rate:  "0",
		},
	}
}

// TestTransactionRequest_singleMode_valid pins case 1: a single-mode request
// (offer populated, no items) passes validation.
func TestTransactionRequest_singleMode_valid(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-single-1",
		Offer:          validOffer(),
	}
	if err := ramphelpers.Validate(req); err != nil {
		t.Fatalf("single-mode TransactionRequest (offer set, no items) must validate; got %v", err)
	}
}

// TestTransactionRequest_neitherMode_rejected pins case 2: neither offer nor
// items violates the XOR rule (exactly-one-mode).
func TestTransactionRequest_neitherMode_rejected(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-neither-1",
	}
	err := ramphelpers.Validate(req)
	if err == nil {
		t.Fatalf("TransactionRequest with NEITHER offer nor items must be rejected by the XOR rule")
	}
	assertRuleIfPresent(t, err, xorRuleID)
}

// TestTransactionRequest_bothModes_rejected pins case 3: both offer and items
// set violates the XOR rule.
func TestTransactionRequest_bothModes_rejected(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-both-1",
		Offer:          validOffer(),
		Items: []*rampv1.TransactionItem{
			{Offer: validOffer()},
		},
	}
	err := ramphelpers.Validate(req)
	if err == nil {
		t.Fatalf("TransactionRequest with BOTH offer and items must be rejected by the XOR rule")
	}
	assertRuleIfPresent(t, err, xorRuleID)
}

// TestTransactionItem_missingOffer_rejected pins case 4: a TransactionItem with
// no offer violates the field-level `required` rule on TransactionItem.offer.
// Driven through a batch-mode TransactionRequest so the item is reachable by the
// validator (items must be non-empty for the request itself to be in batch mode).
func TestTransactionItem_missingOffer_rejected(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-item-missing-1",
		Items: []*rampv1.TransactionItem{
			{}, // no offer — must fail the field-required rule
		},
	}
	err := ramphelpers.Validate(req)
	if err == nil {
		t.Fatalf("TransactionItem with no offer must be rejected (offer is field-required)")
	}
}

// TestTransactionRequest_batchMode_valid lightly guards the Core Invariant
// (case 5): a batch-mode request — each item carries a valid offer, no top-level
// offer — passes validation, proving batch mode stays representable under the XOR.
func TestTransactionRequest_batchMode_valid(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-batch-1",
		Items: []*rampv1.TransactionItem{
			{Offer: validOffer()},
			{Offer: validOffer()},
		},
	}
	if err := ramphelpers.Validate(req); err != nil {
		t.Fatalf("batch-mode TransactionRequest (items each with an offer, no top-level offer) must validate; got %v", err)
	}
}

// assertRuleIfPresent reports when the expected rule id is absent from the
// violation set, without failing the case on absence alone — the rejection
// (err != nil) is the binding assertion; the rule id is the precision check.
func assertRuleIfPresent(t *testing.T, err error, want string) {
	t.Helper()
	ids := ramphelpers.ValidationRuleIDs(err)
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		if id == want {
			return
		}
	}
	t.Errorf("expected violation rule %q in %v", want, ids)
}
