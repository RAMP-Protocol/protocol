package helpers_test

import (
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Regression test for the items-only collapse.
//
// Core Invariant: a redeemed offer is a self-contained bearer token — the agent
// presents the WHOLE signed Offer in each TransactionItem, so the verifier
// checks Offer.signature over the exact reflected bytes rather than
// reconstructing them from the catalog. Single-offer mode was removed: a single
// offer is the degenerate 1-element `items` list.
//
// The proto contract this test pins:
//   - TransactionRequest carries `repeated TransactionItem items` with
//     repeated.min_items=1 (no top-level offer; the offer_xor_items CEL is gone).
//   - TransactionItem.offer is field-required.
//
// minItemsRuleID is the protovalidate rule id for the items min_items=1
// constraint. Asserted when the error carries rule ids; absence is reported but
// does not by itself pass the case — the rejection (err != nil) is load-bearing.
const minItemsRuleID = "repeated.min_items"

// validOffer returns a minimal Offer that passes protovalidate. Three things
// have to hold at once, and each has a different source. The nested Pricing
// carries its own rules (per_unit requires unit; free requires rate 0), so the
// embedded Pricing must itself be valid — FREE/0 is the simplest valid pricing
// and matches the corpusgen Offer seed. (sampleOffer() in offer_test.go is
// shaped for SIGNATURE tests — PER_UNIT without a unit — which protovalidate
// rejects.) Exchange is presence-enforced: it is the execute-routing target,
// and a TransactionRequest's audience statement is per item, so an offer
// without it is unroutable. Signature carries a 128-character hex pattern, so
// an unsigned offer no longer validates at all; the value below is filler in
// that shape, not a signature over anything.
func validOffer() *rampv1.Offer {
	return &rampv1.Offer{
		OfferId:  "of_valid_1",
		Exchange: "exchange.example",
		Pricing: &rampv1.Pricing{
			Model: rampv1.PricingModel_PRICING_MODEL_FREE,
			Rate:  "0",
		},
		Signature: strings.Repeat("ab", 64),
	}
}

// TestTransactionRequest_items_valid pins the happy path: a request whose items
// each carry a valid offer passes validation (a single offer is a 1-item list).
func TestTransactionRequest_items_valid(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-items-1",
		Items: []*rampv1.TransactionItem{
			{Offer: validOffer()},
		},
	}
	if err := helpers.Validate(req); err != nil {
		t.Fatalf("items-only TransactionRequest (one item with an offer) must validate; got %v", err)
	}
}

// TestTransactionRequest_emptyItems_rejected pins the items-min-1 rule: a request
// with no items is rejected (single-offer mode is gone — there is no other way to
// commit an offer).
func TestTransactionRequest_emptyItems_rejected(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-empty-1",
	}
	err := helpers.Validate(req)
	if err == nil {
		t.Fatalf("TransactionRequest with empty items must be rejected by repeated.min_items=1")
	}
	assertRuleIfPresent(t, err, minItemsRuleID)
}

// TestTransactionItem_missingOffer_rejected pins case: a TransactionItem with
// no offer violates the field-level `required` rule on TransactionItem.offer.
func TestTransactionItem_missingOffer_rejected(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-item-missing-1",
		Items: []*rampv1.TransactionItem{
			{}, // no offer — must fail the field-required rule
		},
	}
	err := helpers.Validate(req)
	if err == nil {
		t.Fatalf("TransactionItem with no offer must be rejected (offer is field-required)")
	}
}

// TestTransactionRequest_multiItem_valid guards the Core Invariant: a multi-item
// request — each item carries a valid offer — passes validation.
func TestTransactionRequest_multiItem_valid(t *testing.T) {
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "idem-multi-1",
		Items: []*rampv1.TransactionItem{
			{Offer: validOffer()},
			{Offer: validOffer()},
		},
	}
	if err := helpers.Validate(req); err != nil {
		t.Fatalf("multi-item TransactionRequest (each item with an offer) must validate; got %v", err)
	}
}

// assertRuleIfPresent reports when the expected rule id is absent from the
// violation set, without failing the case on absence alone — the rejection
// (err != nil) is the binding assertion; the rule id is the precision check.
func assertRuleIfPresent(t *testing.T, err error, want string) {
	t.Helper()
	ids := helpers.ValidationRuleIDs(err)
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
