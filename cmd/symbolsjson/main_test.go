package main

import "testing"

// TestBuildSymbols pins the symbol-table contract the docs autolink guard relies on:
// real members resolve, drifted/removed members do not, and a field points at its
// owning message's heading. These are positive controls — if the descriptor walk
// silently stopped emitting fields, this test fails rather than the guard passing
// vacuously.
func TestBuildSymbols(t *testing.T) {
	// Controlled "documented" set (heading slugs on the reference page) so the test
	// is independent of the live docs: TransactionRequest is documented, Preview is
	// deliberately not — exercising the linkable-only-if-documented gate.
	doc := map[string]bool{
		"transactionrequest": true,
		"denialreason":       true,
		"catalogservice":     true,
		"pricingmodel":       true,
		"errordetail":        true,
	}
	syms := buildSymbols(doc)

	present := []string{
		"TransactionRequest",                 // message
		"TransactionRequest.idempotency_key", // snake field
		"ErrorDetail.usageReportRejection",   // JSON camelCase field name
		"DenialReason",                       // enum
		"PRICING_MODEL_PER_UNIT",             // full enum value
		"PER_UNIT",                           // short enum value form
		"CatalogService",                     // service
		"CatalogService.PushResources",       // method
	}
	for _, k := range present {
		if _, ok := syms[k]; !ok {
			t.Errorf("expected symbol %q to be present", k)
		}
	}

	// Drift sentinels: these named real types but non-existent members, and must
	// NOT resolve — that is exactly what lets the guard flag them.
	absent := []string{
		"TransactionRequest.id",      // never existed; idempotency_key is the field
		"CatalogService.PushContent", // wrong method name
		"Offer.quality",              // removed field
	}
	for _, k := range absent {
		if _, ok := syms[k]; ok {
			t.Errorf("did not expect removed/invalid symbol %q to resolve", k)
		}
	}

	if got := syms["TransactionRequest.idempotency_key"].Heading; got != "TransactionRequest" {
		t.Errorf("field heading = %q, want owning message %q", got, "TransactionRequest")
	}

	// Linkable-only-if-documented: Preview is a real message but absent from `doc`,
	// so it must resolve (guard) yet carry no link heading (no dead anchor).
	if p, ok := syms["Preview"]; !ok {
		t.Error("Preview should resolve as a symbol")
	} else if p.Heading != "" {
		t.Errorf("Preview.Heading = %q, want \"\" (undocumented on the reference page → not linkable)", p.Heading)
	}
}
