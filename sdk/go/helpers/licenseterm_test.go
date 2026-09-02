package helpers_test

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// These tests cover what the shared corpus cannot express from a JSON file:
// nil safety, in-place mutation, the error type, and that the entry face never
// touches its input. Every value-level verdict is pinned by
// testdata/licenseterm-vectors.json and replayed in all three languages.

func TestNormalizeLicenseTerm_IsNilSafeAndInPlace(t *testing.T) {
	helpers.NormalizeLicenseTerm(nil)
	helpers.NormalizeLicenseTerm(&rampv1.LicenseTerm{})
	helpers.NormalizeResourceEntry(nil)

	term := &rampv1.LicenseTerm{Restrictions: []*rampv1.Restriction{
		{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{" Generative-AI "}, Prohibited: []string{"SCRAPE"}},
		{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_OTHER, Permitted: []string{" Left-Alone "}},
	}}
	helpers.NormalizeLicenseTerm(term)
	if got := term.Restrictions[0].Permitted[0]; got != "ai-input" {
		t.Errorf("permitted[0] = %q, want ai-input (in place)", got)
	}
	if got := term.Restrictions[0].Prohibited[0]; got != "crawl" {
		t.Errorf("prohibited[0] = %q, want crawl", got)
	}
	if got := term.Restrictions[1].Permitted[0]; got != " Left-Alone " {
		t.Errorf("OTHER token = %q, want untouched", got)
	}
}

func TestValidateLicenseTerm_ReturnsATypedViolation(t *testing.T) {
	term := &rampv1.LicenseTerm{Pricing: &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("frobnications")}}
	warnings, err := helpers.ValidateLicenseTerm(term)
	if err == nil {
		t.Fatal("expected a violation")
	}
	var rv *helpers.RuleViolation
	if !errors.As(err, &rv) {
		t.Fatalf("error is %T, want *helpers.RuleViolation", err)
	}
	if rv.Rule != helpers.RulePricingUnitRegistered || rv.Path != "pricing.unit" || rv.Token != "frobnications" {
		t.Errorf("violation = %+v", *rv)
	}
	if err.Error() != rv.Message {
		t.Errorf("Error() = %q, want the message %q", err.Error(), rv.Message)
	}
	if warnings != nil {
		t.Errorf("a rejected term carries no warnings, got %v", warnings)
	}
	if ws, err := helpers.ValidateLicenseTerm(nil); err != nil || len(ws) != 0 {
		t.Errorf("ValidateLicenseTerm(nil) = %v, %v; want no findings", ws, err)
	}
}

func TestValidateResourceEntry_NeverMutatesAndIsNilSafe(t *testing.T) {
	if v := helpers.ValidateResourceEntry(nil); v.OK() {
		t.Error("a nil entry must not be OK")
	}
	entry := &rampv1.ResourceEntry{Domain: "publisher.example", Path: "/x", Terms: []*rampv1.LicenseTerm{{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"},
		Restrictions: []*rampv1.Restriction{{
			Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"Generative-AI"},
		}},
	}}}
	snapshot := proto.Clone(entry)
	verdict := helpers.ValidateResourceEntry(entry)
	if !verdict.OK() {
		t.Fatalf("expected OK, got violations %+v", verdict.Violations)
	}
	if len(verdict.Warnings) != 0 {
		t.Errorf("an alias resolves before membership, want no warning; got %+v", verdict.Warnings)
	}
	if !proto.Equal(entry, snapshot) {
		t.Error("ValidateResourceEntry modified its input; it must normalise a copy")
	}
	if got := entry.Terms[0].Restrictions[0].Permitted[0]; got != "Generative-AI" {
		t.Errorf("input token = %q, want the caller's spelling left alone", got)
	}
}

func TestValidateResourceEntry_ReportsBothTiersWithEntryPaths(t *testing.T) {
	entry := &rampv1.ResourceEntry{Domain: "publisher.example", Path: "no-leading-slash", Terms: []*rampv1.LicenseTerm{
		{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}},
		{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "1", Currency: "USD", Unit: proto.String("frobnications")}},
	}}
	verdict := helpers.ValidateResourceEntry(entry)
	if verdict.OK() {
		t.Fatal("expected violations")
	}
	var sawPath, sawTerm bool
	for _, v := range verdict.Violations {
		switch {
		case v.Path == "path" && v.Rule == "string.pattern":
			sawPath = true
		case v.Path == "terms[1].pricing.unit" && v.Rule == helpers.RulePricingUnitRegistered:
			sawTerm = true
		}
	}
	if !sawPath || !sawTerm {
		t.Errorf("want both the wire-tier path violation and the ingest-tier term violation, got %+v", verdict.Violations)
	}
}
