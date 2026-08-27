package helpers

// License-term golden-vector emitter.
//
// The sdk/ts and sdk/python ports of the ingest-tier checks — token folding and
// alias resolution, term normalisation, registry membership, the per-term
// verdict and the composed per-entry verdict — assert byte-parity against this
// Go oracle. Every expected value is DERIVED by calling the REAL Go face, never
// hand-typed, exactly as gen_util_vectors_test.go derives the scopes and money
// corpora.
//
// Like TestGenerateVectors this test is a verification no-op by default (it
// asserts the committed file matches a fresh emit) and (re)writes it under
// RAMP_UPDATE_VECTORS=1 — the emitter is both generator and drift gate. It is
// TEST INFRASTRUCTURE, not the code under test.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

const licenseTermVectorsPath = "testdata/licenseterm-vectors.json"

// ltFoldVector is one CanonicalRestrictionToken case. kind is the enum NAME, the
// form the JSON clients see on the wire.
type ltFoldVector struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Token     string `json:"token"`
	Canonical string `json:"canonical"`
}

// ltNormalizeVector is one NormalizeLicenseTerm case: a term as proto-JSON and the
// same term after normalisation. Applying the face twice must give the second
// form again (idempotency), which the emitter asserts before it records.
type ltNormalizeVector struct {
	Name       string          `json:"name"`
	Term       json.RawMessage `json:"term"`
	Normalized json.RawMessage `json:"normalized"`
}

// ltKnownVector is one KnownRestrictionToken case.
type ltKnownVector struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Token string `json:"token"`
	Known bool   `json:"known"`
}

// ltFinding is a violation or a warning as the three SDKs report it: the rule
// id, the snake_case path relative to the checked message, the offending token
// where the rule is about one, and the message — the exact string the Exchange
// puts on the wire for a warning.
type ltFinding struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Token   string `json:"token"`
	Message string `json:"message"`
}

// ltValidateVector is one ValidateLicenseTerm case over an already-canonical term.
type ltValidateVector struct {
	Name      string          `json:"name"`
	Term      json.RawMessage `json:"term"`
	Violation *ltFinding      `json:"violation"`
	Warnings  []ltFinding     `json:"warnings"`
}

// ltEntryVector is one ValidateResourceEntry case. structural reports whether the
// wire tier refused the entry (the exact wire-tier ids are language-local);
// term_rules are the ingest-tier rule ids in report order; warnings are the
// accepted terms' warnings with entry-relative paths.
type ltEntryVector struct {
	Name       string          `json:"name"`
	Entry      json.RawMessage `json:"entry"`
	OK         bool            `json:"ok"`
	Structural bool            `json:"structural"`
	TermRules  []string        `json:"term_rules"`
	Warnings   []ltFinding     `json:"warnings"`
}

var ltVectorJSON = protojson.MarshalOptions{UseProtoNames: true}

func ltProtoJSON(t *testing.T, m proto.Message) json.RawMessage {
	t.Helper()
	b, err := ltVectorJSON.Marshal(m)
	if err != nil {
		t.Fatalf("marshal %T: %v", m, err)
	}
	// Re-encode through encoding/json so the committed bytes carry the corpus
	// writer's own formatting rather than protojson's deliberately unstable one.
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("re-decode %T: %v", m, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-encode %T: %v", m, err)
	}
	return out
}

func ltFindingOf(rule, path, token, message string) ltFinding {
	return ltFinding{Rule: rule, Path: path, Token: token, Message: message}
}

func ltWarningsOf(ws []RuleWarning) []ltFinding {
	out := make([]ltFinding, 0, len(ws))
	for _, w := range ws {
		out = append(out, ltFindingOf(w.Rule, w.Path, w.Token, w.Message))
	}
	return out
}

const (
	ltKindFunction    = rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION
	ltKindGeography   = rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY
	ltKindUserType    = rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE
	ltKindOther       = rampv1.RestrictionKind_RESTRICTION_KIND_OTHER
	ltKindUnspecified = rampv1.RestrictionKind_RESTRICTION_KIND_UNSPECIFIED
)

// buildLTFoldVectors emits the CanonicalRestrictionToken corpus. The non-ASCII
// inputs are the load-bearing rows: a port that reaches for its platform's
// Unicode lowercase folds U+212A into "k" and turns a homograph into a
// registered token.
func buildLTFoldVectors() []ltFoldVector {
	cases := []struct {
		name  string
		kind  rampv1.RestrictionKind
		token string
	}{
		{"function_alias_tdm", ltKindFunction, "tdm"},
		{"function_alias_mixed_case_padded", ltKindFunction, "  Generative-AI "},
		{"function_registered_upper", ltKindFunction, "AI-INPUT"},
		{"function_unknown_lowercased", ltKindFunction, "Flibbertigibbet"},
		{"function_alias_derivative", ltKindFunction, "Derivative"},
		{"user_type_alias_business", ltKindUserType, "Business"},
		{"user_type_registered_untouched", ltKindUserType, "commercial_entity"},
		{"geography_lower_to_upper", ltKindGeography, "us"},
		{"geography_padded", ltKindGeography, " de "},
		{"geography_wildcard", ltKindGeography, "*"},
		{"geography_special_eea", ltKindGeography, "eea"},
		{"other_untouched", ltKindOther, "  Custom-Token "},
		{"unspecified_kind_untouched", ltKindUnspecified, "AI-Train"},
		{"kelvin_sign_not_folded", ltKindFunction, "KEEP"},
		{"dotted_capital_i_not_folded", ltKindFunction, "İnput"},
		{"eszett_not_folded", ltKindUserType, "STRAßE"},
		{"nbsp_not_trimmed", ltKindFunction, " tdm "},
		{"ideographic_space_not_trimmed", ltKindGeography, "　us　"},
		{"rfc8259_whitespace_trimmed", ltKindFunction, "\t\ntdm\r "},
		{"namespaced_lowercased_not_aliased", ltKindFunction, "Acme:Custom-Use"},
		{"empty", ltKindFunction, ""},
	}
	out := make([]ltFoldVector, 0, len(cases))
	for _, c := range cases {
		out = append(out, ltFoldVector{
			Name:      c.name,
			Kind:      c.kind.String(),
			Token:     c.token,
			Canonical: CanonicalRestrictionToken(c.kind, c.token), // REAL face
		})
	}
	return out
}

func ltRestriction(kind rampv1.RestrictionKind, permitted, prohibited []string) *rampv1.Restriction {
	return &rampv1.Restriction{Kind: kind, Permitted: permitted, Prohibited: prohibited}
}

func ltPerUnitPricing(unit string) *rampv1.Pricing {
	return &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String(unit)}
}

func ltFreePricing() *rampv1.Pricing {
	return &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}
}

func ltEnumerated(pricing *rampv1.Pricing, mutate func(t *rampv1.LicenseTerm)) *rampv1.LicenseTerm {
	t := &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: pricing}
	if mutate != nil {
		mutate(t)
	}
	return t
}

// buildLTNormalizeVectors emits the NormalizeLicenseTerm corpus and asserts, for
// every case, that the face is idempotent: normalising the normalised term
// changes nothing.
func buildLTNormalizeVectors(t *testing.T) []ltNormalizeVector {
	t.Helper()
	cases := []struct {
		name string
		term *rampv1.LicenseTerm
	}{
		{"function_permitted_aliases", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"generative-ai", "train-ai", "tdm"}, nil)}
		})},
		{"function_prohibited_aliases", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, nil, []string{"scrape", "copy", "adapt", "derivative"})}
		})},
		{"function_mixed_case_padding", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"  Generative-AI ", "AI-INPUT"}, nil)}
		})},
		{"user_type_aliases", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindUserType, []string{"personal", "business", "enterprise"}, nil)}
		})},
		{"geography_upper", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindGeography, []string{"us", " de ", "eu", "*"}, nil)}
		})},
		{"other_untouched", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindOther, []string{"Custom-Token", "  Spaced  "}, nil)}
		})},
		{"function_unknown_lowercased", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"Search", "Display"}, nil)}
		})},
		{"three_axes_at_once", ltEnumerated(ltPerUnitPricing("tokens"), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{
				ltRestriction(ltKindFunction, []string{"TDM"}, []string{"Scrape"}),
				ltRestriction(ltKindGeography, []string{"gb", "eea"}, nil),
				ltRestriction(ltKindOther, []string{"Left-Alone"}, nil),
			}
			x.Quotas = []*rampv1.Quota{{Metric: "tokens", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
			x.Scopes = []string{"Subscription:Premium"}
		})},
		{"restriction_without_tokens", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, nil, nil)}
		})},
		{"non_ascii_untouched", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"KEEP", " tdm"}, nil)}
		})},
		{"empty_term", &rampv1.LicenseTerm{}},
	}
	out := make([]ltNormalizeVector, 0, len(cases))
	for _, c := range cases {
		input := ltProtoJSON(t, c.term)
		once, ok := proto.Clone(c.term).(*rampv1.LicenseTerm)
		if !ok {
			t.Fatalf("%s: clone", c.name)
		}
		NormalizeLicenseTerm(once) // REAL face
		twice, ok := proto.Clone(once).(*rampv1.LicenseTerm)
		if !ok {
			t.Fatalf("%s: clone", c.name)
		}
		NormalizeLicenseTerm(twice)
		if !proto.Equal(once, twice) {
			t.Fatalf("%s: NormalizeLicenseTerm is not idempotent", c.name)
		}
		out = append(out, ltNormalizeVector{Name: c.name, Term: input, Normalized: ltProtoJSON(t, once)})
	}
	return out
}

// buildLTKnownVectors emits the KnownRestrictionToken corpus.
func buildLTKnownVectors() []ltKnownVector {
	cases := []struct {
		name  string
		kind  rampv1.RestrictionKind
		token string
	}{
		{"function_registered", ltKindFunction, "ai-train"},
		{"function_registered_second", ltKindFunction, "ai-input"},
		{"function_unknown", ltKindFunction, "ai-foo"},
		{"function_alias_is_not_registered", ltKindFunction, "tdm"},
		{"function_uppercase_not_registered", ltKindFunction, "AI-TRAIN"},
		{"geography_iso_alpha2", ltKindGeography, "US"},
		{"geography_iso_alpha2_any_two_letters", ltKindGeography, "ZZ"},
		{"geography_special_wildcard", ltKindGeography, "*"},
		{"geography_special_eea", ltKindGeography, "EEA"},
		{"geography_lowercase", ltKindGeography, "us"},
		{"geography_three_letters", ltKindGeography, "USA"},
		{"geography_non_ascii_two_letters", ltKindGeography, "ÉE"},
		{"user_type_registered", ltKindUserType, "commercial_entity"},
		{"user_type_unknown", ltKindUserType, "robots"},
		{"user_type_alias_is_not_registered", ltKindUserType, "business"},
		{"other_never_known", ltKindOther, "ai-train"},
		{"unspecified_never_known", ltKindUnspecified, "ai-train"},
		{"empty_not_known", ltKindFunction, ""},
	}
	out := make([]ltKnownVector, 0, len(cases))
	for _, c := range cases {
		out = append(out, ltKnownVector{
			Name:  c.name,
			Kind:  c.kind.String(),
			Token: c.token,
			Known: KnownRestrictionToken(c.kind, c.token), // REAL face
		})
	}
	return out
}

// buildLTValidateVectors emits the ValidateLicenseTerm corpus over canonical terms.
func buildLTValidateVectors(t *testing.T) []ltValidateVector {
	t.Helper()
	licenseURI := func() *rampv1.License {
		return &rampv1.License{Uri: proto.String("https://example.com/license.txt"), UriDigest: proto.String("sha256:" + ltRepeatHex(64))}
	}
	cases := []struct {
		name string
		term *rampv1.LicenseTerm
	}{
		{"reference_only_with_restrictions_accepted", &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, License: licenseURI(), Pricing: ltPerUnitPricing("accesses"),
			Restrictions: []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"ai-train"}, nil)},
		}},
		{"reference_only_bare_accepted", &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, License: licenseURI(), Pricing: ltPerUnitPricing("accesses"),
		}},
		{"pricing_unit_unregistered_rejected", ltEnumerated(ltPerUnitPricing("frobnications"), nil)},
		{"pricing_unit_registered_accepted", ltEnumerated(ltPerUnitPricing("tokens"), nil)},
		{"pricing_unit_namespaced_accepted", ltEnumerated(ltPerUnitPricing("acme:widgets"), nil)},
		{"pricing_unit_empty_not_checked", ltEnumerated(ltFreePricing(), nil)},
		{"pricing_unit_uppercase_rejected", ltEnumerated(ltPerUnitPricing("TOKENS"), nil)},
		{"quota_metric_unregistered_rejected", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Quotas = []*rampv1.Quota{{Metric: "frobnications", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
		})},
		{"quota_metric_second_quota_rejected", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Quotas = []*rampv1.Quota{
				{Metric: "tokens", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY},
				{Metric: "frobnications", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY},
			}
		})},
		{"quota_metric_registered_accepted", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Quotas = []*rampv1.Quota{{Metric: "tokens", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
		})},
		{"quota_metric_namespaced_accepted", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Quotas = []*rampv1.Quota{{Metric: "acme:widgets", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
		})},
		{"pricing_unit_checked_before_quota", ltEnumerated(ltPerUnitPricing("frobnications"), func(x *rampv1.LicenseTerm) {
			x.Quotas = []*rampv1.Quota{{Metric: "gizmos", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"flibbertigibbet"}, nil)}
		})},
		{"distinct_kinds_disjoint_tokens_accepted", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{
				ltRestriction(ltKindFunction, []string{"ai-train"}, []string{"search"}),
				ltRestriction(ltKindGeography, []string{"US"}, nil),
			}
		})},
		{"unregistered_token_advisory_warns", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{{Kind: ltKindFunction, Permitted: []string{"flibbertigibbet"}, Advisory: true}}
		})},
		{"unregistered_token_binding_also_only_warns", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{{Kind: ltKindFunction, Permitted: []string{"flibbertigibbet"}, Advisory: false}}
		})},
		{"registered_token_binding_accepted_cleanly", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{{Kind: ltKindFunction, Permitted: []string{"ai-train"}, Advisory: false}}
		})},
		{"namespaced_token_bypasses_membership_on_other", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindOther, []string{"acme:custom-use"}, nil)}
		})},
		{"bare_token_on_other_warns", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindOther, []string{"custom-use"}, nil)}
		})},
		{"warnings_in_report_order", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Restrictions = []*rampv1.Restriction{
				ltRestriction(ltKindFunction, []string{"ai-train", "flib"}, []string{"blib"}),
				ltRestriction(ltKindGeography, []string{"US", "usa"}, nil),
				ltRestriction(ltKindUserType, []string{"robots"}, nil),
			}
			x.Obligations = []*rampv1.Obligation{
				{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE},
				{Kind: rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE},
				{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE},
			}
		})},
		{"other_obligation_without_detail_warns", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}}
		})},
		{"other_obligation_with_detail_accepted", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, Detail: proto.String("see appendix B")}}
		})},
		{"attribution_obligation_without_detail_accepted", ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
			x.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}}
		})},
		{"empty_term_accepted", &rampv1.LicenseTerm{}},
	}
	out := make([]ltValidateVector, 0, len(cases))
	for _, c := range cases {
		warnings, err := ValidateLicenseTerm(c.term) // REAL face
		v := ltValidateVector{Name: c.name, Term: ltProtoJSON(t, c.term), Warnings: ltWarningsOf(warnings)}
		if err != nil {
			var rv *RuleViolation
			if !errors.As(err, &rv) {
				t.Fatalf("%s: ValidateLicenseTerm returned a non-RuleViolation error: %v", c.name, err)
			}
			f := ltFindingOf(rv.Rule, rv.Path, rv.Token, rv.Message)
			v.Violation = &f
		}
		out = append(out, v)
	}
	return out
}

// buildLTEntryVectors emits the ValidateResourceEntry corpus: the composition of
// the two tiers in the Exchange's order, over the entry exactly as given.
func buildLTEntryVectors(t *testing.T) []ltEntryVector {
	t.Helper()
	entry := func(mutate func(e *rampv1.ResourceEntry)) *rampv1.ResourceEntry {
		e := &rampv1.ResourceEntry{Domain: "publisher.example", Path: "/premium/article-42.html",
			Terms: []*rampv1.LicenseTerm{ltEnumerated(ltFreePricing(), nil)}}
		if mutate != nil {
			mutate(e)
		}
		return e
	}
	cases := []struct {
		name  string
		entry *rampv1.ResourceEntry
	}{
		{"valid_minimal", entry(nil)},
		{"domain_with_port_and_single_label_accepted", entry(func(e *rampv1.ResourceEntry) { e.Domain = "edge:8787" })},
		{"alias_resolved_before_membership_no_warning", entry(func(e *rampv1.ResourceEntry) {
			e.Terms[0].Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"Generative-AI"}, nil)}
		})},
		{"unknown_token_warns_with_entry_path", entry(func(e *rampv1.ResourceEntry) {
			e.Terms = append(e.Terms, ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
				x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"ai-train", "flibbertigibbet"}, nil)}
			}))
		})},
		{"structural_path_without_slash", entry(func(e *rampv1.ResourceEntry) { e.Path = "premium/article-42.html" })},
		{"structural_empty_domain", entry(func(e *rampv1.ResourceEntry) { e.Domain = "" })},
		{"structural_domain_with_scheme", entry(func(e *rampv1.ResourceEntry) { e.Domain = "https://publisher.example" })},
		{"structural_padded_token_fails_wire_before_fold", entry(func(e *rampv1.ResourceEntry) {
			e.Terms[0].Restrictions = []*rampv1.Restriction{ltRestriction(ltKindGeography, []string{" de "}, nil)}
		})},
		{"structural_term_without_pricing", entry(func(e *rampv1.ResourceEntry) {
			e.Terms[0].Pricing = nil
		})},
		{"structural_nested_cel_only", entry(func(e *rampv1.ResourceEntry) {
			e.Terms = append(e.Terms, ltEnumerated(&rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD"}, nil))
		})},
		{"structural_too_many_terms", entry(func(e *rampv1.ResourceEntry) {
			for len(e.Terms) < 33 {
				e.Terms = append(e.Terms, ltEnumerated(ltFreePricing(), nil))
			}
		})},
		{"term_reject_pricing_unit", entry(func(e *rampv1.ResourceEntry) {
			e.Terms[0] = ltEnumerated(ltPerUnitPricing("frobnications"), nil)
		})},
		{"term_reject_second_term_quota", entry(func(e *rampv1.ResourceEntry) {
			e.Terms = append(e.Terms, ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
				x.Quotas = []*rampv1.Quota{{Metric: "gizmos", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
			}))
		})},
		{"term_reject_drops_that_terms_warnings", entry(func(e *rampv1.ResourceEntry) {
			e.Terms[0] = ltEnumerated(ltPerUnitPricing("frobnications"), func(x *rampv1.LicenseTerm) {
				x.Restrictions = []*rampv1.Restriction{ltRestriction(ltKindFunction, []string{"flibbertigibbet"}, nil)}
			})
			e.Terms = append(e.Terms, ltEnumerated(ltFreePricing(), func(x *rampv1.LicenseTerm) {
				x.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}}
			}))
		})},
		{"structural_and_term_reject_both_reported", entry(func(e *rampv1.ResourceEntry) {
			e.Path = "x"
			e.Terms[0] = ltEnumerated(ltPerUnitPricing("frobnications"), nil)
		})},
		{"no_terms_accepted", entry(func(e *rampv1.ResourceEntry) { e.Terms = nil })},
	}
	out := make([]ltEntryVector, 0, len(cases))
	for _, c := range cases {
		before := ltProtoJSON(t, c.entry)
		verdict := ValidateResourceEntry(c.entry) // REAL face
		if after := ltProtoJSON(t, c.entry); string(after) != string(before) {
			t.Fatalf("%s: ValidateResourceEntry modified its input", c.name)
		}
		v := ltEntryVector{Name: c.name, Entry: before, OK: verdict.OK(), TermRules: []string{}, Warnings: ltWarningsOf(verdict.Warnings)}
		for _, viol := range verdict.Violations {
			switch viol.Rule {
			case RulePricingUnitRegistered, RuleQuotaMetricRegistered:
				v.TermRules = append(v.TermRules, viol.Rule)
			default:
				v.Structural = true
			}
		}
		out = append(out, v)
	}
	return out
}

func ltRepeatHex(n int) string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexdigits[i%len(hexdigits)]
	}
	return string(b)
}

// TestGenerateLicenseTermVectors emits the license-term golden corpus.
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateLicenseTermVectors(t *testing.T) {
	doc := map[string]any{
		"note": "Go-emitted oracle for the ingest-tier license-term checks. fold: CanonicalRestrictionToken; " +
			"normalize: NormalizeLicenseTerm (idempotent); known: KnownRestrictionToken; validate: ValidateLicenseTerm over " +
			"canonical terms; entry: ValidateResourceEntry (wire tier over the raw entry, then the ingest tier over a " +
			"canonicalised copy). Messages are the exact strings the Exchange puts in PushResourcesResponse.warnings. " +
			"Regenerate with RAMP_UPDATE_VECTORS=1 go test ./sdk/go/helpers/ -run TestGenerateLicenseTermVectors.",
		"fold":      buildLTFoldVectors(),
		"normalize": buildLTNormalizeVectors(t),
		"known":     buildLTKnownVectors(),
		"validate":  buildLTValidateVectors(t),
		"entry":     buildLTEntryVectors(t),
	}
	path := filepath.Join("testdata", filepath.Base(licenseTermVectorsPath))
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
