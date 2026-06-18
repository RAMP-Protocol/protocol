// Package conformance holds machine checks that the doc-conformance denylist
// gate structurally cannot perform: it actually *evaluates* the protovalidate
// CEL constraints embedded in the proto, and validates the example payloads in
// the docs against the wire contract. A green run here means the constraints
// fire as written and the documented examples would survive ingestion.
package conformance

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestProtovalidateConstraints exercises every CEL/standard constraint added by
// the licensing core against representative valid and invalid instances. Until
// this existed, a syntactically-valid-but-wrong CEL (mis-anchored regex,
// renamed field reference) shipped green because nothing in the toolchain ever
// evaluated the constraints — `buf lint` is style-only and `buf generate` just
// embeds the option bytes. This is the regression guard for that whole class.
func TestProtovalidateConstraints(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	hex64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cases := []struct {
		name      string
		msg       proto.Message
		wantValid bool
	}{
		// License.uri_digest — strong-hash structure only.
		{"uri_digest empty ok", &rampv1.License{UriDigest: proto.String("")}, true},
		{"uri_digest sha256 ok", &rampv1.License{UriDigest: proto.String("sha256:" + hex64)}, true},
		{"uri_digest md5 rejected", &rampv1.License{UriDigest: proto.String("md5:" + hex64)}, false},
		{"uri_digest sha256 wrong length", &rampv1.License{UriDigest: proto.String("sha256:dead")}, false},
		{"uri_digest sha256 non-hex", &rampv1.License{UriDigest: proto.String("sha256:" + "g" + hex64[1:])}, false},

		// Pricing message-level CEL: PER_UNIT⇒unit set; FREE⇒rate 0.
		{"pricing per_unit with unit ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("tokens"), Currency: "USD", Rate: 0.05}, true},
		{"pricing per_unit without unit rejected", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Currency: "USD", Rate: 0.05}, false},
		{"pricing free zero rate ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: 0}, true},
		{"pricing free nonzero rate rejected", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: 1.0}, false},

		// Pricing.unit format: empty / bare-dashed / vendor:namespaced.
		{"pricing unit bare ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("sq-km"), Rate: 1}, true},
		{"pricing unit vendor ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("acme:widgets"), Rate: 1}, true},
		{"pricing unit with space rejected", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("two words"), Rate: 1}, false},

		// AcceptableRestriction.values charset + max_items.
		{"acceptable values ok", &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai-train", "ai-input"}}, true},
		{"acceptable values space rejected", &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai train"}}, false},
		{"acceptable values too many rejected", &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: gen65()}, false},

		// Restriction.permitted/prohibited charset.
		{"restriction permitted ok", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}}, true},
		{"restriction permitted control-char rejected", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"bad\ttoken"}}, false},
		{"restriction prohibited ok", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Prohibited: []string{"ai-train"}}, true},
		{"restriction prohibited space rejected", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Prohibited: []string{"ai train"}}, false},

		// Quota.metric format — bare-dashed or vendor:namespaced; empty rejected.
		{"quota metric bare ok", &rampv1.Quota{Metric: "display-words", Limit: 1}, true},
		{"quota metric vendor ok", &rampv1.Quota{Metric: "acme:frames", Limit: 1}, true},
		{"quota metric empty rejected", &rampv1.Quota{Metric: "", Limit: 1}, false},
		{"quota metric space rejected", &rampv1.Quota{Metric: "two words", Limit: 1}, false},

		// d8y64 — License.uri present requires uri_digest (any semantics).
		{"license no uri ok", &rampv1.License{Id: proto.String("CC-BY-4.0")}, true},
		{"license uri with digest ok", &rampv1.License{Uri: proto.String("https://x.example/lic"), UriDigest: proto.String("sha256:" + hex64)}, true},
		{"license uri without digest rejected", &rampv1.License{Uri: proto.String("https://x.example/lic")}, false},

		// fc65j — LicenseTerm presence invariants (pricing required; REFERENCE_ONLY needs license.uri).
		{"term enumerated with pricing ok", &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: freePricing()}, true},
		{"term missing pricing rejected", &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED}, false},
		{"term reference_only with license uri ok", &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Pricing: freePricing(), License: &rampv1.License{Uri: proto.String("https://x.example/lic"), UriDigest: proto.String("sha256:" + hex64)}}, true},
		{"term reference_only without license uri rejected", &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Pricing: freePricing()}, false},

		// 6z1v3 — license-term coherence rules.
		{"restriction disjoint ok", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}, Prohibited: []string{"ai-train"}}, true},
		{"restriction overlap rejected", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}, Prohibited: []string{"ai-input"}}, false},
		{"term one restriction per kind ok", &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: freePricing(), Restrictions: []*rampv1.Restriction{{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION}, {Kind: rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY}}}, true},
		{"term duplicate restriction kind rejected", &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: freePricing(), Restrictions: []*rampv1.Restriction{{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION}, {Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION}}}, false},
		{"quota limit ok", &rampv1.Quota{Metric: "accesses", Limit: 1}, true},
		{"quota limit zero rejected", &rampv1.Quota{Metric: "accesses", Limit: 0}, false},
		{"obligation share_alike with spdx id ok", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, ScopeLicense: &rampv1.License{Id: proto.String("CC-BY-SA-4.0")}}, true},
		{"obligation share_alike without scope_license rejected", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE}, false},
		{"obligation share_alike scope_license uri+digest ok", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, ScopeLicense: &rampv1.License{Uri: proto.String("https://creativecommons.org/licenses/by-sa/4.0/"), UriDigest: proto.String("sha256:" + hex64)}}, true},
		{"obligation share_alike scope_license uri without digest rejected", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, ScopeLicense: &rampv1.License{Uri: proto.String("https://creativecommons.org/licenses/by-sa/4.0/")}}, false},

		// Required-enum discriminators — UNSPECIFIED (zero) is never a valid value.
		// These guard the gap where the conditional coherence CELs above are
		// vacuously satisfied by an unset discriminator.
		{"term semantics unspecified rejected", &rampv1.LicenseTerm{Pricing: freePricing()}, false},
		{"pricing model unspecified rejected", &rampv1.Pricing{Rate: 0}, false},
		{"restriction kind unspecified rejected", &rampv1.Restriction{Permitted: []string{"ai-input"}}, false},
		{"obligation kind unspecified rejected", &rampv1.Obligation{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.msg)
			if tc.wantValid && err != nil {
				t.Errorf("expected VALID, got error: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Errorf("expected INVALID, but validation passed")
			}
		})
	}
}

// TestIdempotencyKeyRequired asserts the state-mutating requests require a
// non-empty idempotency_key — the dedup guarantee has no teeth without it. The
// proto declares the contract ahead of full enforcement; this is the guard that
// the required-key constraint actually fires across every SDK.
func TestIdempotencyKeyRequired(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	cases := []struct {
		name      string
		msg       proto.Message
		wantValid bool
	}{
		{"transaction empty key rejected", &rampv1.TransactionRequest{IdempotencyKey: ""}, false},
		{"transaction key ok", &rampv1.TransactionRequest{IdempotencyKey: "idem-tx-1"}, true},
		{"usage report empty key rejected", &rampv1.UsageReport{IdempotencyKey: ""}, false},
		{"usage report key ok", &rampv1.UsageReport{IdempotencyKey: "idem-ur-1"}, true},
		{"dispute empty key rejected", &rampv1.DisputeRequest{IdempotencyKey: ""}, false},
		{"dispute key ok", &rampv1.DisputeRequest{IdempotencyKey: "idem-dr-1"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.msg)
			if tc.wantValid && err != nil {
				t.Errorf("expected VALID, got error: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Errorf("expected INVALID, but validation passed")
			}
		})
	}
}

func freePricing() *rampv1.Pricing {
	return &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: 0}
}

func gen65() []string {
	s := make([]string, 65)
	for i := range s {
		s[i] = "tok"
	}
	return s
}

// TestErrorDetailConstraints exercises the unified error model: every per-domain
// detail's reason enum must be a defined, non-UNSPECIFIED value (defined_only +
// not_in:[0]), and the ErrorDetail wrapper validates the nested detail. This is
// the regression guard that errors are read as a typed proto reason — never an
// UNSPECIFIED placeholder or an out-of-range int — across every SDK language.
func TestErrorDetailConstraints(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	cases := []struct {
		name      string
		msg       proto.Message
		wantValid bool
	}{
		// TransactionDenial — reuses DenialReason, including the entitlement family.
		{"transaction_denial valid", &rampv1.TransactionDenial{Reason: rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE}, true},
		{"transaction_denial entitlement valid", &rampv1.TransactionDenial{Reason: rampv1.DenialReason_DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION}, true},
		{"transaction_denial unspecified rejected", &rampv1.TransactionDenial{Reason: rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED}, false},
		{"transaction_denial undefined int rejected", &rampv1.TransactionDenial{Reason: rampv1.DenialReason(9999)}, false},

		// One representative valid + zero-rejected case per remaining detail.
		{"catalog_rejection valid", &rampv1.CatalogRejection{Reason: rampv1.CatalogRejectionReason_CATALOG_REJECTION_REASON_TENANT_MISMATCH}, true},
		{"catalog_rejection unspecified rejected", &rampv1.CatalogRejection{Reason: rampv1.CatalogRejectionReason_CATALOG_REJECTION_REASON_UNSPECIFIED}, false},
		{"registration_failure valid", &rampv1.RegistrationFailure{Reason: rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_KEY}, true},
		{"registration_failure unspecified rejected", &rampv1.RegistrationFailure{Reason: rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_UNSPECIFIED}, false},
		{"dispute_failure valid", &rampv1.DisputeFailure{Reason: rampv1.DisputeFailureReason_DISPUTE_FAILURE_REASON_REPORT_NOT_FILED}, true},
		{"dispute_failure unspecified rejected", &rampv1.DisputeFailure{Reason: rampv1.DisputeFailureReason_DISPUTE_FAILURE_REASON_UNSPECIFIED}, false},
		{"domain_verification_failure valid", &rampv1.DomainVerificationFailure{Reason: rampv1.DomainVerificationFailureReason_DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_MISMATCH}, true},
		{"domain_verification_failure unspecified rejected", &rampv1.DomainVerificationFailure{Reason: rampv1.DomainVerificationFailureReason_DOMAIN_VERIFICATION_FAILURE_REASON_UNSPECIFIED}, false},
		{"retrieval_auth_failure valid", &rampv1.RetrievalAuthFailure{Reason: rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH}, true},
		{"retrieval_auth_failure unspecified rejected", &rampv1.RetrievalAuthFailure{Reason: rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_UNSPECIFIED}, false},
		{"usage_report_rejection valid", &rampv1.UsageReportRejection{Reason: rampv1.UsageReportRejectionReason_USAGE_REPORT_REJECTION_REASON_DUPLICATE}, true},
		{"usage_report_rejection unspecified rejected", &rampv1.UsageReportRejection{Reason: rampv1.UsageReportRejectionReason_USAGE_REPORT_REJECTION_REASON_UNSPECIFIED}, false},

		// ErrorDetail wrapper: carries a generic class (no typed reason) or a valid
		// typed detail; a nested invalid reason fails through the wrapper.
		{"error_detail generic class only ok", &rampv1.ErrorDetail{Message: "internal", Domain: "ramp.v1.ExchangeService"}, true},
		{"error_detail with valid detail ok", &rampv1.ErrorDetail{Reason: &rampv1.ErrorDetail_TransactionDenial{TransactionDenial: &rampv1.TransactionDenial{Reason: rampv1.DenialReason_DENIAL_REASON_RATE_LIMITED}}}, true},
		{"error_detail with unspecified nested reason rejected", &rampv1.ErrorDetail{Reason: &rampv1.ErrorDetail_TransactionDenial{TransactionDenial: &rampv1.TransactionDenial{Reason: rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED}}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.msg)
			if tc.wantValid && err != nil {
				t.Errorf("expected VALID, got error: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Errorf("expected INVALID, but validation passed")
			}
		})
	}
}
