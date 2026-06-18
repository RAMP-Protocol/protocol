// Package conformance holds machine checks that the doc-conformance denylist
// gate structurally cannot perform: it actually *evaluates* the protovalidate
// CEL constraints embedded in the proto, and validates the example payloads in
// the docs against the wire contract. A green run here means the constraints
// fire as written and the documented examples would survive ingestion.
package conformance

import (
	"os"
	"regexp"
	"strings"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

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
		// window set so the only variable under test is metric.
		{"quota metric bare ok", &rampv1.Quota{Metric: "display-words", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}, true},
		{"quota metric vendor ok", &rampv1.Quota{Metric: "acme:frames", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}, true},
		{"quota metric empty rejected", &rampv1.Quota{Metric: "", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}, false},
		{"quota metric space rejected", &rampv1.Quota{Metric: "two words", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}, false},

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
		{"quota limit ok", &rampv1.Quota{Metric: "accesses", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}, true},
		{"quota limit zero rejected", &rampv1.Quota{Metric: "accesses", Limit: 0, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}, false},
		{"obligation share_alike with spdx id ok", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, ScopeLicense: &rampv1.License{Id: proto.String("CC-BY-SA-4.0")}}, true},
		{"obligation share_alike without scope_license rejected", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}, false},
		{"obligation share_alike scope_license uri+digest ok", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, ScopeLicense: &rampv1.License{Uri: proto.String("https://creativecommons.org/licenses/by-sa/4.0/"), UriDigest: proto.String("sha256:" + hex64)}}, true},
		{"obligation share_alike scope_license uri without digest rejected", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, ScopeLicense: &rampv1.License{Uri: proto.String("https://creativecommons.org/licenses/by-sa/4.0/")}}, false},

		// Required-enum discriminators — UNSPECIFIED (zero) is never a valid value.
		// These guard the gap where the conditional coherence CELs above are
		// vacuously satisfied by an unset discriminator.
		{"term semantics unspecified rejected", &rampv1.LicenseTerm{Pricing: freePricing()}, false},
		{"pricing model unspecified rejected", &rampv1.Pricing{Rate: 0}, false},
		{"restriction kind unspecified rejected", &rampv1.Restriction{Permitted: []string{"ai-input"}}, false},
		{"obligation kind unspecified rejected", &rampv1.Obligation{Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}, false},
		{"quota window unspecified rejected", &rampv1.Quota{Metric: "accesses", Limit: 1}, false},
		{"obligation trigger unspecified rejected", &rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION}, false},
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

// zeroValueAllowed lists the (Message.field) enum discriminators that MAY carry
// their zero value despite their enum being marked "rejected at ingest". Each
// entry needs a documented reason. This is the ONLY sanctioned escape from
// TestRequiredEnumDiscriminatorsRejectZero — adding a field here is a deliberate
// decision, not an oversight.
var zeroValueAllowed = map[string]string{
	// Advisory request input: an AcceptableRestriction with an unset axis is a
	// "no preference" filter, not a malformed term — the term-side
	// Restriction.kind is the enforced one.
	"AcceptableRestriction.axis": "advisory request-side filter, not a wire-enforced term field",
	// Diagnostic OUTPUT, not enforced term discriminators — the Exchange emits
	// these to explain a result; they are not consumed as trust-boundary input.
	// (Surfaced by this guard, Jun 2026 — both the R6 and R7 hand-reviews missed
	// them; the same category as AcceptableRestriction.axis above.)
	"OfferGroup.restriction_filters":               "advisory diagnostic — which axes pre-filtered the group; not an enforced discriminator",
	"TransactionResponse.restriction_mismatches":   "diagnostic output — axes a denied request failed; Exchange-produced, not input",
	"TransactionResultItem.restriction_mismatches": "diagnostic output — axes a denied request failed; Exchange-produced, not input",
	"WellKnownManifest.pricing_models_supported":   "capability advertisement in the manifest, not a per-term enforced discriminator",
}

// TestRequiredEnumDiscriminatorsRejectZero is the process guard for the
// recurring "added the !=UNSPECIFIED rule to N discriminators, missed the N+1th"
// class (R6-3 missed 4, the R7 re-review still missed Quota.window /
// Obligation.trigger — twice hand-enumerated, twice incomplete).
//
// Instead of trusting a human to find every instance, it DERIVES the contract:
// the proto marks each "must be set" enum by commenting its zero value
// `// unset — rejected at ingest`. This test reads that marker straight from the
// proto, then walks the descriptors and asserts every field of such an enum is
// either covered by a zero-rejection rule (a message/field CEL referencing the
// field + UNSPECIFIED, or enum not_in:[0]) or explicitly allow-listed above. A
// newly added discriminator with the contract comment fails here until it gets
// the rule — the enumeration can no longer drift.
func TestRequiredEnumDiscriminatorsRejectZero(t *testing.T) {
	rejectZeroEnums := enumsMarkedRejectedAtIngest(t)
	if len(rejectZeroEnums) == 0 {
		t.Fatal("found no enums marked '// unset — rejected at ingest' — marker or path drifted?")
	}

	thisField := regexp.MustCompile(`\bthis\.([a-z_]+)\b`)
	usedAllow := map[string]bool{}

	var walk func(protoreflect.MessageDescriptors)
	walk = func(msgs protoreflect.MessageDescriptors) {
		for i := 0; i < msgs.Len(); i++ {
			md := msgs.Get(i)
			walk(md.Messages()) // nested messages
			for j := 0; j < md.Fields().Len(); j++ {
				fd := md.Fields().Get(j)
				if fd.Kind() != protoreflect.EnumKind {
					continue
				}
				if !rejectZeroEnums[string(fd.Enum().Name())] {
					continue
				}
				key := string(md.Name()) + "." + string(fd.Name())
				if _, ok := zeroValueAllowed[key]; ok {
					usedAllow[key] = true
					continue
				}
				if !fieldRejectsZero(md, fd, thisField) {
					t.Errorf("%s (%s) is a required discriminator (its enum zero value is marked 'rejected at ingest') "+
						"but nothing rejects the zero value on the wire. Add a message CEL "+
						"`this.%s != ...%s_UNSPECIFIED` (or allow-list it in zeroValueAllowed with a reason).",
						key, fd.Enum().Name(), fd.Name(), strings.ToUpper(camelToSnake(string(fd.Enum().Name()))))
				}
			}
		}
	}
	walk(rampv1.File_ramp_v1_ramp_proto.Messages())

	for key := range zeroValueAllowed {
		if !usedAllow[key] {
			t.Errorf("zeroValueAllowed[%q] is stale: no such reject-zero enum field exists — remove it.", key)
		}
	}
}

// fieldRejectsZero reports whether some protovalidate rule rejects fd's zero
// value: a field-level enum not_in:[0], a field-level CEL mentioning UNSPECIFIED,
// or a message-level CEL referencing `this.<field>` together with UNSPECIFIED.
func fieldRejectsZero(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, thisField *regexp.Regexp) bool {
	if fr, err := protovalidate.ResolveFieldRules(fd); err == nil && fr != nil {
		if er := fr.GetEnum(); er != nil {
			for _, v := range er.GetNotIn() {
				if v == 0 {
					return true
				}
			}
		}
		for _, r := range fr.GetCel() {
			if strings.Contains(r.GetExpression(), "UNSPECIFIED") {
				return true
			}
		}
	}
	mr, err := protovalidate.ResolveMessageRules(md)
	if err != nil || mr == nil {
		return false
	}
	exprs := mr.GetCelExpression()
	for _, r := range mr.GetCel() {
		exprs = append(exprs, r.GetExpression())
	}
	for _, e := range exprs {
		if !strings.Contains(e, "UNSPECIFIED") {
			continue
		}
		for _, m := range thisField.FindAllStringSubmatch(e, -1) {
			if m[1] == string(fd.Name()) {
				return true
			}
		}
	}
	return false
}

// enumsMarkedRejectedAtIngest reads the proto source and returns the set of enum
// type names whose zero value is annotated `rejected at ingest`.
func enumsMarkedRejectedAtIngest(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("../proto/ramp/v1/ramp.proto")
	if err != nil {
		t.Fatalf("read proto source: %v", err)
	}
	enumLine := regexp.MustCompile(`^\s*enum\s+(\w+)\s*\{`)
	out := map[string]bool{}
	var current string
	for _, line := range strings.Split(string(src), "\n") {
		if m := enumLine.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if strings.Contains(line, "}") && !strings.Contains(line, "=") {
			current = ""
		}
		if current != "" && strings.Contains(line, "= 0") && strings.Contains(line, "rejected at ingest") {
			out[current] = true
		}
	}
	return out
}

// camelToSnake turns "QuotaWindow" into "Quota_Window" so the error hint can
// build the QUOTA_WINDOW_UNSPECIFIED constant name. Best-effort (hint only).
func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return b.String()
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
