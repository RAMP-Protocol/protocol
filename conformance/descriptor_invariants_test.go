// Package conformance — descriptor_invariants_test.go holds the STRUCTURAL
// guards that derive their scope from the proto descriptor itself, never from a
// hand-maintained list, a comment marker, or a denylist.
//
// Every recurring drift in this repo traced back to a guard whose scope was
// opt-in: a human had to remember to mark each new instance (a `// rejected at
// ingest` comment, a denylist entry, a hand-typed table), so the guard was
// complete the day it was written and silently incomplete the day a sibling was
// added without the mark. These guards are opt-OUT: every instance is in scope
// by walking the descriptor, and the only hand-maintained surface is an explicit
// exemption list that the test proves is both necessary and used on every run.
// A new enum field / CEL / token format is covered the moment it exists.
package conformance

import (
	"regexp"
	"strings"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// thisFieldRe extracts `this.<field>` references from a CEL expression.
var thisFieldRe = regexp.MustCompile(`\bthis\.([a-z_]+)\b`)

// eachMessage visits every message in the file, including nested messages.
func eachMessage(fn func(protoreflect.MessageDescriptor)) {
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			md := ms.Get(i)
			fn(md)
			walk(md.Messages())
		}
	}
	walk(rampv1.File_ramp_v1_ramp_proto.Messages())
}

// eachEnumField visits every enum-typed field in the file.
func eachEnumField(fn func(protoreflect.MessageDescriptor, protoreflect.FieldDescriptor)) {
	eachMessage(func(md protoreflect.MessageDescriptor) {
		for j := 0; j < md.Fields().Len(); j++ {
			fd := md.Fields().Get(j)
			if fd.Kind() == protoreflect.EnumKind {
				fn(md, fd)
			}
		}
	})
}

// enumZeroIsUnspecified reports whether ed's zero value is the *_UNSPECIFIED
// sentinel — the structural property meaning "zero is unset", as opposed to an
// enum whose zero is a real default (PRICING_METERING_ONLINE, CITATION_FORMAT_LINK).
func enumZeroIsUnspecified(ed protoreflect.EnumDescriptor) bool {
	v := ed.Values().Get(0)
	return v.Number() == 0 && strings.HasSuffix(string(v.Name()), "_UNSPECIFIED")
}

// ─── INV-1: required discriminators reject the zero value ────────────────────
//
// zeroAllowed lists the (Message.field) discriminators that MAY legitimately
// carry their *_UNSPECIFIED zero. Each entry states why. The test proves every
// entry is BOTH still-present (a field by that name with an UNSPECIFIED-zero
// enum exists) AND still-needed (that field does not already reject zero on its
// own) — so the list is self-cleaning in both directions and cannot mask a
// field that has since been enforced elsewhere.
var zeroAllowed = map[string]string{
	// ── Advisory request-side filters: an unset axis is "no preference", not a
	// malformed term. The enforced discriminator is the term-side Restriction.kind.
	"AcceptableRestriction.axis":     "advisory request-side filter; unset = any axis",
	"OfferGroup.restriction_filters": "advisory diagnostic — which axes pre-filtered the group",

	// ── Server-produced OUTPUT, set only when its condition holds; a zero means
	// "not applicable", never an unvalidated input crossing a trust boundary.
	"OfferGroup.absence_reason":                    "output — set only when a group yields no offers",
	"OfferGroup.discovery_method":                  "output — informational; how the group was discovered",
	"RAMPResponse.absence_reason":                  "output — set only when the broker yields no licensable result; absent on success",
	"RAMPResponse.delivery_method":                 "output — populated on a licensed result",
	"TransactionResponse.delivery_method":          "output — populated on a completed transaction",
	"TransactionResultItem.delivery_method":        "output — per-item delivery on a completed batch item",
	"TransactionResultItem.denial_reason":          "output — set only on a denied batch item",
	"TransactionResultItem.restriction_mismatches": "output — axes a denied batch item failed",
	"TransactionDenial.restriction_mismatches":     "output — axes a denied request failed; carried on the typed error detail",
	"DisputeResponse.resolution":                   "output — unset while a dispute is unresolved",
	"DisputeResponse.status":                       "output — dispute lifecycle status, not an ingest-time input",

	// ── Optional input preference / metadata: unset is itself a valid choice.
	"RequestConstraints.delivery_preference": "optional agent preference; unset = no preference",
	"Offer.delivery_method":                  "offer-side hint; unset = negotiated at delivery",
	"ResourceEntry.source":                   "optional ingestion provenance; unset = unspecified source",
	"ResourceIdentity.c2pa_status":           "optional provenance; UNSPECIFIED is distinct from ABSENT (not evaluated)",

	// ── Capability advertisements on the manifest: a list of supported values,
	// not a per-instance discriminator.
	"WellKnownManifest.pricing_models_supported":   "capability advertisement, not a per-term discriminator",
	"WellKnownManifest.delivery_methods_supported": "capability advertisement",
	"WellKnownManifest.supported_auth_methods":     "capability advertisement",

}

// TestRequiredEnumDiscriminatorsRejectZero is the process guard for the
// recurring "added the !=UNSPECIFIED rule to N discriminators, missed the N+1th"
// class. It does NOT trust a human to enumerate the discriminators: it walks the
// descriptor and treats EVERY field whose enum's zero is the *_UNSPECIFIED
// sentinel as in scope. Each such field must either reject zero on the wire or
// appear in zeroAllowed with a reason. The set cannot drift, because it is the
// descriptor.
func TestRequiredEnumDiscriminatorsRejectZero(t *testing.T) {
	usedAllow := map[string]bool{}
	eachEnumField(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor) {
		if !enumZeroIsUnspecified(fd.Enum()) {
			return
		}
		key := string(md.Name()) + "." + string(fd.Name())
		rejects := fieldRejectsZero(md, fd)
		if reason, ok := zeroAllowed[key]; ok {
			usedAllow[key] = true
			if strings.TrimSpace(reason) == "" {
				t.Errorf("zeroAllowed[%q] has an empty reason; every exemption must say why.", key)
			}
			// Self-cleaning: if an allow-listed field has since gained a
			// zero-rejection rule, the exemption is stale and must be removed —
			// otherwise the allowlist could mask a real future regression.
			if rejects {
				t.Errorf("%s is in zeroAllowed but now rejects its zero on its own — remove the (now stale) exemption.", key)
			}
			return
		}
		if !rejects {
			zero := fd.Enum().Values().Get(0).Name()
			t.Errorf("%s is a required discriminator (enum zero %s is the UNSPECIFIED sentinel) but nothing rejects the zero value on the wire.\n"+
				"  Add a message CEL `this.%s != ramp.v1.%s.%s` with id %q, or allow-list it in zeroAllowed with a reason.",
				key, zero, fd.Name(), fd.Enum().Name(), zero,
				messageSnake(string(md.Name()))+"."+string(fd.Name())+"_specified")
		}
	})
	for key := range zeroAllowed {
		if !usedAllow[key] {
			t.Errorf("zeroAllowed[%q] is stale: no enum field by that name has an UNSPECIFIED-zero enum — remove or fix it.", key)
		}
	}
}

// fieldRejectsZero reports whether some protovalidate rule rejects fd's zero
// value: a field-level enum not_in:[0], a field-level CEL mentioning UNSPECIFIED,
// or a message-level CEL referencing `this.<field>` together with UNSPECIFIED.
func fieldRejectsZero(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor) bool {
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
		for _, m := range thisFieldRe.FindAllStringSubmatch(e, -1) {
			if m[1] == string(fd.Name()) {
				return true
			}
		}
	}
	return false
}

// ─── INV-2: a CEL id's first segment names its owning message ────────────────
//
// Every CEL id in the proto has the form "<message_snake>.<rest>". This is the
// grep-the-id-find-the-message convention; one violator (a CEL id naming a
// different message than the one it lives in) is how a constraint silently
// attaches to the wrong message in a reader's mental model.
func TestCELIDPrefixMatchesMessage(t *testing.T) {
	checked := 0
	eachMessage(func(md protoreflect.MessageDescriptor) {
		want := messageSnake(string(md.Name()))
		check := func(id string) {
			if id == "" || !strings.Contains(id, ".") {
				return
			}
			checked++
			prefix := id[:strings.Index(id, ".")]
			if prefix != want {
				t.Errorf("CEL id %q is declared in message %s, but its prefix %q != %q (snake_case of the owning message). "+
					"Every CEL id's first segment names its owning message.", id, md.Name(), prefix, want)
			}
		}
		if mr, err := protovalidate.ResolveMessageRules(md); err == nil && mr != nil {
			for _, r := range mr.GetCel() {
				check(r.GetId())
			}
		}
		for j := 0; j < md.Fields().Len(); j++ {
			fd := md.Fields().Get(j)
			if fr, err := protovalidate.ResolveFieldRules(fd); err == nil && fr != nil {
				for _, r := range fr.GetCel() {
					check(r.GetId())
				}
			}
		}
	})
	if checked == 0 {
		t.Fatal("no CEL ids found — the resolver path drifted; INV-2 would be vacuous.")
	}
}

// messageSnake turns a PascalCase message name into snake_case:
// "Usage" → "usage", "UsageReport" → "usage_report",
// "AcceptableRestriction" → "acceptable_restriction".
func messageSnake(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			r = r - 'A' + 'a'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ─── INV-3 removed ───────────────────────────────────────────────────────────
//
// The namespaced-token format is now expressed as STANDARD protovalidate
// string.pattern / repeated.items.string.pattern constraints on the fields
// (Pricing.unit, Quota.metric, Usage.consumed_unit, Restriction.permitted/
// prohibited, AcceptableRestriction.values), not custom CEL. There is no
// token-format CEL left to keep canonical, so the old INV-3 (which asserted the
// CEL regex fragments were identical across copies) is obsolete. The standard
// patterns survive into the generated JSON Schema / Pydantic / Zod — which was
// the point of the conversion.

// ─── Positive controls ───────────────────────────────────────────────────────
//
// The descriptor-walking tests above can pass VACUOUSLY if a predicate silently
// regresses (e.g. fieldRejectsZero returns true for everything). These unit
// tests pin the predicates against known inputs — including known-negatives — so
// a dead checker fails here regardless of what the walks report. This is the
// fix for "the guard exists but no longer bites".
func TestInvariantHelpers(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Usage", "usage"},
		{"UsageReport", "usage_report"},
		{"LicenseTerm", "license_term"},
		{"AcceptableRestriction", "acceptable_restriction"},
		{"License", "license"},
	} {
		if got := messageSnake(c.in); got != c.want {
			t.Errorf("messageSnake(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	disputeReason := fieldEnum(t, (&rampv1.DisputeRequest{}).ProtoReflect().Descriptor(), "reason")
	if !enumZeroIsUnspecified(disputeReason) {
		t.Error("enumZeroIsUnspecified(DisputeReason) = false, want true")
	}
	pricingMetering := fieldEnum(t, (&rampv1.Pricing{}).ProtoReflect().Descriptor(), "metering")
	if enumZeroIsUnspecified(pricingMetering) {
		t.Error("enumZeroIsUnspecified(PricingMetering) = true, want false (zero is ONLINE, a real value)")
	}

	// THE anti-vacuity control: fieldRejectsZero MUST return false for the
	// allow-listed AcceptableRestriction.axis (it is genuinely unenforced). If
	// this ever returns true, TestRequiredEnumDiscriminatorsRejectZero is passing
	// for the wrong reason.
	ar := (&rampv1.AcceptableRestriction{}).ProtoReflect().Descriptor()
	if fieldRejectsZero(ar, ar.Fields().ByName("axis")) {
		t.Error("fieldRejectsZero(AcceptableRestriction.axis) = true, want false (anti-vacuity control: it is genuinely unenforced)")
	}
	// And it MUST return true for both enforcement shapes.
	cr := (&rampv1.CatalogRejection{}).ProtoReflect().Descriptor()
	if !fieldRejectsZero(cr, cr.Fields().ByName("reason")) {
		t.Error("fieldRejectsZero(CatalogRejection.reason) = false, want true (field-level not_in:[0])")
	}
	pr := (&rampv1.Pricing{}).ProtoReflect().Descriptor()
	if !fieldRejectsZero(pr, pr.Fields().ByName("model")) {
		t.Error("fieldRejectsZero(Pricing.model) = false, want true (field-level enum not_in:[0])")
	}
}

func fieldEnum(t *testing.T, md protoreflect.MessageDescriptor, field string) protoreflect.EnumDescriptor {
	t.Helper()
	fd := md.Fields().ByName(protoreflect.Name(field))
	if fd == nil {
		t.Fatalf("%s has no field %q", md.Name(), field)
	}
	return fd.Enum()
}
