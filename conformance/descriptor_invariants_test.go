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

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// thisFieldRe extracts `this.<field>` references from a CEL expression.
var thisFieldRe = regexp.MustCompile(`\bthis\.([a-z_]+)\b`)

// These guards walk EachMessage (contract.go) — every message of every contract
// package, map entries excluded. A new contract package is in scope the moment it is
// added to Contract; a new enum field / CEL is in scope the moment it exists.

// eachEnumField visits every enum-typed field of the contract.
func eachEnumField(fn func(protoreflect.MessageDescriptor, protoreflect.FieldDescriptor)) {
	EachMessage(func(md protoreflect.MessageDescriptor) {
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
	"DiscoveryResponse.absence_reason":             "output — set only when the broker yields no offers; absent on success",
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
	if fr := FieldRules(fd); fr != nil {
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
	EachMessage(func(md protoreflect.MessageDescriptor) {
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
			if fr := FieldRules(md.Fields().Get(j)); fr != nil {
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

// ─── INV-4: every bytes length rule is well formed ───────────────────────────
//
// A bytes length rule is ill formed when it sets len and min_len together, or
// when its value is zero. Both make "does this field carry a length rule" answer
// differently depending on whether the asker reads by presence or by value, and
// four consumers ask it: corpusgen (mutants), bytesgen (the bytes_len.json
// manifest), requiredgen (the required-fields manifest) and the class-6 corpus
// coverage guard. conformance.BytesLength rejects both shapes for all of them.
//
// This test exists so `go test ./conformance` is where a developer SEES the
// problem. Without it, ci-local.sh reaches corpusgen (line 66) before any test,
// and a bytes.len:0 used to surface there as "strings: negative Repeat count"
// from bytesOf(-1) — a message that names neither the field nor the rule.
// corpusgen now dies with the same field-naming text this test prints, and the
// test reports every offender instead of stopping at the first.
func TestBytesLengthRulesWellFormed(t *testing.T) {
	checked := 0
	EachRuleSet(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, prefix string, fr *validate.FieldRules) {
		if fr.GetBytes() == nil {
			return
		}
		checked++
		if _, err := BytesLength(fr); err != nil {
			t.Errorf("%s.%s (%sbytes) %v", md.Name(), fd.Name(), prefix, err)
		}
	})
	if checked == 0 {
		t.Fatal("no bytes rules found in the contract — this guard would be vacuous; " +
			"if the evidence rows really lost every bytes rule, delete the guard deliberately")
	}
}

// TestBytesLengthAccessor is the anti-vacuity control for INV-4 and for the
// shared accessor every consumer now reads: the walk above passes trivially if
// BytesLength stops returning errors. It also pins the two-level descent, which
// is what keeps a repeated.items rule from walking past a fail-closed guard.
func TestBytesLengthAccessor(t *testing.T) {
	lenRule := func(n uint64) *validate.FieldRules {
		return &validate.FieldRules{Type: &validate.FieldRules_Bytes{Bytes: &validate.BytesRules{Len: &n}}}
	}
	minLenRule := func(n uint64) *validate.FieldRules {
		return &validate.FieldRules{Type: &validate.FieldRules_Bytes{Bytes: &validate.BytesRules{MinLen: &n}}}
	}

	if r, err := BytesLength(lenRule(32)); err != nil || r == nil || r.Kind != "len" || r.Value != 32 {
		t.Errorf("BytesLength(bytes.len:32) = %+v, %v; want {len 32}, nil", r, err)
	}
	if r, err := BytesLength(minLenRule(1)); err != nil || r == nil || r.Kind != "min_len" || r.Value != 1 {
		t.Errorf("BytesLength(bytes.min_len:1) = %+v, %v; want {min_len 1}, nil", r, err)
	}
	if r, err := BytesLength(&validate.FieldRules{}); err != nil || r != nil {
		t.Errorf("BytesLength(no bytes rule) = %+v, %v; want nil, nil", r, err)
	}
	// The two ill-formed shapes MUST be errors, not a silent "no length rule" —
	// that reading is what let a zero-valued rule enter one consumer's view of the
	// contract and vanish from another's.
	if _, err := BytesLength(lenRule(0)); err == nil {
		t.Error("BytesLength(bytes.len:0) returned no error; an explicit zero length must be a contract error")
	}
	if _, err := BytesLength(minLenRule(0)); err == nil {
		t.Error("BytesLength(bytes.min_len:0) returned no error; an explicit zero floor must be a contract error")
	}
	both := lenRule(32)
	one := uint64(1)
	both.GetBytes().MinLen = &one
	if _, err := BytesLength(both); err == nil {
		t.Error("BytesLength(bytes.len:32 + bytes.min_len:1) returned no error; one of the two rules would be enforced and the other silently dropped")
	}

	// The generators call MustBytesLength, so its panic — not the error above —
	// is what a developer actually reads. It must name the offending field: the
	// message it replaced was "strings: negative Repeat count" from bytesOf(-1).
	fd := (&rampadminv1.TransactionState{}).ProtoReflect().Descriptor().Fields().ByName("signed_url_hash")
	if fd == nil {
		t.Fatal("TransactionState has no signed_url_hash field — pick another bytes field for this control")
	}
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("MustBytesLength did not panic on bytes.len:0 — a generator would read it as 'no length rule' and carry on")
				return
			}
			if msg, _ := r.(string); !strings.Contains(msg, string(fd.FullName())) {
				t.Errorf("MustBytesLength panicked with %q, which does not name the field %s", r, fd.FullName())
			}
		}()
		MustBytesLength(fd, lenRule(0))
	}()
}

// TestRuleSetsDescendIntoItems pins the descent the fail-closed guards depend on.
// The guards' predicates run per rule SET, so a top-level-only sweep leaves them
// open on every repeated field. A repeated.items.string.max_bytes rule — exactly
// the shape requiredgen's assertNoStringByteLengthRules forbids contract-wide —
// must be visible through RuleSets and invisible to a top-level-only read.
func TestRuleSetsDescendIntoItems(t *testing.T) {
	maxBytes := uint64(64)
	fr := &validate.FieldRules{Type: &validate.FieldRules_Repeated{Repeated: &validate.RepeatedRules{
		Items: &validate.FieldRules{Type: &validate.FieldRules_String_{String_: &validate.StringRules{MaxBytes: &maxBytes}}},
	}}}

	if _, _, ok := StringByteLength(fr); ok {
		t.Fatal("StringByteLength saw an item-level rule in the top-level rule set — the test's premise is wrong")
	}
	sets := RuleSets(fr)
	if len(sets) != 2 || sets[0].Prefix != "" || sets[1].Prefix != "repeated.items." {
		t.Fatalf("RuleSets returned %d sets with prefixes %q — want the field's own rules then repeated.items.", len(sets), prefixesOf(sets))
	}
	found := false
	for _, rs := range sets {
		if member, n, ok := StringByteLength(rs.Rules); ok {
			found = true
			if rs.Prefix != "repeated.items." || member != "max_bytes" || n != 64 {
				t.Errorf("StringByteLength found %s%s:%d; want repeated.items.max_bytes:64", rs.Prefix, member, n)
			}
		}
	}
	if !found {
		t.Error("a repeated.items.string.max_bytes rule was invisible to the sweep — every guard built on it is open on repeated fields")
	}

	// The contract really uses this shape, so the descent is not theoretical: the
	// real walk must reach item rules too, or the guards are wide on live fields.
	items := 0
	EachRuleSet(func(_ protoreflect.MessageDescriptor, _ protoreflect.FieldDescriptor, prefix string, _ *validate.FieldRules) {
		if prefix == "repeated.items." {
			items++
		}
	})
	if items == 0 {
		t.Error("EachRuleSet visited no repeated.items rule set, but the contract declares them " +
			"(ListRequest.filters and five ramp.v1 fields) — the descent regressed")
	}
}

func prefixesOf(sets []RuleSet) []string {
	out := make([]string, 0, len(sets))
	for _, rs := range sets {
		out = append(out, rs.Prefix)
	}
	return out
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

// TestRequesterBillingRefStaysRemoved pins the billing_ref removal at the
// descriptor level: Requester carries no caller-written billing_ref field.
// Billing identity is resolved from the verified request signature and the
// account minted at Register, never from a request field — a reappearing
// billing_ref would also collide by name with the authoritative account
// handle (RegisterResponse.billing_ref). The freed field number is NOT
// pinned: pre-v1, removed numbers return to the free pool (no `reserved`
// statements until v1.0.0 is tagged).
func TestRequesterBillingRefStaysRemoved(t *testing.T) {
	md := (&rampv1.Requester{}).ProtoReflect().Descriptor()
	if fd := md.Fields().ByName("billing_ref"); fd != nil {
		t.Errorf("Requester regained a billing_ref field (number %d) — billing keys on the verified caller identity, never a request field", fd.Number())
	}
}

// TestResourceMutabilityPresenceContract pins the presence semantics the typed
// ResourceEntry.resource_mutability field rests on. That field is proto3 `optional`
// (explicit presence), so an omitted value skips its not_in:[0] rule and is VALID —
// the common ingest case where a publisher does not declare the hint, which the
// Exchange then defaults to STATIC at Offer build. Drop the `optional` keyword and
// the field becomes a singular enum whose zero is present-and-rejected, silently
// flipping every omitting feed to rejected while `buf breaking` (the change is
// wire-compatible) and the language gates stay green. The Offer-side twin
// ResourceIdentity.resource_mutability is deliberately singular (no presence): it is
// required on every signed Offer, so its zero must always be rejected. Pin both halves.
func TestResourceMutabilityPresenceContract(t *testing.T) {
	entry := (&rampv1.ResourceEntry{}).ProtoReflect().Descriptor()
	if fd := entry.Fields().ByName("resource_mutability"); fd == nil {
		t.Fatal("ResourceEntry has no resource_mutability field")
	} else if !fd.HasPresence() {
		t.Error("ResourceEntry.resource_mutability lost explicit presence — restore the `optional` keyword; " +
			"without it an omitted hint is a present zero and not_in:[0] rejects every feed that omits the field")
	}
	identity := (&rampv1.ResourceIdentity{}).ProtoReflect().Descriptor()
	if fd := identity.Fields().ByName("resource_mutability"); fd == nil {
		t.Fatal("ResourceIdentity has no resource_mutability field")
	} else if fd.HasPresence() {
		t.Error("ResourceIdentity.resource_mutability gained explicit presence — it must stay singular; " +
			"it is required on every signed Offer, so its zero must always be rejected")
	}
}
