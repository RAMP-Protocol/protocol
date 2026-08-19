// Command corpusgen emits the cross-language validation corpus: for every
// message field that carries a protovalidate field rule, a valid baseline plus
// boundary-violating mutants (one per constraint), each rendered as proto-JSON
// with Go protovalidate's verdict recorded as the oracle.
//
// The corpus is the single, generated source the Python (Pydantic) and TS (Zod)
// parity tests consume — no rule is restated by hand. Go protovalidate is the
// requirement's only executable form, so its verdict defines each case. Scope is
// FIELD-level rules only: cross-field message CEL is server-authoritative and not
// represented here (a field mutant may incidentally also trip a message CEL — that
// is fine; the field-level violation is what the clients are expected to catch).
//
// Determinism: cases are emitted in a stable order so the committed corpus is a
// byte-exact, drift-gated artifact (regenerate: go run ./conformance/corpusgen).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/RAMP-Protocol/protocol/conformance"
	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Fixed well-known-type values so the canonical proto-JSON round-trip test
// (TestCanonicalRoundTrip) actually exercises Timestamp (RFC 3339) and Duration
// encodings — the proto-JSON forms most likely to diverge across languages. Fixed,
// not time.Now(), so the corpus stays deterministic for the drift gate.
var (
	fixedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedDur  = 90 * time.Second
)

// Case is one corpus entry. Valid==true is a baseline; Valid==false is a mutant
// whose Rules are the protovalidate rule ids Go reported (the oracle verdict).
type Case struct {
	ID      string          `json:"id"`
	Message string          `json:"message"` // short proto message name (== generated class/schema name)
	Valid   bool            `json:"valid"`
	Rules   []string        `json:"rules,omitempty"`
	JSON    json.RawMessage `json:"json"`
}

// seeds are valid baseline instances for messages whose cross-field CEL (or
// required sub-message) auto-fill cannot satisfy. A seed is a valid EXAMPLE, not
// a restatement of any rule. Auto-fill handles everything else; a message that
// auto-fill cannot make valid AND has no seed fails the run loudly.
func seeds() map[string]proto.Message {
	pricing := func() *rampv1.Pricing {
		return &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}
	}
	// Exchange is presence-enforced on Offer (it is the execute-routing target
	// and the audience statement of a TransactionRequest), so a seed without it
	// is not a valid baseline — seeds bypass auto-fill entirely.
	offer := func() *rampv1.Offer {
		return &rampv1.Offer{OfferId: "offer-seed", Exchange: "exchange.example", Pricing: pricing()}
	}
	return map[string]proto.Message{
		"Pricing":     pricing(),
		"License":     &rampv1.License{Id: proto.String("CC-BY-4.0")},
		"Restriction": &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}},
		"Obligation": &rampv1.Obligation{
			Kind:    rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION,
			Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE,
		},
		"Quota":                 &rampv1.Quota{Metric: "accesses", Limit: 1, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY},
		"LicenseTerm":           &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: pricing()},
		"AcceptableRestriction": &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai-train"}},
		"DisputeRequest":        &rampv1.DisputeRequest{IdempotencyKey: "idem-dr", Exchange: "exchange.example", Reason: rampv1.DisputeReason_DISPUTE_REASON_CONTENT_MISMATCH},
		// Reflected-Offer execute contract (items-only): Offer is
		// the required sub-message of TransactionItem (auto-fill needs its seed),
		// and TransactionRequest needs a valid 1-item items[] baseline because its
		// items field is now repeated.min_items=1 (single-offer mode removed).
		"Offer":              offer(),
		"TransactionRequest": &rampv1.TransactionRequest{IdempotencyKey: "idem-tx", Items: []*rampv1.TransactionItem{{Offer: offer()}}},
		// ramp.admin.v1 payloads embedded (required) in the setter request/response
		// envelopes. RequiredFields MUST be exactly ["x"]: the repeated.unique
		// duplicate_item edge appends the auto-filled good item (stringSamples[0]=="x")
		// and relies on the baseline already holding it, so the mutant is ["x","x"].
		// The refusal that carries per-member detail. Auto-fill would pick the
		// FIRST allowed reason (DOMAIN_NOT_VERIFIED) and still populate
		// field_errors, publishing as VALID the pairing the field comment rules
		// out — and the branch's own reason would reach no corpus case, so a
		// client that dropped it would stay green. The empty path is the
		// whole-object failure (oneOf, minProperties) that belongs to no single
		// member; seeding it pins that accept boundary in all three languages.
		"RegistrationFailure": &rampv1.RegistrationFailure{
			Reason: rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
			FieldErrors: []*rampv1.RegistrationFieldError{
				{Path: "", Error: "matched 2 branches of oneOf, exactly 1 required"},
			},
		},
		// terms_digest pins the document at terms_uri, so the two are joined by a
		// message CEL rule. Auto-fill populates terms_digest (it carries a pattern)
		// but never terms_uri (no field rule to trigger on), which is precisely the
		// shape a seed exists for. Seeding BOTH also keeps the terms_digest pattern
		// mutants honest: they trip the pattern alone rather than the pattern and
		// the cross-field rule together.
		"WellKnownManifest": &rampv1.WellKnownManifest{
			Ver:         "1.0",
			Role:        rampv1.Role_ROLE_EXCHANGE,
			Domain:      "exchange.example",
			TermsUri:    proto.String("https://exchange.example/terms"),
			TermsDigest: proto.String("sha256:" + strings.Repeat("ab", 32)),
			// Auto-fill never populates a nested message, so without this seed the
			// only identity_documents coverage would be standalone IdentityDocuments
			// cases — the block validating in isolation, never inside a manifest.
			// Seeding it puts the block through canonical_test.go's proto-JSON
			// round-trip on WellKnownManifest/valid.
			IdentityDocuments: &rampv1.IdentityDocuments{
				WbaDirectory:       proto.String("/.well-known/http-message-signatures-directory"),
				SignatureAgentCard: proto.String("/.well-known/signature-agent-card.json"),
			},
		},
		"TenantFeeRate":   &rampadminv1.TenantFeeRate{TenantId: "tenant-seed", FeeRateBps: 0},
		"ReportingPolicy": &rampadminv1.ReportingPolicy{TenantId: "tenant-seed", RequiredFields: []string{"x"}},
	}
}

// stringSamples are candidate valid strings; the first that matches a field's
// pattern and length bounds becomes the auto-filled value (generic — no per-field
// table). badStrings are candidates that should FAIL a typical token/number/hash
// pattern; the first that the pattern rejects becomes the violating value.
//
// APPEND-ONLY, for a different reason than badStrings: validString returns the
// FIRST entry that matches, so appending cannot change what any existing field
// auto-fills to, and the corpus diff stays additive. Inserting anywhere else can
// silently re-value every field a new earlier entry happens to satisfy.
var stringSamples = []string{"x", "ai-train", "tokens", "accesses", "0", "sha256:" + strings.Repeat("ab", 32), ""}

// APPEND-ONLY: a badStrings entry's INDEX is baked into the emitted case IDs (see
// stringEdges' pattern#<idx> mutants), so appending keeps existing case IDs stable and
// the byte drift-gate diff purely additive. The trailing four are money-specific
// killers — numbers a naive Decimal would accept (negative / NaN / Infinity / exponent)
// but the decimal-string money pattern rejects; they are the money-value blind spot.
var badStrings = []string{"two words", "1.2.3", "!!bad!!", "\x00ctl\x00", " ", "-5", "NaN", "Infinity", "1E3"}

// patternKillers are bad values chosen FOR A SPECIFIC pattern, keyed by the
// pattern string itself. badStrings is shared with every pattern-ruled field in
// the contract, so widening it to cover one family's shapes would add a mutant
// to money, quota and token fields that has nothing to do with them. This table
// is the narrow alternative: the values only reach the fields whose rule is that
// exact pattern.
//
// APPEND-ONLY per entry, like badStrings: the index is baked into the emitted
// case id (killer#<idx>).
//
// The domain family's entries are the shapes the constraint exists to refuse.
// Scheme and path are the load-bearing pair — a domain value is concatenated
// into a URL a resolver fetches, so smuggling either one in chooses WHAT is
// fetched, not merely from where.
var patternKillers = map[string][]string{
	bareDomainPattern: {
		"https://exchange.example",  // scheme prefix
		"exchange.example/register", // path suffix
		"exchange.example?x=1",      // query suffix
		"user@exchange.example",     // userinfo
		"exchange.example:123456",   // port out of range
		"exchange.example:",         // empty port
		"exchange.example.",         // trailing root dot
		"exchange..example",         // empty label
		"-exchange.example",         // leading hyphen
		"[::1]:443",                 // bracketed IPv6 literal
		"exchange.example:0",        // port 0 names no listening service
		"exchange.example:99999",    // port above 65535
	},
}

// bareDomainPattern is the recipient-host shape, quoted from the proto so the
// killer table above can be keyed by it. A drift between this copy and the
// fields is caught by conformance's own descriptor guard, not here.
const bareDomainPattern = `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$`

func main() {
	v, err := protovalidate.New()
	must(err)
	sd := seeds()

	// The corpus keys messages by bare short name (Case.Message == the generated
	// class/schema name), so bare names MUST stay unique across the contract packages.
	if err := conformance.AssertUniqueBareNames(); err != nil {
		die("%v", err)
	}

	var cases []Case
	conformance.EachMessage(func(md protoreflect.MessageDescriptor) {
		var constrained []protoreflect.FieldDescriptor
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if fr := rules(fd); fr != nil && hasConstraint(fr) {
				constrained = append(constrained, fd)
			}
		}
		if len(constrained) == 0 {
			return
		}
		short := string(md.Name())
		base, err := baseline(md, sd)
		if err != nil {
			die("baseline %s: %v", short, err)
		}
		if verr := v.Validate(base.Interface()); verr != nil {
			die("baseline %s is not valid (add/fix a seed): %v", short, verr)
		}
		cases = append(cases, mkCase(short+"/valid", short, base.Interface(), true, nil, v))

		for _, fd := range constrained {
			for _, e := range edges(fd, rules(fd), sd) {
				m := proto.Clone(base.Interface()).ProtoReflect()
				e.apply(m)
				verr := v.Validate(m.Interface())
				ids := ruleIDs(verr)
				id := fmt.Sprintf("%s/%s/%s", short, fd.Name(), e.label)
				if e.valid {
					// Positive edge: Go must accept it. Proves the ACCEPT boundary
					// (e.g. money "") the negative-only mutants never exercise.
					if verr != nil {
						die("positive edge %s expected valid, got %v", id, ids)
					}
					cases = append(cases, mkCase(id, short, m.Interface(), true, nil, v))
					continue
				}
				if verr == nil {
					die("mutant %s.%s/%s did not violate any rule — edge is wrong", short, fd.Name(), e.label)
				}
				if !contains(ids, e.want) {
					die("mutant %s.%s/%s expected rule %q, got %v", short, fd.Name(), e.label, e.want, ids)
				}
				cases = append(cases, mkCase(id, short, m.Interface(), false, ids, v))
			}
		}
	})

	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	out, err := json.MarshalIndent(cases, "", "  ")
	must(err)
	must(os.WriteFile("conformance/corpus/cases.json", append(out, '\n'), 0o644))
	fmt.Printf("wrote %d cases -> conformance/corpus/cases.json\n", len(cases))

	writeCrossField(v)
}

// writeCrossField emits conformance/corpus/crossfield.json: one invalid mutant
// per message-level (cross-field) CEL rule, each pinned to Go protovalidate's
// verdict. This is kept SEPARATE from cases.json on purpose — cases.json is the
// FIELD-level corpus the generated Pydantic/Zod clients are tested against today,
// and those clients do not yet enforce cross-field CEL (the symmetric gap noted
// in ramp-sdk-api.md). The SDK L1 validator (helpers.Validate) is tested
// against THIS file, and a future TS/Python L1 that authors the cross-field rules
// by hand consumes it as their oracle — without breaking the field-level parity.
func writeCrossField(v protovalidate.Validator) {
	type mutant struct {
		id   string
		msg  proto.Message
		want string // the message CEL rule id this mutant must trip
	}
	freePricing := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}
	mutants := []mutant{
		{
			"Pricing/cel/per_unit_requires_unit",
			&rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD"},
			"pricing.per_unit.requires_unit",
		},
		{
			"Pricing/cel/free_zero_rate",
			&rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "5"},
			"pricing.free.zero_rate",
		},
		{
			"License/cel/digest_required_with_uri",
			&rampv1.License{Id: proto.String("CC-BY-4.0"), Uri: proto.String("https://example.com/license")},
			"license.digest_required_with_uri",
		},
		{
			// field_errors is scoped to the schema refusal; any other reason
			// carrying it publishes member detail that does not apply.
			"RegistrationFailure/cel/field_errors_scoped_to_invalid_data",
			&rampv1.RegistrationFailure{
				Reason:      rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE,
				FieldErrors: []*rampv1.RegistrationFieldError{{Path: "/vat_id", Error: "required"}},
			},
			"registration_failure.field_errors_scoped_to_invalid_data",
		},
		{
			// The manifest mirror of the rule above: a digest with no document
			// address cannot be checked against anything.
			"WellKnownManifest/cel/terms_digest_requires_terms_uri",
			&rampv1.WellKnownManifest{
				Ver:         "1.0",
				Role:        rampv1.Role_ROLE_EXCHANGE,
				Domain:      "exchange.example",
				TermsDigest: proto.String("sha256:" + strings.Repeat("ab", 32)),
			},
			"well_known_manifest.terms_digest_requires_terms_uri",
		},
		{
			"Restriction/cel/permitted_prohibited_disjoint",
			&rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}, Prohibited: []string{"ai-train"}},
			"restriction.permitted_prohibited_disjoint",
		},
		{
			"Obligation/cel/share_alike_requires_scope_license",
			&rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE},
			"obligation.share_alike.requires_scope_license",
		},
		{
			"LicenseTerm/cel/reference_only_requires_uri",
			&rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY},
			"license_term.reference_only.requires_uri",
		},
		{
			"LicenseTerm/cel/one_restriction_per_kind",
			&rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   freePricing,
				Restrictions: []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}},
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}},
				},
			},
			"license_term.one_restriction_per_kind",
		},
	}

	var cases []Case
	for _, mt := range mutants {
		verr := v.Validate(mt.msg)
		if verr == nil {
			die("cross-field mutant %s did not violate any rule", mt.id)
		}
		ids := ruleIDs(verr)
		if !contains(ids, mt.want) {
			die("cross-field mutant %s expected rule %q, got %v", mt.id, mt.want, ids)
		}
		short := string(mt.msg.ProtoReflect().Descriptor().Name())
		cases = append(cases, mkCase(mt.id, short, mt.msg, false, ids, v))
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	out, err := json.MarshalIndent(cases, "", "  ")
	must(err)
	must(os.WriteFile("conformance/corpus/crossfield.json", append(out, '\n'), 0o644))
	fmt.Printf("wrote %d cross-field cases -> conformance/corpus/crossfield.json\n", len(cases))
}

// ── baseline construction ────────────────────────────────────────────────────

func baseline(md protoreflect.MessageDescriptor, sd map[string]proto.Message) (protoreflect.Message, error) {
	var m protoreflect.Message
	if s, ok := sd[string(md.Name())]; ok {
		m = proto.Clone(s).ProtoReflect()
	} else {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
		if err != nil {
			return nil, err
		}
		m = mt.New()
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			fr := rules(fd)
			if fr == nil || !hasConstraint(fr) {
				continue
			}
			if err := setValid(m, fd, fr, sd); err != nil {
				return nil, fmt.Errorf("field %s: %w", fd.Name(), err)
			}
		}
	}
	enrichWKT(m)
	return m, nil
}

// enrichWKT populates any direct Timestamp/Duration field on the baseline so the
// canonical round-trip test exercises those proto-JSON encodings. Singular,
// non-repeated, top-level fields only — enough to cover the corpus messages that
// carry them; deeper nesting is not currently exercised.
func enrichWKT(m protoreflect.Message) {
	fds := m.Descriptor().Fields()
	for i := 0; i < fds.Len(); i++ {
		fd := fds.Get(i)
		if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			continue
		}
		switch fd.Message().FullName() {
		case "google.protobuf.Timestamp":
			m.Set(fd, protoreflect.ValueOfMessage(timestamppb.New(fixedTime).ProtoReflect()))
		case "google.protobuf.Duration":
			m.Set(fd, protoreflect.ValueOfMessage(durationpb.New(fixedDur).ProtoReflect()))
		}
	}
}

// validItem builds ONE valid element for a repeated field. Scalar items come
// straight from validScalar; a message item is built the same way a top-level
// baseline is — from its seed when one exists, otherwise auto-filled — because
// validScalar deliberately returns an unset Value for MessageKind and appending
// that to a list panics.
//
// It auto-fills where setValid's singular-message branch instead demands a seed.
// The split is deliberate: a singular message field is usually a required
// sub-message whose validity depends on cross-field CEL that auto-fill cannot
// satisfy (the reason seeds exist at all), whereas a repeated element only has
// to clear its own field rules, which auto-fill does handle. A repeated element
// that needs more can still be seeded — the seed map is consulted first.
//
// Recursion terminates on the seed map or on a message whose constrained fields
// are all scalar. The contract has no message cycle; if one is ever introduced
// without a seed this recurses until the stack overflows, which is loud but
// unhelpful — seed the cycle's entry point.
func validItem(fd protoreflect.FieldDescriptor, item *validate.FieldRules, sd map[string]proto.Message) (protoreflect.Value, error) {
	if fd.Kind() != protoreflect.MessageKind {
		return validScalar(fd, item)
	}
	sub, err := baseline(fd.Message(), sd)
	if err != nil {
		return protoreflect.Value{}, fmt.Errorf("repeated message item %s: %w", fd.Message().Name(), err)
	}
	return protoreflect.ValueOfMessage(sub), nil
}

func setValid(m protoreflect.Message, fd protoreflect.FieldDescriptor, fr *validate.FieldRules, sd map[string]proto.Message) error {
	if fd.IsList() {
		v, err := validItem(fd, itemRules(fr), sd)
		if err != nil {
			return err
		}
		m.Mutable(fd).List().Append(v)
		return nil
	}
	v, err := validScalar(fd, fr)
	if err != nil {
		return err
	}
	if fd.Kind() == protoreflect.MessageKind {
		s, ok := sd[string(fd.Message().Name())]
		if !ok {
			return fmt.Errorf("required message field needs a seed for %s", fd.Message().Name())
		}
		m.Set(fd, protoreflect.ValueOfMessage(proto.Clone(s).ProtoReflect()))
		return nil
	}
	m.Set(fd, v)
	return nil
}

// validScalar returns a valid value for fd given its rules (enum→first allowed,
// string→first sample matching pattern+length, int64/int32/double→their lower
// bound, else zero).
func validScalar(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(firstAllowedEnum(fd.Enum(), fr.GetEnum())), nil
	case protoreflect.StringKind:
		s, ok := validString(fr.GetString())
		if !ok {
			return protoreflect.Value{}, fmt.Errorf("no sample string matches the pattern/length")
		}
		return protoreflect.ValueOfString(s), nil
	case protoreflect.Int64Kind:
		return protoreflect.ValueOfInt64(int64(gte(fr.GetInt64()))), nil
	case protoreflect.Int32Kind:
		if r := fr.GetInt32(); r != nil {
			switch x := r.GetGreaterThan().(type) {
			case *validate.Int32Rules_Gte:
				return protoreflect.ValueOfInt32(x.Gte), nil
			case *validate.Int32Rules_Gt:
				return protoreflect.ValueOfInt32(x.Gt + 1), nil
			}
		}
		return protoreflect.ValueOfInt32(0), nil
	case protoreflect.DoubleKind:
		if r := fr.GetDouble(); r != nil {
			switch x := r.GetGreaterThan().(type) {
			case *validate.DoubleRules_Gte:
				return protoreflect.ValueOfFloat64(x.Gte), nil
			case *validate.DoubleRules_Gt:
				return protoreflect.ValueOfFloat64(x.Gt + 1), nil
			}
		}
		return protoreflect.ValueOfFloat64(0), nil
	case protoreflect.MessageKind:
		return protoreflect.Value{}, nil // handled by caller via seed
	}
	return protoreflect.Value{}, fmt.Errorf("unhandled kind %s", fd.Kind())
}

// ── edges (boundary-violating mutants) ───────────────────────────────────────

type edge struct {
	label string
	want  string // the protovalidate rule id this edge must trip (integrity check)
	apply func(m protoreflect.Message)
	valid bool // a POSITIVE edge: Go must ACCEPT it (e.g. "" on a money field). want is unused.
}

func edges(fd protoreflect.FieldDescriptor, fr *validate.FieldRules, sd map[string]proto.Message) []edge {
	var es []edge
	if fr.GetRequired() {
		es = append(es, edge{label: "missing", want: "required", apply: func(m protoreflect.Message) { m.Clear(fd) }})
	}
	if fd.IsList() {
		return append(es, listEdges(fd, fr, sd)...)
	}
	switch fd.Kind() {
	case protoreflect.EnumKind:
		es = append(es, enumEdges(fd, fr.GetEnum())...)
	case protoreflect.StringKind:
		es = append(es, stringEdges(fd, fr.GetString())...)
	case protoreflect.Int64Kind:
		if r := fr.GetInt64(); r != nil {
			if _, ok := r.GetGreaterThan().(*validate.Int64Rules_Gte); ok {
				n := r.GetGte() - 1
				es = append(es, edge{label: "below_min", want: "int64.gte", apply: func(m protoreflect.Message) {
					m.Set(fd, protoreflect.ValueOfInt64(n))
				}})
			}
		}
	case protoreflect.Int32Kind:
		if r := fr.GetInt32(); r != nil {
			var lower, upper string
			var lowerMutant, upperMutant int32
			switch x := r.GetGreaterThan().(type) {
			case *validate.Int32Rules_Gte:
				lower, lowerMutant = "gte", x.Gte-1
			case *validate.Int32Rules_Gt:
				lower, lowerMutant = "gt", x.Gt
			}
			switch x := r.GetLessThan().(type) {
			case *validate.Int32Rules_Lt:
				upper, upperMutant = "lt", x.Lt
			case *validate.Int32Rules_Lte:
				upper, upperMutant = "lte", x.Lte+1
			}
			want := numericRuleID("int32", lower, upper)
			if lower != "" {
				n := lowerMutant
				es = append(es, edge{label: "below_min", want: want, apply: func(m protoreflect.Message) {
					m.Set(fd, protoreflect.ValueOfInt32(n))
				}})
			}
			if upper != "" {
				n := upperMutant
				es = append(es, edge{label: "above_max", want: want, apply: func(m protoreflect.Message) {
					m.Set(fd, protoreflect.ValueOfInt32(n))
				}})
			}
		}
	case protoreflect.DoubleKind:
		if r := fr.GetDouble(); r != nil {
			var lower, upper string
			var lowerMutant, upperMutant float64
			switch x := r.GetGreaterThan().(type) {
			case *validate.DoubleRules_Gte:
				lower, lowerMutant = "gte", x.Gte-1
			case *validate.DoubleRules_Gt:
				lower, lowerMutant = "gt", x.Gt
			}
			switch x := r.GetLessThan().(type) {
			case *validate.DoubleRules_Lt:
				upper, upperMutant = "lt", x.Lt
			case *validate.DoubleRules_Lte:
				upper, upperMutant = "lte", x.Lte+1
			}
			want := numericRuleID("double", lower, upper)
			if lower != "" {
				n := lowerMutant
				es = append(es, edge{label: "below_min", want: want, apply: func(m protoreflect.Message) {
					m.Set(fd, protoreflect.ValueOfFloat64(n))
				}})
			}
			if upper != "" {
				n := upperMutant
				es = append(es, edge{label: "above_max", want: want, apply: func(m protoreflect.Message) {
					m.Set(fd, protoreflect.ValueOfFloat64(n))
				}})
			}
		}
	}
	return es
}

// numericRuleID is the protovalidate rule id a scalar bound violation reports.
// With both bounds set, protovalidate checks the range as ONE rule whose id
// joins the two bound names (e.g. int32.gte_lt) — both boundary mutants trip
// that combined id; with a single bound, the id is just that bound's name.
func numericRuleID(kind, lower, upper string) string {
	switch {
	case lower != "" && upper != "":
		return kind + "." + lower + "_" + upper
	case lower != "":
		return kind + "." + lower
	default:
		return kind + "." + upper
	}
}

func enumEdges(fd protoreflect.FieldDescriptor, r *validate.EnumRules) []edge {
	var es []edge
	for _, n := range r.GetNotIn() {
		nn := protoreflect.EnumNumber(n)
		es = append(es, edge{label: "not_in", want: "enum.not_in", apply: func(m protoreflect.Message) {
			m.Set(fd, protoreflect.ValueOfEnum(nn))
		}})
	}
	// A presence-tracked (proto3 optional) enum that rejects its zero via not_in
	// still ACCEPTS omission: protovalidate skips an unset optional field's rule,
	// so the cleared value is valid — the common ingest case where a publisher
	// omits the hint. Gated on BOTH a not_in rule AND presence (the non-trivial
	// pairing), so it fires only for a field that rejects its zero yet may be
	// absent — today just ResourceEntry.resource_mutability — pinning
	// omitted-is-valid across all three runners.
	if len(r.GetNotIn()) > 0 && fd.HasPresence() {
		es = append(es, edge{label: "unset_valid", valid: true,
			apply: func(m protoreflect.Message) { m.Clear(fd) }})
	}
	// Only when defined_only is set does Go reject an undefined number. With
	// not_in:[0] alone, proto's open-enum forward-compat lets an unknown value
	// through server-side (a newer peer's value), so no edge here.
	if r.GetDefinedOnly() {
		undef := undefinedEnum(fd.Enum())
		es = append(es, edge{label: "undefined", want: "enum.defined_only", apply: func(m protoreflect.Message) {
			m.Set(fd, protoreflect.ValueOfEnum(undef))
		}})
	}
	return es
}

func stringEdges(fd protoreflect.FieldDescriptor, r *validate.StringRules) []edge {
	var es []edge
	if p := r.GetPattern(); p != "" {
		// One INVALID mutant per badStrings entry the pattern rejects (option A), each
		// keyed by the stable badStrings index so IDs don't shift when the list grows.
		// This is where the money killers reach money fields.
		for _, i := range failingBadStringIdxs(p) {
			bad := badStrings[i]
			es = append(es, edge{label: fmt.Sprintf("pattern#%d", i), want: "string.pattern",
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(bad)) }})
		}
		// Pattern-specific killers, so a family's own refusal shapes reach the
		// corpus — and therefore the Pydantic and Zod replays — without widening
		// the shared table. Each is asserted to actually fail its pattern, so a
		// stale entry cannot sit here as a silent no-op.
		re := regexp.MustCompile(p)
		for i, bad := range patternKillers[p] {
			if re.MatchString(bad) {
				die("patternKillers[%q][%d] = %q is ACCEPTED by the pattern — it would emit a case asserting the opposite", p, i, bad)
			}
			es = append(es, edge{label: fmt.Sprintf("killer#%d", i), want: "string.pattern",
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(bad)) }})
		}
		// The empty-string boundary: if the pattern ACCEPTS "" it is a positive case
		// (money — the empty-money blind spot; proves clients accept ""); if it REJECTS "" then
		// the zero value is invalid, so omission must be rejected (pattern-derived
		// required-presence, e.g. Quota.metric) — only meaningful for a non-optional
		// field whose cleared value really is "".
		if regexp.MustCompile(p).MatchString("") {
			es = append(es, edge{label: "empty_ok", valid: true,
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString("")) }})
		} else if !fd.HasPresence() {
			es = append(es, edge{label: "missing_empty", want: "string.pattern",
				apply: func(m protoreflect.Message) { m.Clear(fd) }})
		}
	}
	if n := r.GetMinLen(); n > 0 {
		s := strings.Repeat("a", int(n)-1)
		es = append(es, edge{label: "too_short", want: "string.min_len",
			apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(s)) }})
	}
	if n := r.GetMaxLen(); n > 0 {
		s := strings.Repeat("a", int(n)+1)
		es = append(es, edge{label: "too_long", want: "string.max_len",
			apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(s)) }})
	}
	return es
}

// failingBadStringIdxs returns the indices of badStrings the pattern rejects, in order.
// Shared by stringEdges (multi-emit) and listEdges item_pattern (first only), so the two
// call sites stay in lockstep on what "a bad string for this pattern" means.
func failingBadStringIdxs(pattern string) []int {
	re := regexp.MustCompile(pattern)
	var idxs []int
	for i, s := range badStrings {
		if !re.MatchString(s) {
			idxs = append(idxs, i)
		}
	}
	return idxs
}

func listEdges(fd protoreflect.FieldDescriptor, fr *validate.FieldRules, sd map[string]proto.Message) []edge {
	var es []edge
	r := fr.GetRepeated()
	item := itemRules(fr)
	good, err := validItem(fd, item, sd) // a valid item value
	must(err)
	if r != nil && r.GetMaxItems() > 0 {
		n := int(r.GetMaxItems()) + 1
		es = append(es, edge{label: "too_many", want: "repeated.max_items", apply: func(m protoreflect.Message) {
			l := m.Mutable(fd).List()
			for l.Len() < n {
				l.Append(good)
			}
		}})
	}
	if r != nil && r.GetUnique() {
		// The baseline seeds exactly one valid item (setValid), so appending it again
		// yields [x, x]: two items, under any max_items, tripping ONLY repeated.unique.
		// Without this the rule reaches no corpus case, and the Zod/Pydantic parity gate
		// cannot see whether the clients enforce it.
		es = append(es, edge{label: "duplicate_item", want: "repeated.unique",
			apply: func(m protoreflect.Message) { m.Mutable(fd).List().Append(good) }})
	}
	if item != nil {
		if s := item.GetString(); s != nil {
			if p := s.GetPattern(); p != "" {
				if bad, ok := badString(p); ok {
					es = append(es, edge{label: "item_pattern", want: "string.pattern",
						apply: func(m protoreflect.Message) { m.Mutable(fd).List().Append(protoreflect.ValueOfString(bad)) }})
				}
				// Pattern-specific killers reach list items too — a repeated
				// domain field admits the same smuggled scheme or path as a
				// singular one, and the acceptance criterion says every field
				// carrying the constraint, not every singular field.
				re := regexp.MustCompile(p)
				for i, bad := range patternKillers[p] {
					if re.MatchString(bad) {
						die("patternKillers[%q][%d] = %q is ACCEPTED by the pattern", p, i, bad)
					}
					es = append(es, edge{label: fmt.Sprintf("item_killer#%d", i), want: "string.pattern",
						apply: func(m protoreflect.Message) { m.Mutable(fd).List().Append(protoreflect.ValueOfString(bad)) }})
				}
			}
			if n := s.GetMinLen(); n > 0 {
				bad := strings.Repeat("a", int(n)-1)
				es = append(es, edge{label: "item_too_short", want: "string.min_len",
					apply: func(m protoreflect.Message) { m.Mutable(fd).List().Append(protoreflect.ValueOfString(bad)) }})
			}
			if n := s.GetMaxLen(); n > 0 {
				bad := strings.Repeat("a", int(n)+1)
				es = append(es, edge{label: "item_too_long", want: "string.max_len",
					apply: func(m protoreflect.Message) { m.Mutable(fd).List().Append(protoreflect.ValueOfString(bad)) }})
			}
		}
	}
	return es
}

// ── rule helpers ─────────────────────────────────────────────────────────────

func rules(fd protoreflect.FieldDescriptor) *validate.FieldRules {
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil {
		return nil
	}
	return fr
}

// itemRules is the per-item FieldRules of a repeated field (repeated.items).
func itemRules(fr *validate.FieldRules) *validate.FieldRules { return fr.GetRepeated().GetItems() }

// hasConstraint reports whether fr carries a FIELD-level rule we generate edges
// for. CEL-only (cross-field) field rules are excluded — they are not client-
// enforceable and belong to the server.
func hasConstraint(fr *validate.FieldRules) bool {
	if fr.GetRequired() {
		return true
	}
	if e := fr.GetEnum(); e != nil && (e.GetDefinedOnly() || len(e.GetNotIn()) > 0) {
		return true
	}
	if s := fr.GetString(); s != nil && (s.GetPattern() != "" || s.GetMinLen() > 0 || s.GetMaxLen() > 0) {
		return true
	}
	if i := fr.GetInt64(); i != nil && i.GetGreaterThan() != nil {
		return true
	}
	if i := fr.GetInt32(); i != nil && (i.GetGreaterThan() != nil || i.GetLessThan() != nil) {
		return true
	}
	if d := fr.GetDouble(); d != nil && (d.GetGreaterThan() != nil || d.GetLessThan() != nil) {
		return true
	}
	if r := fr.GetRepeated(); r != nil {
		if r.GetMaxItems() > 0 || r.GetMinItems() > 0 || r.GetUnique() {
			return true
		}
		if it := r.GetItems(); it != nil && it.GetString().GetPattern() != "" {
			return true
		}
	}
	return false
}

func firstAllowedEnum(ed protoreflect.EnumDescriptor, r *validate.EnumRules) protoreflect.EnumNumber {
	notIn := map[int32]bool{}
	for _, n := range r.GetNotIn() {
		notIn[n] = true
	}
	vs := ed.Values()
	for i := 0; i < vs.Len(); i++ {
		num := vs.Get(i).Number()
		name := string(vs.Get(i).Name())
		if notIn[int32(num)] || strings.HasSuffix(name, "_UNSPECIFIED") {
			continue
		}
		return num
	}
	return 0
}

func undefinedEnum(ed protoreflect.EnumDescriptor) protoreflect.EnumNumber {
	max := int32(0)
	vs := ed.Values()
	for i := 0; i < vs.Len(); i++ {
		if int32(vs.Get(i).Number()) > max {
			max = int32(vs.Get(i).Number())
		}
	}
	return protoreflect.EnumNumber(max + 1)
}

func validString(r *validate.StringRules) (string, bool) {
	var re *regexp.Regexp
	if r != nil && r.GetPattern() != "" {
		re = regexp.MustCompile(r.GetPattern())
	}
	min, max := uint64(0), uint64(0)
	if r != nil {
		min, max = r.GetMinLen(), r.GetMaxLen()
	}
	for _, s := range stringSamples {
		if re != nil && !re.MatchString(s) {
			continue
		}
		if min > 0 && uint64(len(s)) < min {
			continue
		}
		if max > 0 && uint64(len(s)) > max {
			continue
		}
		return s, true
	}
	return "", false
}

// badString returns the FIRST badStrings entry the pattern rejects — the single-emit
// form used for list items (multi-emit belongs to scalar stringEdges only, so list
// edges don't amplify). Shares failingBadStringIdxs so both sites agree on "bad".
func badString(pattern string) (string, bool) {
	if idxs := failingBadStringIdxs(pattern); len(idxs) > 0 {
		return badStrings[idxs[0]], true
	}
	return "", false
}

func gte(r *validate.Int64Rules) int64 {
	if r == nil {
		return 0
	}
	if x, ok := r.GetGreaterThan().(*validate.Int64Rules_Gte); ok {
		return x.Gte
	}
	return 0
}

// ── output / misc ────────────────────────────────────────────────────────────

func mkCase(id, short string, m proto.Message, valid bool, ids []string, _ protovalidate.Validator) Case {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	must(err)
	// re-indent to canonical form so the committed corpus is stable
	var v any
	must(json.Unmarshal(b, &v))
	canon, err := json.Marshal(v)
	must(err)
	sort.Strings(ids)
	return Case{ID: id, Message: short, Valid: valid, Rules: dedupe(ids), JSON: canon}
}

func ruleIDs(err error) []string {
	verr, ok := err.(*protovalidate.ValidationError)
	if !ok {
		return nil
	}
	var ids []string
	for _, vi := range verr.Violations {
		ids = append(ids, vi.Proto.GetRuleId())
	}
	return ids
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func must(err error) {
	if err != nil {
		die("%v", err)
	}
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "corpusgen: "+f+"\n", a...)
	os.Exit(1)
}
