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
		},
		"TenantFeeRate":   &rampadminv1.TenantFeeRate{TenantId: "tenant-seed", FeeRateBps: 0},
		"ReportingPolicy": &rampadminv1.ReportingPolicy{TenantId: "tenant-seed", RequiredFields: []string{"x"}},
		// ramp.admin.v1 evidence-read payloads (required sub-messages of
		// GetTransactionEvidenceResponse). Seeded wholesale: they carry rule
		// shapes auto-fill does not handle — bytes rules (len=32 keys,
		// non-empty canonical bytes) and required Timestamp fields.
		"TransactionEvidence": &rampadminv1.TransactionEvidence{
			TransactionId:       "tx-seed",
			TenantId:            "tenant-seed",
			OfferId:             "offer-seed",
			OfferJson:           `{"offer_id":"offer-seed"}`,
			OfferCanonicalBytes: []byte(`{"offer_id":"offer-seed"}`),
			// "EdDSA" is the content-signature label the contract pins (see
			// offer_sig_algorithm's comment); "ed25519" is the RFC 9421
			// HTTP-request-signature label and must not appear here.
			OfferSig:                          strings.Repeat("ab", 64),
			OfferSigAlgorithm:                 "EdDSA",
			ExchangeSigningPublicKey:          []byte(strings.Repeat("k", 32)),
			AgentAcceptanceSignature:          strings.Repeat("ab", 64),
			AgentAcceptanceCanonicalBytes:     []byte(`{"requester_id":"agent-seed"}`),
			AgentAcceptanceSignatureAlgorithm: "EdDSA",
			RequesterId:                       "agent-seed",
			RequesterDomain:                   "agent.example",
			RequestIdempotencyKey:             "idem-tx",
			AgentPublicKey:                    []byte(strings.Repeat("k", 32)),
			CreatedAt:                         timestamppb.New(fixedTime),
		},
		"TransactionState": &rampadminv1.TransactionState{
			IdempotencyKey:  "idem-tx:offer-seed",
			SignedUrlExpiry: timestamppb.New(fixedTime),
			SignedUrlHash:   []byte(strings.Repeat("h", 32)),
		},
		"ReportingObligationState": &rampadminv1.ReportingObligationState{
			State:     rampadminv1.ObligationState_OBLIGATION_STATE_PENDING,
			WindowEnd: timestamppb.New(fixedTime),
		},
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
			if fr := rules(fd); fr != nil {
				// Fail loud on any rule member this generator cannot classify —
				// an allowlist alone fails OPEN: a field carrying only an
				// unrecognized shape (how the first bytes rules shipped
				// uncovered) would get zero corpus cases with every gate green.
				assertRulesClassified(string(md.Name()), fd, fr)
				if hasConstraint(fr) {
					constrained = append(constrained, fd)
				}
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
			es := edges(fd, rules(fd), sd)
			// A constrained field with zero edges means edges() does not know the
			// field's rule shape — the corpus would silently carry no case for it
			// (how the first bytes rules shipped uncovered). Fail the run instead.
			if len(es) == 0 {
				die("field %s.%s has rules but produced no edges — teach edges() its rule shape", short, fd.Name())
			}
			for _, e := range es {
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
				cases = append(cases, mkCasePatched(id, short, m.Interface(), false, ids, e.postJSON))
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
	// postJSON patches the marshaled JSON object AFTER protojson. Needed for
	// wire shapes protojson cannot produce from a proto value: an explicit-empty
	// implicit-presence field ("field": "", "items": []) is dropped by protojson,
	// yet is a distinct client parse path from omission.
	postJSON func(obj map[string]any)
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
	case protoreflect.BytesKind:
		es = append(es, bytesEdges(fd, fr)...)
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
		// Honest labels: protojson DROPS a zero-valued implicit-presence enum,
		// so for not_in:[0] on a non-optional field the emitted JSON OMITS the
		// field entirely — the case pins "omitted is rejected", not "an explicit
		// UNSPECIFIED string is rejected", and its id says so. A presence-tracked
		// field (or a nonzero not_in value) serializes the value explicitly and
		// keeps the plain label.
		label := "not_in"
		if n == 0 && !fd.HasPresence() {
			label = "not_in_zero_omitted"
		}
		es = append(es, edge{label: label, want: "enum.not_in", apply: func(m protoreflect.Message) {
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
	if r.Const != nil {
		c := r.GetConst()
		// Two invalid mutants: an unrelated label (the algorithm-confusion
		// probe — a client must reject a claimed "none") and a case variant,
		// so a client comparing case-insensitively diverges from Go. The case
		// variant is skipped when flipping case cannot change the value.
		es = append(es, edge{label: "const_other", want: "string.const",
			apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString("none")) }})
		if variant := strings.ToLower(c); variant != c {
			es = append(es, edge{label: "const_case", want: "string.const",
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(variant)) }})
		} else if variant := strings.ToUpper(c); variant != c {
			es = append(es, edge{label: "const_case", want: "string.const",
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(variant)) }})
		}
		if c != "" && !fd.HasPresence() {
			// The cleared value "" also violates the const, so omission must be
			// rejected — same presence collapse as min_len's too_short_omitted.
			es = append(es, edge{label: "const_omitted", want: "string.const",
				apply: func(m protoreflect.Message) { m.Clear(fd) }})
		}
	}
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
		set := func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(s)) }
		if n == 1 && !fd.HasPresence() {
			// Honest labels: same omission collapse as bytesEdges — one below a
			// min_len=1 floor is "" and protojson drops it, so the case pins
			// omission; the explicit "" wire shape is its own case.
			name := string(fd.Name())
			es = append(es,
				edge{label: "too_short_omitted", want: "string.min_len", apply: set},
				edge{label: "too_short_explicit_empty", want: "string.min_len", apply: set,
					postJSON: func(obj map[string]any) { obj[name] = "" }})
		} else {
			es = append(es, edge{label: "too_short", want: "string.min_len", apply: set})
		}
	}
	if n := r.GetMaxLen(); n > 0 {
		s := strings.Repeat("a", int(n)+1)
		es = append(es, edge{label: "too_long", want: "string.max_len",
			apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(s)) }})
	}
	// FORWARD-PROVISIONED, currently unreachable: no contract field may carry
	// string.max_bytes while requiredgen's assertNoStringByteLengthRules panics
	// on it (protoschema renders it as a CHARACTER count, so the generated
	// clients would diverge from Go). The mutants below — and the max_bytes
	// entry in classifiedRuleMembers — are what this generator would emit the day
	// the sdk-types pipeline gets a byte-count refine and that panic is lifted.
	//
	// They stay because the cost is one branch inside a generator that already
	// walks the rule. The class-6 corpus coverage guard did NOT stay: a coverage
	// assertion that can never run is coverage on paper, and it also carried
	// helpers no test ever exercised. Reintroducing max_bytes means writing the
	// guard then, against the mutants below.
	if n := r.GetMaxBytes(); n > 0 {
		ascii := strings.Repeat("a", int(n)+1)
		es = append(es, edge{label: "too_many_bytes", want: "string.max_bytes",
			apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(ascii)) }})
		// max_bytes counts BYTES, not characters. This mutant is over the limit in
		// bytes but well under it in characters ("é" is 2 UTF-8 bytes), so a client
		// that counts characters accepts it and diverges from Go's verdict.
		multibyte := strings.Repeat("é", int(n)/2+1)
		es = append(es, edge{label: "too_many_bytes_multibyte", want: "string.max_bytes",
			apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfString(multibyte)) }})
	}
	return es
}

// bytesEdges emits boundary mutants for bytes rules. An exact-length rule
// (bytes.len) gets both a shorter and a longer mutant — one alone would let a
// client enforce only min or only max and stay green. min_len's mutant at
// len-1 is the empty value when min_len==1; protovalidate still reports
// bytes.min_len for it (no presence on proto3 singular bytes), which the
// generator's oracle check confirms at emit time.
//
// The rule is read through conformance.MustBytesLength so this generator, the
// bytes_len.json manifest and the class-6 coverage guard cannot disagree about
// which fields carry a length rule. It also means a zero-valued length rule dies
// there with the field's name instead of reaching bytesOf(-1) and surfacing as
// "strings: negative Repeat count".
func bytesEdges(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) []edge {
	var es []edge
	r := conformance.MustBytesLength(fd, fr)
	if r == nil {
		return es
	}
	if r.Kind == "len" {
		short := bytesOf(int(r.Value) - 1)
		long := bytesOf(int(r.Value) + 1)
		es = append(es,
			edge{label: "wrong_len_short", want: "bytes.len",
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfBytes(short)) }},
			edge{label: "wrong_len_long", want: "bytes.len",
				apply: func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfBytes(long)) }})
	}
	if n := r.Value; r.Kind == "min_len" {
		short := bytesOf(int(n) - 1)
		set := func(m protoreflect.Message) { m.Set(fd, protoreflect.ValueOfBytes(short)) }
		if n == 1 && !fd.HasPresence() {
			// Honest labels: one below a min_len=1 floor is EMPTY bytes, and
			// protojson DROPS an empty implicit-presence field — the emitted
			// JSON omits the field entirely, so the case pins "omission is
			// rejected" (same collapse as enum not_in_zero_omitted). The
			// explicit-empty wire shape ("field": "") is a different client
			// parse path, so it is emitted as its own case via a JSON-layer
			// patch; Go's verdict is identical for both.
			name := string(fd.Name())
			es = append(es,
				edge{label: "too_short_omitted", want: "bytes.min_len", apply: set},
				edge{label: "too_short_explicit_empty", want: "bytes.min_len", apply: set,
					postJSON: func(obj map[string]any) { obj[name] = "" }})
		} else {
			es = append(es, edge{label: "too_short", want: "bytes.min_len", apply: set})
		}
	}
	return es
}

// bytesOf is n copies of a fixed non-zero byte — deterministic filler for
// length-rule mutants.
func bytesOf(n int) []byte {
	return []byte(strings.Repeat("b", n))
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
	if r != nil && r.GetMinItems() > 0 {
		// The baseline is valid, so it holds at least min_items valid items;
		// truncating to one below the floor trips ONLY repeated.min_items.
		n := int(r.GetMinItems()) - 1
		truncate := func(m protoreflect.Message) { m.Mutable(fd).List().Truncate(n) }
		if n == 0 {
			// Honest labels: one below a min_items=1 floor is the EMPTY list,
			// and protojson DROPS an empty repeated field — the emitted JSON
			// omits the field entirely, so the case pins "omission is
			// rejected". The explicit-empty wire shape ("items": []) is a
			// different client parse path, emitted as its own case via a
			// JSON-layer patch; Go's verdict is identical for both.
			name := string(fd.Name())
			es = append(es,
				edge{label: "too_few_omitted", want: "repeated.min_items", apply: truncate},
				edge{label: "too_few_explicit_empty", want: "repeated.min_items", apply: truncate,
					postJSON: func(obj map[string]any) { obj[name] = []any{} }})
		} else {
			es = append(es, edge{label: "too_few", want: "repeated.min_items", apply: truncate})
		}
	}
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

// rules resolves fd's field rules through the shared helper, which panics on a
// resolver failure: it is not "no rules", and treating it as nil would silently
// drop every corpus case the field should have.
func rules(fd protoreflect.FieldDescriptor) *validate.FieldRules {
	return conformance.FieldRules(fd)
}

// itemRules is the per-item FieldRules of a repeated field (repeated.items).
func itemRules(fr *validate.FieldRules) *validate.FieldRules { return fr.GetRepeated().GetItems() }

// classifiedRuleMembers is the closed set of (rule kind, member) pairs
// hasConstraint/edges() know how to turn into corpus cases, and the SINGLE
// inventory of them: hasConstraint reads this table rather than restating it.
// Field-level `cel` and `required` are handled outside it (cel is server-only by
// scope; required gets the `missing` edge). assertRulesClassified dies on
// anything set outside this table, so a new rule shape MUST be taught to edges()
// (and added here) before it can ship — the allowlist fails CLOSED.
var classifiedRuleMembers = map[string]map[string]bool{
	// string.max_bytes is classified but FORWARD-PROVISIONED: requiredgen's
	// assertNoStringByteLengthRules currently forbids it contract-wide (see the
	// max_bytes edge in stringEdges for the full position).
	"string":   {"const": true, "pattern": true, "min_len": true, "max_len": true, "max_bytes": true},
	"enum":     {"defined_only": true, "not_in": true},
	"bytes":    {"len": true, "min_len": true},
	"int64":    {"gte": true},
	"int32":    {"gte": true, "gt": true, "lt": true, "lte": true},
	"double":   {"gte": true, "gt": true, "lt": true, "lte": true},
	"repeated": {"min_items": true, "max_items": true, "unique": true, "items": true},
}

// classifiedItemMembers is the same closed set for repeated.items sub-rules —
// listEdges only mutates string item rules today.
var classifiedItemMembers = map[string]map[string]bool{
	"string": {"pattern": true, "min_len": true, "max_len": true},
}

// assertRulesClassified dies if fr carries any set rule member outside the
// classified tables. This is the fail-closed complement to hasConstraint:
// hasConstraint answers "does this field get cases", this answers "is every
// rule on this field one the generator understands".
func assertRulesClassified(short string, fd protoreflect.FieldDescriptor, fr *validate.FieldRules) {
	checkMembers(short, fd, fr, classifiedRuleMembers, "")
	if it := fr.GetRepeated().GetItems(); it != nil {
		checkMembers(short, fd, it, classifiedItemMembers, "repeated.items.")
	}
}

func checkMembers(short string, fd protoreflect.FieldDescriptor, fr *validate.FieldRules, known map[string]map[string]bool, prefix string) {
	fr.ProtoReflect().Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(f.Name())
		if name == "cel" || name == "required" {
			return true
		}
		// A non-message member (e.g. `ignore`) changes rule semantics in ways
		// this generator does not model — unclassified, so fail closed.
		if f.Kind() != protoreflect.MessageKind || f.IsList() {
			die("field %s.%s carries rule %s%s — teach edges()/hasConstraint its shape (and classifiedRuleMembers) before shipping it", short, fd.Name(), prefix, name)
		}
		members, ok := known[name]
		if !ok {
			die("field %s.%s carries rule %s%s — teach edges()/hasConstraint its shape (and classifiedRuleMembers) before shipping it", short, fd.Name(), prefix, name)
		}
		v.Message().Range(func(mf protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			if !members[string(mf.Name())] {
				die("field %s.%s carries rule %s%s.%s — teach edges()/hasConstraint its shape (and classifiedRuleMembers) before shipping it", short, fd.Name(), prefix, name, mf.Name())
			}
			return true
		})
		return true
	})
}

// hasConstraint reports whether fr carries a FIELD-level rule we generate edges
// for. CEL-only (cross-field) field rules are excluded — they are not client-
// enforceable and belong to the server.
//
// It is DERIVED from the classified tables above, not from a third hand-written
// list of the same rules. The hand-written version drifted: the tables (and
// listEdges) covered repeated.items.string.min_len/max_len while this function's
// repeated branch fired only on an item pattern, so a repeated field whose only
// rules were item lengths would pass the fail-closed classification and then get
// ZERO corpus cases with every gate green. One inventory, one place to edit.
//
// Membership is by rule member SET, not by value: an explicitly zero-valued rule
// (min_len: 0, unique: false) now counts as a constraint and produces no edges,
// which the caller turns into a loud "has rules but produced no edges" failure.
// That is the intended direction — such a rule constrains nothing and is a
// contract error (bytesgen fails the same way on a zero-valued bytes length).
func hasConstraint(fr *validate.FieldRules) bool {
	if fr.GetRequired() {
		return true
	}
	found := false
	fr.ProtoReflect().Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(f.Name())
		// `cel` is server-scope and `required` is handled above; anything not in
		// the table already died in assertRulesClassified, which runs first.
		if name == "cel" || name == "required" || f.Kind() != protoreflect.MessageKind || f.IsList() {
			return true
		}
		members, ok := classifiedRuleMembers[name]
		if !ok {
			return true
		}
		v.Message().Range(func(mf protoreflect.FieldDescriptor, mv protoreflect.Value) bool {
			mname := string(mf.Name())
			// repeated.items is a nested FieldRules, so it contributes through the
			// item table (what listEdges actually mutates), not by its presence.
			if name == "repeated" && mname == "items" {
				if hasItemConstraint(mv.Message()) {
					found = true
				}
				return true
			}
			if members[mname] {
				found = true
			}
			return true
		})
		return true
	})
	return found
}

// hasItemConstraint is hasConstraint for a repeated field's per-item rules,
// derived the same way from classifiedItemMembers.
func hasItemConstraint(item protoreflect.Message) bool {
	found := false
	item.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(f.Name())
		if name == "cel" || name == "required" || f.Kind() != protoreflect.MessageKind || f.IsList() {
			return true
		}
		members, ok := classifiedItemMembers[name]
		if !ok {
			return true
		}
		v.Message().Range(func(mf protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			if members[string(mf.Name())] {
				found = true
			}
			return true
		})
		return true
	})
	return found
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
	if r != nil && r.Const != nil {
		// A const admits exactly one value; the sample search below cannot
		// discover it.
		return r.GetConst(), true
	}
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
	return mkCasePatched(id, short, m, valid, ids, nil)
}

// mkCasePatched is mkCase with an optional JSON-layer patch (edge.postJSON)
// applied between protojson marshal and canonical re-marshal.
func mkCasePatched(id, short string, m proto.Message, valid bool, ids []string, patch func(obj map[string]any)) Case {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	must(err)
	// re-indent to canonical form so the committed corpus is stable
	obj := map[string]any{}
	must(json.Unmarshal(b, &obj))
	if patch != nil {
		patch(obj)
	}
	canon, err := json.Marshal(obj)
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
