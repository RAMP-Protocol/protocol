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
// byte-exact, drift-gated artifact (regenerate: scripts/gen-corpus.sh).
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
	offer := func() *rampv1.Offer {
		return &rampv1.Offer{OfferId: "offer-seed", Pricing: pricing()}
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
		"DisputeRequest":        &rampv1.DisputeRequest{IdempotencyKey: "idem-dr", Reason: rampv1.DisputeReason_DISPUTE_REASON_CONTENT_MISMATCH},
		// Reflected-Offer execute contract (RAMP-103 / items-only 6afpc): Offer is
		// the required sub-message of TransactionItem (auto-fill needs its seed),
		// and TransactionRequest needs a valid 1-item items[] baseline because its
		// items field is now repeated.min_items=1 (single-offer mode removed).
		"Offer":              offer(),
		"TransactionRequest": &rampv1.TransactionRequest{IdempotencyKey: "idem-tx", Items: []*rampv1.TransactionItem{{Offer: offer()}}},
	}
}

// stringSamples are candidate valid strings; the first that matches a field's
// pattern and length bounds becomes the auto-filled value (generic — no per-field
// table). badStrings are candidates that should FAIL a typical token/number/hash
// pattern; the first that the pattern rejects becomes the violating value.
var stringSamples = []string{"x", "ai-train", "tokens", "accesses", "0", "sha256:" + strings.Repeat("ab", 32), ""}
var badStrings = []string{"two words", "1.2.3", "!!bad!!", "\x00ctl\x00", " "}

func main() {
	v, err := protovalidate.New()
	must(err)
	sd := seeds()

	var cases []Case
	eachMessage(func(md protoreflect.MessageDescriptor) {
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
			for _, e := range edges(fd, rules(fd)) {
				m := proto.Clone(base.Interface()).ProtoReflect()
				e.apply(m)
				verr := v.Validate(m.Interface())
				ids := ruleIDs(verr)
				if verr == nil {
					die("mutant %s.%s/%s did not violate any rule — edge is wrong", short, fd.Name(), e.label)
				}
				if !contains(ids, e.want) {
					die("mutant %s.%s/%s expected rule %q, got %v", short, fd.Name(), e.label, e.want, ids)
				}
				id := fmt.Sprintf("%s/%s/%s", short, fd.Name(), e.label)
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
		{"Pricing/cel/per_unit_requires_unit",
			&rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD"},
			"pricing.per_unit.requires_unit"},
		{"Pricing/cel/free_zero_rate",
			&rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "5"},
			"pricing.free.zero_rate"},
		{"License/cel/digest_required_with_uri",
			&rampv1.License{Id: proto.String("CC-BY-4.0"), Uri: proto.String("https://example.com/license")},
			"license.digest_required_with_uri"},
		{"Restriction/cel/permitted_prohibited_disjoint",
			&rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}, Prohibited: []string{"ai-train"}},
			"restriction.permitted_prohibited_disjoint"},
		{"Obligation/cel/share_alike_requires_scope_license",
			&rampv1.Obligation{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE},
			"obligation.share_alike.requires_scope_license"},
		{"LicenseTerm/cel/reference_only_requires_uri",
			&rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY},
			"license_term.reference_only.requires_uri"},
		{"LicenseTerm/cel/one_restriction_per_kind",
			&rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   freePricing,
				Restrictions: []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}},
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}},
				},
			},
			"license_term.one_restriction_per_kind"},
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

func setValid(m protoreflect.Message, fd protoreflect.FieldDescriptor, fr *validate.FieldRules, sd map[string]proto.Message) error {
	if fd.IsList() {
		l := m.Mutable(fd).List()
		v, err := validScalar(fd, itemRules(fr))
		if err != nil {
			return err
		}
		l.Append(v)
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
// string→first sample matching pattern+length, int64→its gte bound).
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
}

func edges(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) []edge {
	var es []edge
	if fr.GetRequired() {
		es = append(es, edge{"missing", "required", func(m protoreflect.Message) { m.Clear(fd) }})
	}
	if fd.IsList() {
		return append(es, listEdges(fd, fr)...)
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
				es = append(es, edge{"below_min", "int64.gte", func(m protoreflect.Message) {
					m.Set(fd, protoreflect.ValueOfInt64(n))
				}})
			}
		}
	}
	return es
}

func enumEdges(fd protoreflect.FieldDescriptor, r *validate.EnumRules) []edge {
	var es []edge
	for _, n := range r.GetNotIn() {
		nn := protoreflect.EnumNumber(n)
		es = append(es, edge{"not_in", "enum.not_in", func(m protoreflect.Message) {
			m.Set(fd, protoreflect.ValueOfEnum(nn))
		}})
	}
	// Only when defined_only is set does Go reject an undefined number. With
	// not_in:[0] alone, proto's open-enum forward-compat lets an unknown value
	// through server-side (a newer peer's value), so no edge here.
	if r.GetDefinedOnly() {
		undef := undefinedEnum(fd.Enum())
		es = append(es, edge{"undefined", "enum.defined_only", func(m protoreflect.Message) {
			m.Set(fd, protoreflect.ValueOfEnum(undef))
		}})
	}
	return es
}

func stringEdges(fd protoreflect.FieldDescriptor, r *validate.StringRules) []edge {
	var es []edge
	if p := r.GetPattern(); p != "" {
		if bad, ok := badString(p); ok {
			es = append(es, edge{"pattern", "string.pattern", func(m protoreflect.Message) {
				m.Set(fd, protoreflect.ValueOfString(bad))
			}})
		}
	}
	if n := r.GetMinLen(); n > 0 {
		s := strings.Repeat("a", int(n)-1)
		es = append(es, edge{"too_short", "string.min_len", func(m protoreflect.Message) {
			m.Set(fd, protoreflect.ValueOfString(s))
		}})
	}
	if n := r.GetMaxLen(); n > 0 {
		s := strings.Repeat("a", int(n)+1)
		es = append(es, edge{"too_long", "string.max_len", func(m protoreflect.Message) {
			m.Set(fd, protoreflect.ValueOfString(s))
		}})
	}
	return es
}

func listEdges(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) []edge {
	var es []edge
	r := fr.GetRepeated()
	item := itemRules(fr)
	good, _ := validScalar(fd, item) // a valid item value
	if r != nil && r.GetMaxItems() > 0 {
		n := int(r.GetMaxItems()) + 1
		es = append(es, edge{"too_many", "repeated.max_items", func(m protoreflect.Message) {
			l := m.Mutable(fd).List()
			for l.Len() < n {
				l.Append(good)
			}
		}})
	}
	if item != nil {
		if p := item.GetString().GetPattern(); p != "" {
			if bad, ok := badString(p); ok {
				es = append(es, edge{"item_pattern", "string.pattern", func(m protoreflect.Message) {
					m.Mutable(fd).List().Append(protoreflect.ValueOfString(bad))
				}})
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
	if r := fr.GetRepeated(); r != nil {
		if r.GetMaxItems() > 0 || r.GetMinItems() > 0 {
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

func badString(pattern string) (string, bool) {
	re := regexp.MustCompile(pattern)
	for _, s := range badStrings {
		if !re.MatchString(s) {
			return s, true
		}
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
	b, err := protojson.MarshalOptions{}.Marshal(m)
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

func eachMessage(fn func(protoreflect.MessageDescriptor)) {
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			md := ms.Get(i)
			if !md.IsMapEntry() {
				fn(md)
			}
			walk(md.Messages())
		}
	}
	walk(rampv1.File_ramp_v1_ramp_proto.Messages())
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
