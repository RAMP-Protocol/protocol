package conformance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// The shared recipient-host constraint, quoted from the proto. Every field that
// carries a domain — the `exchange` field on each addressed request,
// Offer.exchange, TransactionDenial.exchange, ResourceResponse.exchange,
// Requester.domain, AuthorizedExchange.domain and the RequestConstraints lists —
// is expected to use THIS pattern, not a private variant.
const sharedDomainPattern = `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$`

// malformedDomains are the shapes the constraint exists to refuse. A scheme or a
// path is the load-bearing pair: the value is concatenated into a URL that a
// resolver fetches, so smuggling either one in would let the writer of the field
// choose WHAT is fetched, not merely from where. The corpus generator cannot
// produce these — its bad-string table is shared with money and token fields, and
// widening it there would add a mutant to every pattern-ruled field in the
// contract to cover three shapes that only matter here.
var malformedDomains = []struct{ name, value string }{
	{"scheme_prefix", "https://exchange.example"},
	{"path_suffix", "exchange.example/register"},
	{"query_suffix", "exchange.example?x=1"},
	{"userinfo", "user@exchange.example"},
	{"port_too_long", "exchange.example:123456"},
	{"port_empty", "exchange.example:"},
	{"trailing_root_dot", "exchange.example."},
	{"empty_label", "exchange..example"},
	{"leading_hyphen", "-exchange.example"},
	{"whitespace", "exchange example"},
}

// wantDomainFields is the number of fields the shared domain constraint is meant
// to be on. It is a ratchet, not a description: see the exact-count check below.
const wantDomainFields = 18

// digestPattern is the "method:hexdigest" shape. Several fields carry it, and which
// ones is read from the descriptor by the membership check below rather than listed
// here — a list in a comment is exactly the copy that drifts, and this one already had:
// it named three fields on the day a fourth was added. Copies of one rule are the shape
// that drifts, so the family gets the same descriptor-derived check as the domain one.
const digestPattern = `^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$`

const wantDigestFields = 4

// resourcePathPattern is the absolute-path shape, carried by ResourceEntry.path
// and RemoveResourcesRequest.paths. It is the third shared pattern in the
// contract, and it gets the same descriptor-derived membership check the other two
// have for a reason the corpus generator depends on: corpusgen keys its
// pattern-specific killer table BY THE PATTERN STRING, so if the proto's copy moves
// and the generator's does not, the lookup misses, five killer mutants silently
// stop being emitted, and nothing else in the suite notices. This guard is what
// makes that drift loud.
const resourcePathPattern = `^/[^?#\x00-\x20\x7f]*$`

const wantResourcePathFields = 2

func fieldNames(fs []domainField) string {
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, string(f.msg.Name())+"."+string(f.fd.Name()))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// TestDigestPatternMembership pins the digest family the same way. The pattern is
// repeated per field because protovalidate has no way to share one, so the only
// available guard is to assert the copies stay identical and stay counted.
func TestDigestPatternMembership(t *testing.T) {
	fields := findFieldsWithPattern(t, digestPattern)
	if len(fields) != wantDigestFields {
		t.Fatalf("the digest pattern is on %d fields, expected %d — a copy drifted or a "+
			"new digest field was added without it.\nFields: %s",
			len(fields), wantDigestFields, fieldNames(fields))
	}
	// Every copy admits the same values, which is the property the three
	// hand-written copies exist to preserve.
	for _, df := range fields {
		name := string(df.msg.Name()) + "." + string(df.fd.Name())
		for _, bad := range []string{"md5:" + strings.Repeat("a", 32), "sha256:dead", "sha256:" + strings.Repeat("g", 64)} {
			if validateDomainValue(t, df, bad) {
				t.Errorf("%s accepted %q — a weak or malformed digest defeats the swap-protection the field exists for", name, bad)
			}
		}
		if !validateDomainValue(t, df, "sha256:"+strings.Repeat("ab", 32)) {
			t.Errorf("%s refused a well-formed sha256 digest", name)
		}
	}
}

// TestResourcePathPatternMembership pins the catalog-path family the way the domain
// and digest families are pinned: an exact count, then a shared reject/accept set
// proving the two copies still admit the same values.
//
// The shapes below are the ones that change WHICH resource a row names rather than
// merely how it is spelled — the path is concatenated after the domain to form the
// catalog URI, so a missing leading slash, a query or fragment delimiter,
// whitespace or a control byte each re-point the row.
func TestResourcePathPatternMembership(t *testing.T) {
	fields := findFieldsWithPattern(t, resourcePathPattern)
	if len(fields) != wantResourcePathFields {
		t.Fatalf("the resource-path pattern is on %d fields, expected %d — a copy drifted, or a "+
			"new path field was added without it. If that was deliberate, update "+
			"wantResourcePathFields; if the pattern itself was edited, update "+
			"resourcePathPattern here AND the copy in conformance/corpusgen (its killer "+
			"table is keyed by the pattern string, so a stale key emits nothing).\nFields: %s",
			len(fields), wantResourcePathFields, fieldNames(fields))
	}
	for _, df := range fields {
		name := string(df.msg.Name()) + "." + string(df.fd.Name())
		for _, bad := range []string{"x", "/a?b", "/a#b", "/a b", "/a\x7f", ""} {
			if validateDomainValue(t, df, bad) {
				t.Errorf("%s accepted %q — a value that re-points the catalog URI rather than "+
					"naming the resource the publisher meant", name, bad)
			}
		}
		if !validateDomainValue(t, df, "/premium/article-42.html") {
			t.Errorf("%s refused a well-formed absolute path", name)
		}
	}
}

// domainField is one field carrying the shared constraint.
type domainField struct {
	msg      protoreflect.MessageDescriptor
	fd       protoreflect.FieldDescriptor
	repeated bool
}

// findDomainFields walks the contract for every field whose protovalidate rule
// is the shared domain pattern, on the singular string form and on the
// repeated-item form.
func findDomainFields(t *testing.T) []domainField {
	t.Helper()
	return findFieldsWithPattern(t, sharedDomainPattern)
}

// findFieldsWithPattern walks the contract for every field whose protovalidate
// rule carries the given pattern, on the singular string form and on the
// repeated-item form.
func findFieldsWithPattern(t *testing.T, pattern string) []domainField {
	t.Helper()
	var out []domainField
	EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			rules, has := fieldRules(fd)
			if !has {
				continue
			}
			if s := rules.GetString(); s != nil && s.GetPattern() == pattern {
				out = append(out, domainField{md, fd, false})
				continue
			}
			if r := rules.GetRepeated(); r != nil && r.GetItems() != nil {
				if s := r.GetItems().GetString(); s != nil && s.GetPattern() == pattern {
					out = append(out, domainField{md, fd, true})
				}
			}
		}
	})
	return out
}

// fieldRules reads a field's protovalidate rules through the library's own
// resolver rather than pulling the extension by hand — the same call the three
// generators in this package already make, so a change in how rules are carried
// (a predefined rule, say) reaches this guard without a second implementation to
// remember.
func fieldRules(fd protoreflect.FieldDescriptor) (*validate.FieldRules, bool) {
	fr, err := protovalidate.ResolveFieldRules(fd)
	return fr, err == nil && fr != nil
}

// messageWith returns a fresh instance of the field's message carrying v in that
// field and nothing else. Both guards need exactly this, and a second copy is a
// second place for the repeated/singular distinction to be got wrong.
func messageWith(t *testing.T, df domainField, v string) proto.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(df.msg.FullName())
	if err != nil {
		t.Fatalf("FindMessageByName %s: %v", df.msg.FullName(), err)
	}
	m := mt.New()
	if df.repeated {
		m.Mutable(df.fd).List().Append(protoreflect.ValueOfString(v))
	} else {
		m.Set(df.fd, protoreflect.ValueOfString(v))
	}
	return m.Interface()
}

// validateDomainValue sets v on the field and reports whether the pattern rule
// accepted it — i.e. whether string.pattern or string.max_len fired. Other rules
// on the same message are ignored on purpose: the question is what the FIELD's
// own shape rule said, not whether the whole instance is valid.
func validateDomainValue(t *testing.T, df domainField, v string) bool {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(df.msg.FullName())
	if err != nil {
		t.Fatalf("FindMessageByName %s: %v", df.msg.FullName(), err)
	}
	val, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	m := mt.New()
	if df.repeated {
		m.Mutable(df.fd).List().Append(protoreflect.ValueOfString(v))
	} else {
		m.Set(df.fd, protoreflect.ValueOfString(v))
	}
	verr, isVE := val.Validate(m.Interface()).(*protovalidate.ValidationError)
	if !isVE {
		return true
	}
	// Only violations ON THIS FIELD count. A sibling field's rule firing — a
	// required recipient left unset on the same message, say — says nothing about
	// whether the value under test was admitted, and treating it as a verdict
	// would make this helper report the opposite of the truth.
	return !fieldViolatedShape(verr, df.fd)
}

// fieldViolatedShape reports whether the given field was rejected by its own
// shape rule (pattern or max_len), ignoring every other field's violations.
//
// Matching is on the violation's field PATH rather than its FieldDescriptor,
// because for a repeated field's item the descriptor is nil and the field is
// named only in the path (with the item's index appended). Reading the
// descriptor alone would silently classify every list-item refusal as "some
// other field's problem".
func fieldViolatedShape(verr *protovalidate.ValidationError, fd protoreflect.FieldDescriptor) bool {
	for _, v := range verr.Violations {
		switch v.Proto.GetRuleId() {
		case "string.pattern", "string.max_len":
		default:
			continue
		}
		if els := v.Proto.GetField().GetElements(); len(els) > 0 {
			if els[0].GetFieldName() == string(fd.Name()) {
				return true
			}
			continue
		}
		if v.FieldDescriptor != nil && v.FieldDescriptor.FullName() == fd.FullName() {
			return true
		}
	}
	return false
}

// TestSharedDomainConstraintRejectsMalformedValues is the acceptance guard for
// the recipient-host shape: on EVERY field carrying the shared constraint, a
// scheme prefix, a path or query suffix, and a bad port are rejected — and the
// rejection names string.pattern, so the case cannot pass because some unrelated
// rule happened to fire.
func TestSharedDomainConstraintRejectsMalformedValues(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	fields := findDomainFields(t)
	// An EXACT count, not a floor. A floor below the real number lets a field
	// silently lose the constraint — the failure this guard exists to catch —
	// while the suite stays green. Adding a domain-valued field is meant to
	// require touching this number, so the addition gets a moment's thought
	// about whether it belongs to the family.
	if len(fields) != wantDomainFields {
		t.Fatalf("the shared domain constraint is on %d fields, expected %d.\n"+
			"A field gained or lost it — if that was deliberate, update wantDomainFields; "+
			"if the pattern itself was edited, update sharedDomainPattern too.\nFields: %s",
			len(fields), wantDomainFields, fieldNames(fields))
	}
	for _, df := range fields {
		name := fmt.Sprintf("%s.%s", df.msg.Name(), df.fd.Name())
		for _, bad := range malformedDomains {
			t.Run(name+"/"+bad.name, func(t *testing.T) {
				err := v.Validate(messageWith(t, df, bad.value))
				var verr *protovalidate.ValidationError
				if !errors.As(err, &verr) {
					// Three-way, like the validation cases: a nil error means the
					// value was accepted, and a NON-validation error means the
					// validator itself failed — swallowing that would let a CEL
					// compile error read as a passing subtest.
					if err != nil {
						t.Fatalf("%s = %q: validator error: %v", name, bad.value, err)
					}
					t.Fatalf("%s = %q must be rejected, but validation passed", name, bad.value)
				}
				// Scoped to THIS field: a sibling's rule firing on the same
				// bare message would otherwise let the case pass without the
				// value under test being refused at all.
				if !fieldViolatedShape(verr, df.fd) {
					t.Errorf("%s = %q was rejected, but not by its own string.pattern (got %v) — "+
						"the case would pass for the wrong reason", name, bad.value, violationIDs(verr))
				}
			})
		}
	}
}

// TestSharedDomainConstraintAcceptsRealHosts pins the other side of the boundary.
// The permissive shapes are deliberate: single-label service hosts are what real
// deployments use (a three-Exchange compose stack addresses "exchange:8081"), and
// a rule demanding a dotted name with an alphabetic suffix would reject them.
func TestSharedDomainConstraintAcceptsRealHosts(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	good := []string{
		"exchange.example",
		"exchange.example:8081",
		"exchange",        // single-label service host
		"exchange-b:8081", // compose service name with a port
		"sub.example.com:443",
		"xn--80ak6aa92e.com", // punycode: interior double hyphen
		"Exchange.Example",   // case is normalised by the reader, not refused here
		"1.2.3.4",
	}
	for _, df := range findDomainFields(t) {
		name := fmt.Sprintf("%s.%s", df.msg.Name(), df.fd.Name())
		for _, ok := range good {
			t.Run(name+"/"+strings.ReplaceAll(ok, ".", "_"), func(t *testing.T) {
				err := v.Validate(messageWith(t, df, ok))
				var verr *protovalidate.ValidationError
				if err != nil && !errors.As(err, &verr) {
					t.Fatalf("%s = %q: validator error: %v", name, ok, err)
				}
				if verr != nil && fieldViolatedShape(verr, df.fd) {
					t.Errorf("%s = %q must be accepted by the domain pattern, but its own shape rule fired", name, ok)
				}
			})
		}
	}
}
