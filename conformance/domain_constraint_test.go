package conformance

import (
	"fmt"
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
const sharedDomainPattern = `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:[0-9]{1,5})?$`

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
	var out []domainField
	EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			rules, has := fieldRules(fd)
			if !has {
				continue
			}
			if s := rules.GetString(); s != nil && s.GetPattern() == sharedDomainPattern {
				out = append(out, domainField{md, fd, false})
				continue
			}
			if r := rules.GetRepeated(); r != nil && r.GetItems() != nil {
				if s := r.GetItems().GetString(); s != nil && s.GetPattern() == sharedDomainPattern {
					out = append(out, domainField{md, fd, true})
				}
			}
		}
	})
	return out
}

func fieldRules(fd protoreflect.FieldDescriptor) (*validate.FieldRules, bool) {
	opts := fd.Options()
	if opts == nil || !proto.HasExtension(opts, validate.E_Field) {
		return nil, false
	}
	fr, _ := proto.GetExtension(opts, validate.E_Field).(*validate.FieldRules)
	return fr, fr != nil
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
	// Anti-vacuity: a refactor that renamed the pattern out from under this test
	// would otherwise leave it green over an empty set.
	if len(fields) < 15 {
		t.Fatalf("expected the shared domain constraint on at least 15 fields, found %d — "+
			"if the pattern was edited, update sharedDomainPattern to match the proto", len(fields))
	}
	for _, df := range fields {
		name := fmt.Sprintf("%s.%s", df.msg.Name(), df.fd.Name())
		for _, bad := range malformedDomains {
			t.Run(name+"/"+bad.name, func(t *testing.T) {
				mt, err := protoregistry.GlobalTypes.FindMessageByName(df.msg.FullName())
				if err != nil {
					t.Fatalf("FindMessageByName %s: %v", df.msg.FullName(), err)
				}
				m := mt.New()
				if df.repeated {
					l := m.Mutable(df.fd).List()
					l.Append(protoreflect.ValueOfString(bad.value))
				} else {
					m.Set(df.fd, protoreflect.ValueOfString(bad.value))
				}
				err = v.Validate(m.Interface())
				verr, ok := err.(*protovalidate.ValidationError)
				if !ok {
					t.Fatalf("%s = %q must be rejected, but validation passed", name, bad.value)
				}
				if !violationsContain(verr, "string.pattern") {
					t.Errorf("%s = %q was rejected, but not by string.pattern (got %v) — "+
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
		"exchange",          // single-label service host
		"exchange-b:8081",   // compose service name with a port
		"sub.example.com:443",
		"xn--80ak6aa92e.com", // punycode: interior double hyphen
		"Exchange.Example",   // case is normalised by the reader, not refused here
		"1.2.3.4",
	}
	for _, df := range findDomainFields(t) {
		name := fmt.Sprintf("%s.%s", df.msg.Name(), df.fd.Name())
		for _, ok := range good {
			t.Run(name+"/"+strings.ReplaceAll(ok, ".", "_"), func(t *testing.T) {
				mt, err := protoregistry.GlobalTypes.FindMessageByName(df.msg.FullName())
				if err != nil {
					t.Fatalf("FindMessageByName: %v", err)
				}
				m := mt.New()
				if df.repeated {
					m.Mutable(df.fd).List().Append(protoreflect.ValueOfString(ok))
				} else {
					m.Set(df.fd, protoreflect.ValueOfString(ok))
				}
				if verr, isVE := v.Validate(m.Interface()).(*protovalidate.ValidationError); isVE {
					if violationsContain(verr, "string.pattern") {
						t.Errorf("%s = %q must be accepted by the domain pattern, but string.pattern fired", name, ok)
					}
				}
			})
		}
	}
}
