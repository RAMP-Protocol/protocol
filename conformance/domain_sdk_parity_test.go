package conformance

// Drift guard: the domain rule the SDK ships IS the domain rule on the wire.
//
// The bare-domain shape now exists twice — as the protovalidate pattern on every
// domain-valued field of the contract, and as the constant the three SDKs export
// so a client can refuse a bad value before sending it. The whole point of the
// second copy is that a value the SDK accepts is one the wire accepts, which
// holds only while the two are byte-identical. Nothing made them so; they were
// kept aligned by whoever remembered.
//
// That failed exactly once already, and quietly. When the shared constraint was
// first stamped on the fields, its port group was written as a real 1-65535
// range while the SDK's copy said "one to five digits". The SDK therefore
// accepted :0, :012, :0443, :00443, :65536 and :99999 — values the wire refuses —
// which inverts the property the client-side check exists to provide. Every
// suite in every language passed, because none of them compares the two. It was
// found by reading both regexes side by side.
//
// Division of labour with the neighbouring guard in domain_constraint_test.go:
// that one owns MEMBERSHIP — which fields carry the rule, that they all carry the
// SAME rule, and an exact-count ratchet so a new domain-valued field cannot skip
// it. This one owns AGREEMENT with the SDK, and nothing else. It leans on that
// membership check for its field set, so if the two ever disagree about the
// contract's shape, the neighbour fails first and more precisely.
//
// The proto is authoritative. On failure the wire has not moved to meet the SDK;
// the SDK must be brought to the proto's bytes and its vectors regenerated.
//
// The expected values are READ from the SDK's committed vectors rather than
// restated here, for the reason ver_field_contract_test.go gives at length: this
// package cannot import sdk/go — nothing in conformance depends on sdk/, by
// design, since it is the guard tier BELOW the SDKs. A committed file generated
// from the real Go constants, and already replayed by the Python and TypeScript
// parity suites, is a data read exactly like the corpus and the doc scans.

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
)

// audienceVectors is the committed cross-language oracle for the bare-domain
// rule, emitted from the real Go constants by the sdk/go/helpers vector
// generator. Read as data (see the file header on why this is not an import).
const audienceVectors = "../sdk/go/helpers/testdata/audience-vectors.json"

// sdkDomainRule is the shape the SDK ships, as recorded in the vectors.
type sdkDomainRule struct {
	Pattern string `json:"bare_domain_pattern"`
	MaxLen  uint64 `json:"bare_domain_max_len"`
}

// sdkRule reads the SDK's copy of the rule from the committed vectors. Errors are
// fatal rather than skipped: a missing file or a missing key means this guard has
// lost its anchor, and passing silently would be worse than failing.
var sdkRule = sync.OnceValues(func() (sdkDomainRule, error) {
	b, err := os.ReadFile(audienceVectors)
	if err != nil {
		return sdkDomainRule{}, err
	}
	var doc sdkDomainRule
	if err := json.Unmarshal(b, &doc); err != nil {
		return sdkDomainRule{}, err
	}
	if doc.Pattern == "" || doc.MaxLen == 0 {
		return sdkDomainRule{}, errNoSDKDomainRule
	}
	return doc, nil
})

var errNoSDKDomainRule = errors.New(
	audienceVectors + " carries no bare_domain_pattern / bare_domain_max_len — this guard reads the SDK's copy of the domain rule from there")

// stringRules returns the field's string rules, reaching through the repeated
// wrapper when the field is a list. The singular/repeated split is the same one
// the membership guard makes; going through domainField.repeated keeps the two
// reading the descriptor the same way.
func stringRules(t *testing.T, df domainField) *validate.StringRules {
	t.Helper()
	rules, has := fieldRules(df.fd)
	if !has {
		t.Fatalf("%s.%s: protovalidate rules vanished between the two guards", df.msg.Name(), df.fd.Name())
	}
	if df.repeated {
		return rules.GetRepeated().GetItems().GetString()
	}
	return rules.GetString()
}

// TestSDKBareDomainRuleMatchesTheWire is the gate the two copies of the rule were
// missing. A failure means a value one side accepts the other refuses.
func TestSDKBareDomainRuleMatchesTheWire(t *testing.T) {
	want, err := sdkRule()
	if err != nil {
		t.Fatalf("read the SDK's domain rule: %v", err)
	}
	fields := findDomainFields(t)
	// Guard the guard: an empty set would make every assertion below vacuous, and
	// the failure would look like a pass.
	if len(fields) == 0 {
		t.Fatal("no field carries the shared domain constraint — this guard would assert nothing")
	}
	for _, df := range fields {
		name := string(df.msg.Name()) + "." + string(df.fd.Name())
		s := stringRules(t, df)
		if got := s.GetPattern(); got != want.Pattern {
			t.Errorf("%s: the wire and the SDK disagree about the domain pattern.\n"+
				"  wire (authoritative): %s\n"+
				"  SDK  (%s): %s\n"+
				"Bring the SDK to the wire's bytes and regenerate its vectors.",
				name, got, audienceVectors, want.Pattern)
		}
		if got := s.GetMaxLen(); got != want.MaxLen {
			t.Errorf("%s: the wire and the SDK disagree about the domain length bound.\n"+
				"  wire (authoritative): max_len = %d\n"+
				"  SDK  (%s): %d",
				name, got, audienceVectors, want.MaxLen)
		}
	}
}
