package conformance

// Drift guard: the domain rule the SDK ships IS the domain rule on the wire.
//
// The bare-domain shape now exists twice — as the protovalidate pattern on the
// contract's recipient-addressing fields (not on every field that happens to hold
// a domain; several deliberately carry no rule), and as the constant the three
// SDKs export so a client can refuse a bad value before sending it. The point of the
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
// SAME pattern, and a count that catches a field LOSING it. Note what that count
// does not do: a newly added field that never carried the rule leaves the total
// where it was, so neither guard notices. This one owns AGREEMENT with the SDK,
// and nothing else.
//
// The two halves of that agreement are not equally direct, and it is worth saying
// which is which. The max_len comparison is a live descriptor read: nothing else
// in the package pins that number, so a rule whose bound moved is caught here and
// only here. The pattern comparison is one step removed — findDomainFields selects
// fields BY equality to the neighbour's sharedDomainPattern literal, so what this
// file really compares is the SDK's copy against that literal. The chain still
// closes, because the neighbour pins the descriptor to the same literal and an
// edit to it that no field carries empties the set and trips the fatal below. But
// a failure here names the conformance package's literal, not a byte read from the
// descriptor in this function.
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
//
// Resolution goes through contract.go's FieldRules, the one resolver every
// generator and guard in this package shares. It also fixes the error policy
// this guard was written with: the local helper it used to call read a RESOLVER
// ERROR as "no rules", which would report the rules as vanished — a confusing
// diagnosis of a resolver problem. FieldRules panics on that case and returns
// nil only for a genuinely unruled field.
func stringRules(t *testing.T, df domainField) *validate.StringRules {
	t.Helper()
	rules := FieldRules(df.fd)
	if rules == nil {
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
				"  contract (authoritative, via the shared literal): %s\n"+
				"  SDK      (%s): %s\n"+
				"Bring the SDK to the contract's bytes and regenerate its vectors.",
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
