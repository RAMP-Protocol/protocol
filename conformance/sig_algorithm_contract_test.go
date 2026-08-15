// Package conformance — sig_algorithm_contract_test.go ties the pinned
// signature-algorithm labels to the SDK constants that actually write them.
//
// ramp.admin.v1 pins "EdDSA" as a string.const on the evidence row's two
// algorithm fields, so a row whose label says anything else is refused. The
// values that get written come from SDK constants. Nothing connected the two.
//
// THE FAILURE THAT WAS POSSIBLE. Change the SDK constant. Every Go test passes,
// every parity test passes, the corpus regenerates cleanly — and every evidence
// row the Exchange writes from then on is rejected by its own read RPC, because
// the const still says the old value. The break surfaces in production, on the
// forensic plane, at the moment someone needs it.
//
// The const is read from the DESCRIPTOR and the constant from the committed wire
// vector, so neither literal is restated here. A guard that spelled "EdDSA" a
// third time would add a third place to drift.
//
// Reading the SDK side as data rather than importing it is the ver-field guard's
// arrangement, for its reason: nothing in conformance depends on sdk/, because
// this package is the descriptor-level layer BELOW the SDKs. The vector file is
// generated from the real Go constants and is already replayed by the Python and
// TS parity suites, so a change that misses either side goes red.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// sigAlgorithmBindings pairs each pinned contract field with the SDK constant
// that produces its value.
//
// The pairing is the one thing here that must be stated by hand — no descriptor
// or vector says which constant feeds which field. It is a short, closed list
// and the test below fails if either side of a pair stops resolving, so a
// renamed field or a renamed constant is a failure rather than a silent skip.
var sigAlgorithmBindings = []struct {
	message  string // bare contract message name
	field    string // field carrying the string.const
	constant string // vector entry name in wire-constants-vectors.json
}{
	{"TransactionEvidence", "offer_sig_algorithm", "OfferSignatureAlgorithm"},
	{"TransactionEvidence", "agent_acceptance_signature_algorithm", "AcceptanceSignatureAlgorithm"},
}

// wireConstant returns the value of a named entry in the committed wire-constants
// vector. Absence is fatal: a missing entry means this guard lost its anchor, and
// passing silently would be worse than failing.
func wireConstant(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(wireConstantsVectors)
	if err != nil {
		t.Fatalf("read %s: %v", wireConstantsVectors, err)
	}
	var doc struct {
		Vectors []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", wireConstantsVectors, err)
	}
	for _, v := range doc.Vectors {
		if v.Name == name {
			return v.Value
		}
	}
	t.Fatalf("%s carries no %s entry — the SDK constant is not exported to the "+
		"cross-language vector, so this guard cannot compare it against the contract",
		wireConstantsVectors, name)
	return ""
}

// constRule returns the string.const pinned on a contract field, and whether the
// field carries one at all.
func constRule(md protoreflect.MessageDescriptor, field string) (string, bool, error) {
	fd := md.Fields().ByName(protoreflect.Name(field))
	if fd == nil {
		return "", false, fmt.Errorf("message %s has no field %q", md.Name(), field)
	}
	fr := FieldRules(fd)
	s := fr.GetString_()
	if s == nil || s.Const == nil {
		return "", false, nil
	}
	return s.GetConst(), true, nil
}

func TestSignatureAlgorithmConstMatchesSDKConstant(t *testing.T) {
	for _, b := range sigAlgorithmBindings {
		t.Run(b.message+"."+b.field, func(t *testing.T) {
			mt, err := findContractMessage(b.message)
			if err != nil {
				t.Fatalf("resolve %s: %v", b.message, err)
			}
			pinned, ok, err := constRule(mt.Descriptor(), b.field)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("%s.%s carries no string.const — this guard exists because that field "+
					"pins the label an SDK writes; if the pin was removed deliberately, remove the "+
					"binding from sigAlgorithmBindings too", b.message, b.field)
			}

			produced := wireConstant(t, b.constant)
			if pinned != produced {
				t.Errorf("the contract accepts only %q on %s.%s, but the SDK writes %q (constant %s).\n"+
					"Every row written with the SDK value would be refused by the read RPC that validates "+
					"against the const. Change both, or neither.",
					pinned, b.message, b.field, produced, b.constant)
			}
		})
	}
}

// TestEveryPinnedAlgorithmFieldIsBound stops the list above from going stale in
// the direction a hand-maintained list always goes: a new pinned field is added
// and nobody remembers to bind it.
//
// Scope comes from the descriptor. Any contract field whose NAME marks it as an
// algorithm label and which carries a string.const must appear in
// sigAlgorithmBindings — so adding a third one fails until someone says which
// constant produces it.
func TestEveryPinnedAlgorithmFieldIsBound(t *testing.T) {
	bound := map[string]bool{}
	for _, b := range sigAlgorithmBindings {
		bound[b.message+"."+b.field] = true
	}

	var unbound []string
	EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			name := string(fd.Name())
			if !isAlgorithmLabelField(name) {
				continue
			}
			if _, ok, err := constRule(md, name); err != nil || !ok {
				continue // unpinned label fields are a separate question
			}
			key := string(md.Name()) + "." + name
			if !bound[key] {
				unbound = append(unbound, key)
			}
		}
	})

	if len(unbound) > 0 {
		t.Errorf("pinned algorithm-label field(s) with no SDK constant bound: %v\n"+
			"Each one accepts exactly one string. Add it to sigAlgorithmBindings naming the "+
			"constant that writes it, so the two cannot drift apart.", unbound)
	}
}

// isAlgorithmLabelField matches the naming the contract uses for a
// signature-algorithm label. Both spellings are live: ramp.v1 says
// signature_algorithm, and ramp.admin.v1 says sig_algorithm on the field
// neighbouring offer_sig, whose short name it inherits.
func isAlgorithmLabelField(name string) bool {
	return name == "signature_algorithm" ||
		name == "sig_algorithm" ||
		hasSuffix(name, "_signature_algorithm") ||
		hasSuffix(name, "_sig_algorithm")
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
