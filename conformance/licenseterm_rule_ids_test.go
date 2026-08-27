package conformance

// Drift guard: the ingest-tier rule ids the SDKs emit share the contract's
// CEL-id namespace without colliding with it.
//
// The license-term checks the SDK runs after canonicalisation — registry
// membership and coherence — are not protovalidate rules, because a CEL
// expression cannot re-list a vocabulary without drifting from it. They are
// still reported to a publisher as rule ids, in the same shape the descriptor's
// CEL ids take: the owning message in snake_case, then the rule. Two guards keep
// that a single namespace. Every SDK id must name a real contract message, so an
// id cannot outlive the message it describes; and no SDK id may equal a CEL id,
// or a client would report one rule under a name the descriptor already gives
// another.
//
// The ids are read out of the committed corpus as DATA, never by importing
// sdk/go — conformance is the guard tier below the SDKs.

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const licenseTermVectors = "../sdk/go/helpers/testdata/licenseterm-vectors.json"

var errNoLicenseTermRules = errors.New(
	"the license-term corpus carries no rule ids — regenerate it with " +
		"RAMP_UPDATE_VECTORS=1 go test ./sdk/go/helpers/ -run TestGenerateLicenseTermVectors")

// sdkLicenseTermRuleIDs collects every rule id the corpus's validate and entry
// lists report, as the set the three SDKs are pinned to.
func sdkLicenseTermRuleIDs(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(licenseTermVectors)
	if err != nil {
		t.Fatalf("read %s: %v", licenseTermVectors, err)
	}
	type finding struct {
		Rule string `json:"rule"`
	}
	var doc struct {
		Validate []struct {
			Violation *finding  `json:"violation"`
			Warnings  []finding `json:"warnings"`
		} `json:"validate"`
		Entry []struct {
			TermRules []string  `json:"term_rules"`
			Warnings  []finding `json:"warnings"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode %s: %v", licenseTermVectors, err)
	}
	ids := map[string]bool{}
	for _, v := range doc.Validate {
		if v.Violation != nil {
			ids[v.Violation.Rule] = true
		}
		for _, w := range v.Warnings {
			ids[w.Rule] = true
		}
	}
	for _, e := range doc.Entry {
		for _, r := range e.TermRules {
			ids[r] = true
		}
		for _, w := range e.Warnings {
			ids[w.Rule] = true
		}
	}
	if len(ids) == 0 {
		t.Fatal(errNoLicenseTermRules)
	}
	return ids
}

// declaredCELIDs walks the contract descriptor for every CEL id, message-level
// and field-level, the same way the prefix invariant does.
func declaredCELIDs() map[string]bool {
	ids := map[string]bool{}
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if mr, err := protovalidate.ResolveMessageRules(md); err == nil && mr != nil {
			for _, r := range mr.GetCel() {
				ids[r.GetId()] = true
			}
		}
		for j := 0; j < md.Fields().Len(); j++ {
			if fr, err := protovalidate.ResolveFieldRules(md.Fields().Get(j)); err == nil && fr != nil {
				for _, r := range fr.GetCel() {
					ids[r.GetId()] = true
				}
			}
		}
	})
	return ids
}

var snakeMessageID = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestLicenseTermRuleIDsShareTheCELNamespaceWithoutColliding(t *testing.T) {
	sdkIDs := sdkLicenseTermRuleIDs(t)
	celIDs := declaredCELIDs()
	if len(celIDs) == 0 {
		t.Fatal("no CEL ids found in the contract — the descriptor walk drifted and this guard would assert nothing")
	}
	messages := map[string]bool{}
	EachMessage(func(md protoreflect.MessageDescriptor) {
		messages[messageSnake(string(md.Name()))] = true
	})
	for id := range sdkIDs {
		owner, _, ok := strings.Cut(id, ".")
		if !ok || !snakeMessageID.MatchString(owner) {
			t.Errorf("SDK rule id %q does not start with a snake_case message segment", id)
			continue
		}
		if !messages[owner] {
			t.Errorf("SDK rule id %q names %q, which is not a contract message — an id must not outlive the message it describes", id, owner)
		}
		if celIDs[id] {
			t.Errorf("SDK rule id %q is also a descriptor CEL id — one name for two rules", id)
		}
	}
}
