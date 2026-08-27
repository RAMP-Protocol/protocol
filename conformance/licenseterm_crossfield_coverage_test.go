package conformance

// Drift guard: every cross-field rule an entry can reach has a vector that
// isolates it.
//
// The two JSON ports cannot compose a message-level CEL rule the way protovalidate
// does — their generated schemas are field-level and their cross-field refinements
// attach per message — so each hand-enumerates the sites reachable from a
// ResourceEntry and walks them. A hand-written walk has exactly one failure mode:
// it stops reaching somewhere. That failure is silent unless a vector isolates the
// rule at the site that was dropped, because a per-entry verdict that already has
// another violation stays false either way.
//
// This is the guard that makes the corpus's case list an obligation rather than a
// sample. It reads the vector file as DATA — conformance is the tier below the
// SDKs and imports nothing from them — and derives the obligation from the
// descriptor, so adding a message-level CEL rule to any message an entry reaches
// fails here until a vector covers it.

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// entryReachableRoot is the message a publisher pushes. Every message reachable
// from it by field traversal is a site the ports' walks must reach.
const entryReachableRoot = "ResourceEntry"

// crossFieldRulesReachableFromEntry returns every message-level CEL id declared on
// a message reachable from ResourceEntry, mapped to the message that declares it.
// Reachability is computed here rather than listed, so a new field that introduces
// a new message brings its rules into the obligation automatically.
func crossFieldRulesReachableFromEntry(t *testing.T) map[string]string {
	t.Helper()

	var root protoreflect.MessageDescriptor
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if string(md.Name()) == entryReachableRoot {
			root = md
		}
	})
	if root == nil {
		t.Fatalf("%s is not in the contract — this guard is looking for the wrong root "+
			"and would assert nothing", entryReachableRoot)
	}

	rules := map[string]string{}
	seen := map[protoreflect.FullName]bool{}
	var walk func(protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		if opts, ok := md.Options().(proto.Message); ok && proto.HasExtension(opts, validate.E_Message) {
			mr, _ := proto.GetExtension(opts, validate.E_Message).(*validate.MessageRules)
			for _, c := range mr.GetCel() {
				rules[c.GetId()] = string(md.Name())
			}
		}
		for i := 0; i < md.Fields().Len(); i++ {
			if sub := md.Fields().Get(i).Message(); sub != nil {
				walk(sub)
			}
		}
	}
	walk(root)

	if len(rules) == 0 {
		t.Fatalf("no message-level CEL rules are reachable from %s — the walk above is "+
			"broken and this guard would pass on an empty obligation", entryReachableRoot)
	}
	return rules
}

// coveredCrossFieldRules reads the ids the committed entry vectors record.
func coveredCrossFieldRules(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(licenseTermVectors)
	if err != nil {
		t.Fatalf("read %s: %v", licenseTermVectors, err)
	}
	var doc struct {
		Entry []struct {
			Name            string   `json:"name"`
			CrossFieldRules []string `json:"cross_field_rules"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode %s: %v", licenseTermVectors, err)
	}
	if len(doc.Entry) == 0 {
		t.Fatalf("%s carries no entry vectors — this guard would pass vacuously", licenseTermVectors)
	}
	covered := map[string]bool{}
	for _, e := range doc.Entry {
		for _, id := range e.CrossFieldRules {
			covered[id] = true
		}
	}
	return covered
}

func TestEveryReachableCrossFieldRuleHasAnEntryVector(t *testing.T) {
	reachable := crossFieldRulesReachableFromEntry(t)
	covered := coveredCrossFieldRules(t)

	var missing []string
	for id, msg := range reachable {
		if !covered[id] {
			missing = append(missing, id+" (on "+msg+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d cross-field rule(s) reachable from %s have no entry vector isolating them:\n  %s\n"+
			"A port walks to each of these messages by hand. Without a vector that makes one of them "+
			"the entry's ONLY violation, a walk that stops reaching that message keeps every suite "+
			"green. Add a case to buildLTEntryVectors carrying exactly this one violation and "+
			"regenerate with RAMP_UPDATE_VECTORS=1.",
			len(missing), entryReachableRoot, strings.Join(missing, "\n  "))
	}

	// The other direction: a recorded id that is no longer reachable is a vector
	// pinning a rule the contract has moved or dropped.
	for id := range covered {
		if _, ok := reachable[id]; !ok {
			t.Errorf("the entry vectors record %q, which is not reachable from %s — the rule moved "+
				"or was removed, and the case now pins nothing", id, entryReachableRoot)
		}
	}
}
