package conformance

// Drift guard: the size test inside the one-per-kind rule matches the cap on the
// list it guards.
//
// LicenseTerm.restrictions carries a max_items cap, and the message-level CEL
// license_term.one_restriction_per_kind leads with a size test against the same
// number. The duplication is unavoidable — CEL cannot read a sibling field's rules —
// so it is held here instead.
//
// Why the test is inside the rule at all: the predicate compares the list against
// itself, and neither the cap nor the defined-only enum bounds it. protovalidate
// collects every violation rather than short-circuiting, so a field rule that fires
// still leaves the message rules to walk the whole oversized list, and an undefined
// enum number stays distinct from every other, so all() never finds the duplicate it
// would stop on. Measured before the size test existed: four thousand restrictions
// cost seventeen seconds to refuse from twenty kilobytes of wire.
//
// Why drift here is a correctness hole and not untidiness. The rule stays SILENT
// above the threshold, on the understanding that the cap already refuses such a
// list. Raise the cap without moving the threshold and the two numbers open a gap:
// a list longer than the threshold but within the new cap skips the duplicate check
// AND passes the cap, so a term carrying two restrictions on one axis is accepted at
// the boundary — the exact authoring error the rule exists to catch. Lower the cap
// below the threshold and the reverse happens: the rule keeps walking lists the cap
// already refuses, which is the cost this test's subject was written to avoid.
//
// Both halves are live descriptor reads, so nothing here restates the contract.

import (
	"regexp"
	"strconv"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	oneRestrictionPerKindID = "license_term.one_restriction_per_kind"
	restrictionsOwner       = "LicenseTerm"
	restrictionsField       = "restrictions"
)

// sizeGuardThreshold matches the leading size test of the guarded expression. It is
// anchored at the start so a size() call appearing later in the predicate — the
// filter's own .size() comparison does — cannot be mistaken for the guard.
var sizeGuardThreshold = regexp.MustCompile(`^this\.` + restrictionsField + `\.size\(\) > (\d+) \|\|`)

// restrictionsMaxItems reads the cap off the field's own rules.
func restrictionsMaxItems(t *testing.T) uint64 {
	t.Helper()
	var (
		found bool
		cap_  uint64
	)
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if string(md.Name()) != restrictionsOwner {
			return
		}
		fd := md.Fields().ByName(restrictionsField)
		if fd == nil {
			return
		}
		fr, err := protovalidate.ResolveFieldRules(fd)
		if err != nil || fr == nil || fr.GetRepeated() == nil {
			return
		}
		cap_, found = fr.GetRepeated().GetMaxItems(), true
	})
	if !found {
		t.Fatalf("%s.%s carries no repeated.max_items — either the field moved or its cap was "+
			"dropped, and the size test in %s now guards nothing",
			restrictionsOwner, restrictionsField, oneRestrictionPerKindID)
	}
	if cap_ == 0 {
		t.Fatalf("%s.%s reports a max_items of 0; this guard would compare against a bound that "+
			"refuses every list", restrictionsOwner, restrictionsField)
	}
	return cap_
}

// oneRestrictionPerKindExpression reads the guarded rule's expression off the message.
func oneRestrictionPerKindExpression(t *testing.T) string {
	t.Helper()
	var expr string
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if string(md.Name()) != restrictionsOwner {
			return
		}
		mr, err := protovalidate.ResolveMessageRules(md)
		if err != nil || mr == nil {
			return
		}
		for _, r := range mr.GetCel() {
			if r.GetId() == oneRestrictionPerKindID {
				expr = r.GetExpression()
			}
		}
	})
	if expr == "" {
		t.Fatalf("no CEL rule %q found on %s — if the rule was renamed or removed, this guard "+
			"asserts nothing and must be retargeted or deleted", oneRestrictionPerKindID, restrictionsOwner)
	}
	return expr
}

func TestOneRestrictionPerKindSizeGuardMatchesTheListCap(t *testing.T) {
	cap_ := restrictionsMaxItems(t)
	expr := oneRestrictionPerKindExpression(t)

	m := sizeGuardThreshold.FindStringSubmatch(expr)
	if m == nil {
		t.Fatalf("the %q expression does not lead with a size test over %s.\n"+
			"Without one the rule is quadratic in a list protovalidate walks in full even when the "+
			"cap fires — twenty kilobytes of wire bought seventeen seconds of CPU before this test "+
			"existed, at a boundary reached before the caller is authenticated.\nExpression: %s",
			oneRestrictionPerKindID, restrictionsField, expr)
	}
	got, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatalf("size-test threshold %q in %q is not a number: %v", m[1], oneRestrictionPerKindID, err)
	}
	if got != cap_ {
		t.Errorf("the size test in %q allows %d but %s.%s caps at %d.\n"+
			"These must be equal. Above the threshold the rule reports nothing, on the understanding "+
			"that the cap refuses the list; a threshold BELOW the cap leaves lists in between "+
			"unchecked for duplicate axes AND accepted, and a threshold ABOVE it spends the "+
			"quadratic walk on lists the cap already refuses.",
			oneRestrictionPerKindID, got, restrictionsOwner, restrictionsField, cap_)
	}
}
