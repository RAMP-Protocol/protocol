// Package conformance — contract.go is the SINGLE source of "which proto packages make
// up the wire contract" AND of how a field's protovalidate rules are resolved. Every
// descriptor-walking guard and every generator iterates this list, so adding the next
// contract package is one entry here and nothing else.
//
// This is the only non-test file in the package, and that is deliberate: the corpus and
// required/unique manifest generators are `package main` under conformance/*/ and cannot
// import a _test.go file. Before this existed, each of them re-hardcoded the same two
// walk() calls, so a new package was covered only where someone remembered to add it —
// the exact opt-in failure mode descriptor_invariants_test.go's header warns about. The
// rule-resolution helpers below exist for the same reason one level down: every caller
// walked the fields itself and decided on its own what a RESOLVER ERROR means, and
// several decided "no rules", which silently disarms the guard doing the asking.
//
// The rule-SHAPE helpers exist for the same reason one level down again: every caller
// also decided on its own what a rule looks like. "Does this field carry a bytes length
// rule" was read four ways (by value, by presence, and two different mixes), and the
// fail-closed guards read only the top-level rule oneof, so a repeated.items.* rule
// walked past them. One accessor and one two-level sweep, both here.
//
// Note wire_naming_test.go deliberately does NOT walk descriptors: it reads the committed
// corpus JSON, which already covers every package walked here.
package conformance

import (
	"fmt"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// ContractFile is one proto package of the wire contract: its descriptor, its package
// name (the corpus and doc markers carry BARE message names, resolved against these in
// order), and the website reference page that must document every symbol it defines.
type ContractFile struct {
	Package string
	File    protoreflect.FileDescriptor
	// RefPage is the doc-coverage reference page, relative to the conformance/ directory
	// (where `go test ./conformance` runs).
	RefPage string
}

// Contract is the wire contract, in bare-name resolution order.
var Contract = []ContractFile{
	{
		Package: "ramp.v1",
		File:    rampv1.File_ramp_v1_ramp_proto,
		RefPage: "../website/src/content/docs/reference/proto-ramp.mdx",
	},
	{
		Package: "ramp.admin.v1",
		File:    rampadminv1.File_ramp_admin_v1_admin_proto,
		RefPage: "../website/src/content/docs/reference/proto-admin.mdx",
	},
}

// ContractPackages returns the contract package names in resolution order.
func ContractPackages() []string {
	out := make([]string, 0, len(Contract))
	for _, c := range Contract {
		out = append(out, c.Package)
	}
	return out
}

// ContractFiles returns the contract file descriptors in resolution order.
func ContractFiles() []protoreflect.FileDescriptor {
	out := make([]protoreflect.FileDescriptor, 0, len(Contract))
	for _, c := range Contract {
		out = append(out, c.File)
	}
	return out
}

// EachMessage visits every message of every contract file, including nested messages,
// and skipping synthetic map-entry messages (they carry no rules, no docs, and no
// corpus representation).
func EachMessage(fn func(protoreflect.MessageDescriptor)) {
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
	for _, f := range Contract {
		walk(f.File.Messages())
	}
}

// FieldRules resolves fd's protovalidate field rules, returning nil when fd carries
// none.
//
// It exists to own ONE decision: a resolver error is not "no rules". Swallowing it
// disarms whatever the caller was going to do with the rules — the corpus loses every
// case for the field, a manifest loses its entry, a coverage guard stops requiring
// anything — and the build stays green, which is the failure mode this whole package
// is built to prevent. So the policy is to panic: a `package main` generator dies with
// a non-zero exit, a test fails with the message. Both are the fail-closed direction.
//
// Callers that need the rules of one specific field (not a whole walk) use this
// directly; callers that walk the contract use EachRuledField.
func FieldRules(fd protoreflect.FieldDescriptor) *validate.FieldRules {
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil {
		panic(fmt.Sprintf("conformance: resolving protovalidate rules for field %s: %v — a resolver error is not 'no rules'", fd.FullName(), err))
	}
	return fr
}

// EachRuledField visits every field carrying protovalidate field rules, across every
// message EachMessage walks, in descriptor order. Fields with no rules are skipped; a
// resolver error panics (see FieldRules).
//
// This is the walk every generator and rule-shaped guard wants. Hand-rolling it means
// re-deciding the error policy each time, which is how the class-6 corpus coverage
// guard came to treat an unresolvable field as unruled.
func EachRuledField(fn func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, fr *validate.FieldRules)) {
	EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if fr := FieldRules(fd); fr != nil {
				fn(md, fd, fr)
			}
		}
	})
}

// ── rule-shape inspection ────────────────────────────────────────────────────
//
// The helpers below own the two questions every generator and rule-shaped guard
// asks about a rule set, so the repo has ONE answer to each:
//
//   - "does this field carry a bytes length rule, and which one" (BytesLength)
//   - "does this rule set carry a string byte-length rule" (StringByteLength)
//
// Before this, the first question was read four different ways — by value in one
// generator, by presence in another, by a mix of both in two more — so the same
// field could be ruled for one consumer and unruled for the next.

// RuleSet is one level of a field's protovalidate rules: the field's own rules,
// or the per-item rules of a repeated field. Prefix names the level for
// diagnostics — "" for the field's own rules, "repeated.items." for item rules —
// so a message can say WHERE it found the rule.
type RuleSet struct {
	Prefix string
	Rules  *validate.FieldRules
}

// RuleSets returns fr's rule levels in sweep order: the field's own rules first,
// then its repeated.items rules when the field declares them.
//
// A guard that reads only the top-level rule oneof walks straight past
// repeated.items.<kind>.<member>. That shape is already used by the contract
// (admin.proto ListRequest.filters and five sites in ramp.proto), so such a guard
// is open on every repeated field while looking fail-closed. Anything asking
// "does the contract carry rule X anywhere" must go through this.
//
// It is a plain function over a FieldRules, not part of the descriptor walk, so a
// test can feed it a synthetic rule set and prove the descent still happens.
func RuleSets(fr *validate.FieldRules) []RuleSet {
	if fr == nil {
		return nil
	}
	out := []RuleSet{{Prefix: "", Rules: fr}}
	if it := fr.GetRepeated().GetItems(); it != nil {
		out = append(out, RuleSet{Prefix: "repeated.items.", Rules: it})
	}
	return out
}

// EachRuleSet is EachRuledField descended one level: it visits every ruled
// field's own rules AND its repeated.items rules, in descriptor order. Use it
// for any contract-wide "is rule X present" sweep; use EachRuledField only when
// the question is genuinely about the field's own top-level rules.
func EachRuleSet(fn func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, prefix string, fr *validate.FieldRules)) {
	EachRuledField(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, fr *validate.FieldRules) {
		for _, rs := range RuleSets(fr) {
			fn(md, fd, rs.Prefix, rs.Rules)
		}
	})
}

// BytesLengthRule names one bytes length rule: Kind is "len" (an exact length)
// or "min_len" (a floor), and Value is the declared byte count.
type BytesLengthRule struct {
	Kind  string
	Value uint64
}

// BytesLength reads the bytes length rule fr declares, returning nil when it
// declares none. This is the ONLY reading of "does this carry a bytes length
// rule" in the repo — see the four divergent readings this replaced.
//
// The reading is by PRESENCE, not by value, and the two shapes that would make
// presence and value disagree are errors rather than results:
//
//  1. len AND min_len both set. Every consumer carries one length kind per field
//     (the bytes_len.json manifest, the corpus mutants, the coverage guard), so
//     one of the two rules would be dropped silently.
//  2. A zero value (len:0 / min_len:0). It constrains nothing, so a value-reading
//     consumer treats the field as unruled while a presence-reading one enters it
//     into the manifest. It is a contract error, not a rule.
//
// With both rejected, presence and value cannot disagree, so every consumer sees
// the same set of ruled fields. Callers inside a generator use MustBytesLength,
// which applies the package's fail-closed panic policy; the invariant test in
// descriptor_invariants_test.go calls this one so it can report the field name
// instead of aborting the test binary.
func BytesLength(fr *validate.FieldRules) (*BytesLengthRule, error) {
	b := fr.GetBytes()
	if b == nil {
		return nil, nil
	}
	if b.Len != nil && b.MinLen != nil {
		return nil, fmt.Errorf("carries BOTH bytes.len:%d and bytes.min_len:%d — every consumer holds one length kind per field, so one of the two would be enforced and the other silently dropped; express the intent as a single rule",
			b.GetLen(), b.GetMinLen())
	}
	if b.Len != nil {
		if b.GetLen() == 0 {
			return nil, fmt.Errorf("carries bytes.len:0 — an explicit zero length constrains nothing, so it is a contract error, not a rule")
		}
		return &BytesLengthRule{Kind: "len", Value: b.GetLen()}, nil
	}
	if b.MinLen != nil {
		if b.GetMinLen() == 0 {
			return nil, fmt.Errorf("carries bytes.min_len:0 — an explicit zero floor constrains nothing, so it is a contract error, not a rule")
		}
		return &BytesLengthRule{Kind: "min_len", Value: b.GetMinLen()}, nil
	}
	return nil, nil
}

// MustBytesLength is BytesLength with this package's fail-closed error policy:
// an ill-formed length rule stops the generator (non-zero exit) or fails the test
// rather than being read as "no length rule". fd only names the offender.
func MustBytesLength(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) *BytesLengthRule {
	r, err := BytesLength(fr)
	if err != nil {
		panic(fmt.Sprintf("conformance: field %s %v", fd.FullName(), err))
	}
	return r
}

// StringByteLength reports the string byte-length rule fr declares — the member
// name ("min_bytes" or "max_bytes") and its value — or ok=false when it declares
// none.
//
// It is shared because it is a fail-closed guard's predicate (requiredgen's
// assertNoStringByteLengthRules) and a guard is only as wide as the sweep it runs
// on: protoschema translates both members into a JSON Schema minLength/maxLength,
// which counts CHARACTERS, so a multibyte value the Go server rejects passes the
// generated Pydantic/Zod. Run it over EachRuleSet, never EachRuledField, or the
// rule can enter the contract as repeated.items.string.max_bytes unseen.
func StringByteLength(fr *validate.FieldRules) (member string, value uint64, ok bool) {
	s := fr.GetString()
	if s == nil {
		return "", 0, false
	}
	if n := s.GetMinBytes(); n > 0 {
		return "min_bytes", n, true
	}
	if n := s.GetMaxBytes(); n > 0 {
		return "max_bytes", n, true
	}
	return "", 0, false
}

// EachEnum calls fn for every enum in the contract — file-level and nested inside
// a message, in every contract package.
//
// It exists because the bare-name scheme treats enums exactly like messages, and
// a walk that visited only messages left half the namespace unguarded. ramp.v1
// was the only package defining enums until ramp.admin.v1 added ObligationState,
// so the gap had no way to bite and no way to be noticed.
func EachEnum(fn func(protoreflect.EnumDescriptor)) {
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			md := ms.Get(i)
			for j := 0; j < md.Enums().Len(); j++ {
				fn(md.Enums().Get(j))
			}
			walk(md.Messages())
		}
	}
	for _, f := range Contract {
		for i := 0; i < f.File.Enums().Len(); i++ {
			fn(f.File.Enums().Get(i))
		}
		walk(f.File.Messages())
	}
}

// AssertUniqueBareNames reports an error when two contract packages define a message
// or an ENUM with the same bare name. The corpus keys cases by bare short name
// (Case.Message == the generated class/schema name), the merged JSON-Schema $defs are
// keyed the same way, and the {/* ramp-validate: X */} doc markers resolve the same way
// — a cross-package duplicate would silently collide in all three. Returned as an error,
// not a fatal, so both a `package main` generator (which exits) and a test (which fails)
// can use it.
//
// ENUMS ARE CHECKED IN THE SAME NAMESPACE AS MESSAGES, not in one of their own,
// because merge_schema.py hoists both into a single $defs map. A message and an
// enum sharing a bare name collide there just as two messages would.
//
// The enum half is the one that fails quietly. merge_schema.py keys enum $defs by
// bare name with setdefault, so the SECOND enum of a colliding pair is dropped and
// every field referring to it silently gets the FIRST enum's value list. Generated
// Pydantic and Zod would then accept values the Go server rejects, with nothing
// failing anywhere in between. A duplicate message name at least collides on a
// structure a reader can see.
func AssertUniqueBareNames() error {
	seen := map[string]protoreflect.FullName{}
	var err error
	claim := func(kind, bare string, full protoreflect.FullName) {
		if prev, ok := seen[bare]; ok && prev != full && err == nil {
			err = fmt.Errorf("duplicate bare %s name %q (%s vs %s) — the corpus/parity bare-name scheme cannot represent it",
				kind, bare, prev, full)
			return
		}
		seen[bare] = full
	}
	EachMessage(func(md protoreflect.MessageDescriptor) {
		claim("message", string(md.Name()), md.FullName())
	})
	EachEnum(func(ed protoreflect.EnumDescriptor) {
		claim("enum", string(ed.Name()), ed.FullName())
	})
	return err
}
