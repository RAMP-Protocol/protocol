// Package conformance — samerule_test.go is the drift gate for restated rules.
//
// The toolchain forces some rules to be INLINE COPIES: corpusgen and the client
// generators read field-level rules directly, so a rule that ramp.admin.v1
// restates from ramp.v1 (or from another field in the same file) cannot be
// deduplicated at the proto layer — but nothing else keeps the copies equal if
// the source changes. Before this gate, a drifted copy would surface only as
// unexplained parity-corpus differences.
//
// The gate has two halves:
//
//  1. EQUALITY. A field whose leading comment carries the directive
//
//     Same rule as <fully.qualified.package.Message.field>
//
//     declares itself a copy, and this test fails unless the two fields'
//     resolved protovalidate FieldRules are EQUAL (proto.Equal — the
//     byte-for-byte view after option merging).
//
//  2. COMPLETENESS. The set of fields that must declare is derived from the
//     descriptor itself, never from a hand-maintained list (the
//     descriptor_invariants_test.go rule): every scalar/enum/bytes field in a
//     non-root contract package whose resolved rules are byte-identical to
//     another contract field's must be a directive source, a directive target,
//     or carry an entry in sameRuleCoincidences — an explicit "identical by
//     coincidence, not by copy" exemption. The exemption list is itself
//     fail-closed: an entry that no longer names a field, or whose field no
//     longer has a rule twin, fails as stale.
//
// The root contract package (the first in Contract — ramp.v1) is the upstream
// vocabulary restatements are copied FROM; its internal duplicates predate this
// gate and are not enforced. Message-typed fields are skipped: the only rule
// they carry is the required-envelope convention, which is a shape, not a
// restatable value rule.
//
// Comments come from gen/descriptor.binpb (built with source info); rules come
// from the linked-in generated descriptors — the same authoritative
// protovalidate view every other gate uses.
package conformance

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// The directive may wrap across comment lines, so whitespace between its words
// (including the newline+space form descriptor comments carry) is tolerated.
var sameRuleDirective = regexp.MustCompile(`[Ss]ame\s+rule\s+as\s+([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)`)

// sameRuleCoincidences names non-root contract fields whose rules are
// byte-identical to another contract field's by COINCIDENCE, not by copy —
// tying them with a directive would force unrelated fields to move together.
// Every entry must still resolve to a field AND still have a rule twin, or the
// completeness sweep fails it as stale.
var sameRuleCoincidences = map[string]string{
	"ramp.admin.v1.TransactionEvidence.offer_id":       "bare min_len:1 — any-non-empty-string, shared shape with unrelated fields",
	"ramp.admin.v1.TransactionEvidence.offer_json":     "bare min_len:1 — any-non-empty-string, shared shape with unrelated fields",
	"ramp.admin.v1.TransactionState.idempotency_key":   "bare min_len:1 — deliberately unbounded (derived key), not a copy of any bounded rule",
	"ramp.admin.v1.TransactionState.signed_url_hash":   "bytes.len:32 — a sha256 digest; matches the Ed25519 key length by arithmetic accident",
	"ramp.admin.v1.TenantFeeRate.tenant_id":            "the ANCHOR the tenant_id directives point at; itself identical to unrelated {min_len:1,max_len:255} fields",
	"ramp.admin.v1.TransactionEvidence.transaction_id": "the ANCHOR the request's transaction_id directive points at; {min_len:1,max_len:255} matches tenant ids by convention, not by copy",
}

func TestSameRuleDirectivesHoldByteForByte(t *testing.T) {
	directives := collectSameRuleDirectives(t) // field full name -> target full name

	if len(directives) == 0 {
		t.Fatal("no 'Same rule as' directives found in the contract — the gate is wired to nothing (descriptor missing source info?)")
	}

	for src, dst := range directives {
		srcFD, err := findField(src)
		if err != nil {
			t.Errorf("directive source %s: %v", src, err)
			continue
		}
		dstFD, err := findField(dst)
		if err != nil {
			t.Errorf("%s says 'Same rule as %s', which does not resolve to a field: %v", src, dst, err)
			continue
		}
		// Rules equality alone is blind to presence: protovalidate SKIPS an unset
		// presence-tracked field, so `optional string x` and plain `string x`
		// with byte-identical rules still behave differently at runtime (the
		// optional copy accepts omission its source rejects). A directive
		// declares same BEHAVIOR, so the presence mode must match too.
		if srcFD.HasPresence() != dstFD.HasPresence() {
			t.Errorf("restated rule PRESENCE mismatch: %s declares 'Same rule as %s' but HasPresence differs (source %v, target %v) — protovalidate skips an unset presence-tracked field, so the copies diverge at runtime on omission",
				src, dst, srcFD.HasPresence(), dstFD.HasPresence())
		}
		srcRules, err := protovalidate.ResolveFieldRules(srcFD)
		if err != nil {
			t.Errorf("resolving rules for %s: %v", src, err)
			continue
		}
		dstRules, err := protovalidate.ResolveFieldRules(dstFD)
		if err != nil {
			t.Errorf("resolving rules for %s (target of %s's directive): %v", dst, src, err)
			continue
		}
		if srcRules == nil {
			t.Errorf("%s declares 'Same rule as %s' but itself carries no field rules", src, dst)
			continue
		}
		if dstRules == nil {
			t.Errorf("%s says 'Same rule as %s', but the target carries no field rules", src, dst)
			continue
		}
		if !proto.Equal(srcRules, dstRules) {
			t.Errorf("restated rule DRIFTED: %s declares 'Same rule as %s' but the rules differ\n  source: %v\n  target: %v\n(update the copy, or remove the directive if the divergence is now intended)",
				src, dst, srcRules, dstRules)
		}
	}
}

// TestRuleIdenticalGroupsAreDeclared is the completeness half: it derives the
// set of fields that must declare from the descriptor (rule-identical groups)
// instead of trusting authors to opt in. See the file header.
func TestRuleIdenticalGroupsAreDeclared(t *testing.T) {
	directives := collectSameRuleDirectives(t)
	targets := map[string]bool{}
	for _, dst := range directives {
		targets[dst] = true
	}
	rootPkg := ContractPackages()[0]

	// Group every ruled non-message field by its deterministically serialized
	// resolved rules.
	groups := map[string][]string{}
	EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
				continue
			}
			fr, err := protovalidate.ResolveFieldRules(fd)
			if err != nil {
				t.Fatalf("resolving rules for %s: %v", fd.FullName(), err)
			}
			if fr == nil {
				continue
			}
			key, err := proto.MarshalOptions{Deterministic: true}.Marshal(fr)
			if err != nil {
				t.Fatalf("serializing rules for %s: %v", fd.FullName(), err)
			}
			groups[string(key)] = append(groups[string(key)], string(fd.FullName()))
		}
	})

	inTwinGroup := map[string]bool{}
	for _, fields := range groups {
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields {
			inTwinGroup[name] = true
			if strings.HasPrefix(name, rootPkg+".") {
				continue // the root package is the upstream vocabulary, not a restater
			}
			if _, ok := directives[name]; ok {
				continue
			}
			if targets[name] {
				continue
			}
			if _, ok := sameRuleCoincidences[name]; ok {
				continue
			}
			t.Errorf("%s has rules byte-identical to %v but declares nothing — add a 'Same rule as <field>' directive if it is a copy, or a sameRuleCoincidences entry if the match is accidental",
				name, others(fields, name))
		}
	}

	// Exemption hygiene: a coincidence entry must still name a real field that
	// still has a rule twin, or it is stale and hides nothing.
	for name, why := range sameRuleCoincidences {
		if _, err := findField(name); err != nil {
			t.Errorf("stale sameRuleCoincidences entry %s (%s): %v", name, why, err)
			continue
		}
		if !inTwinGroup[name] {
			t.Errorf("stale sameRuleCoincidences entry %s (%s): the field no longer has a rule-identical twin — remove the entry", name, why)
		}
	}
}

func others(fields []string, self string) []string {
	out := make([]string, 0, len(fields)-1)
	for _, f := range fields {
		if f != self {
			out = append(out, f)
		}
	}
	return out
}

func findField(fullName string) (protoreflect.FieldDescriptor, error) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(fullName))
	if err != nil {
		return nil, err
	}
	fd, ok := d.(protoreflect.FieldDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is a %T, not a field", fullName, d)
	}
	return fd, nil
}

// collectSameRuleDirectives scans the leading comments of every field in the
// contract packages (from the committed descriptor, which carries source info)
// and returns source-field -> target-field for each directive found.
func collectSameRuleDirectives(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../gen/descriptor.binpb")
	if err != nil {
		t.Fatalf("read descriptor: %v", err)
	}
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &fds); err != nil {
		t.Fatalf("parse descriptor: %v", err)
	}
	contract := map[string]bool{}
	for _, p := range ContractPackages() {
		contract[p] = true
	}

	out := map[string]string{}
	for _, f := range fds.GetFile() {
		if !contract[f.GetPackage()] {
			continue
		}
		// Index leading comments by source path (the SourceCodeInfo location key).
		comments := map[string]string{}
		for _, loc := range f.GetSourceCodeInfo().GetLocation() {
			if c := loc.GetLeadingComments(); c != "" {
				comments[pathKey(loc.GetPath())] = c
			}
		}
		var walk func(prefix []int32, scope string, msgs []*descriptorpb.DescriptorProto)
		walk = func(prefix []int32, scope string, msgs []*descriptorpb.DescriptorProto) {
			for mi, m := range msgs {
				msgPath := append(append([]int32{}, prefix...), int32(mi))
				msgName := scope + "." + m.GetName()
				for fi, fld := range m.GetField() {
					// field path: <msgPath>, 2 (DescriptorProto.field), fi
					key := pathKey(append(append([]int32{}, msgPath...), 2, int32(fi)))
					if mm := sameRuleDirective.FindStringSubmatch(comments[key]); mm != nil {
						out[msgName+"."+fld.GetName()] = mm[1]
					}
				}
				// nested messages: <msgPath>, 3 (DescriptorProto.nested_type)
				walk(append(append([]int32{}, msgPath...), 3), msgName, m.GetNestedType())
			}
		}
		// top-level messages: 4 (FileDescriptorProto.message_type)
		walk([]int32{4}, f.GetPackage(), f.GetMessageType())
	}
	return out
}

func pathKey(p []int32) string {
	out := make([]byte, 0, len(p)*4)
	for _, v := range p {
		out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return string(out)
}
