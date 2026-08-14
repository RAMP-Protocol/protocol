// Package conformance — samerule_test.go is the drift gate for restated rules.
//
// The toolchain forces some rules to be INLINE COPIES: corpusgen and the client
// generators read field-level rules directly, so a rule that ramp.admin.v1
// restates from ramp.v1 (or from another field in the same file) cannot be
// deduplicated at the proto layer — but nothing else keeps the copies equal if
// the source changes. Before this gate, a drifted copy would surface only as
// unexplained parity-corpus differences.
//
// The mechanism: a field whose leading comment carries the directive
//
//	Same rule as <fully.qualified.package.Message.field>
//
// declares itself a copy. This test resolves the directive and fails unless the
// two fields' resolved protovalidate FieldRules are EQUAL (proto.Equal — the
// byte-for-byte view after option merging). Adding a new restated rule is one
// comment line; a directive that no longer resolves, or a copy that drifted,
// fails here by name. Comments come from gen/descriptor.binpb (built with
// source info); rules come from the linked-in generated descriptors — the same
// authoritative protovalidate view every other gate uses.
package conformance

import (
	"fmt"
	"os"
	"regexp"
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

// knownCopies are the restated rules this branch introduced; each MUST carry
// the directive so the gate is provably armed for them. New copies only add
// their directive comment — extending this list is optional pinning.
var knownCopies = []string{
	"ramp.admin.v1.TransactionEvidence.agent_acceptance_signature",
	"ramp.admin.v1.TransactionEvidence.request_idempotency_key",
	"ramp.admin.v1.TransactionEvidence.tenant_id",
	"ramp.admin.v1.ReportingObligationState.consumed_quantity",
	"ramp.admin.v1.ReportingPolicy.tenant_id",
	"ramp.admin.v1.GetTransactionEvidenceRequest.transaction_id",
	"ramp.admin.v1.GetTransactionEvidenceRequest.tenant_id",
}

func TestSameRuleDirectivesHoldByteForByte(t *testing.T) {
	directives := collectSameRuleDirectives(t) // field full name -> target full name

	for _, name := range knownCopies {
		if _, ok := directives[name]; !ok {
			t.Errorf("known restated rule %s carries no 'Same rule as <field>' directive — the drift gate is not armed for it", name)
		}
	}
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
