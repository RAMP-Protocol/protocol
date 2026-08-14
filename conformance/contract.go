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

// AssertUniqueBareNames reports an error when two contract packages define a message
// with the same bare name. The corpus keys cases by bare short name (Case.Message ==
// the generated class/schema name), the merged JSON-Schema $defs are keyed the same way,
// and the {/* ramp-validate: X */} doc markers resolve the same way — a cross-package
// duplicate would silently collide in all three. Returned as an error, not a fatal, so
// both a `package main` generator (which exits) and a test (which fails) can use it.
func AssertUniqueBareNames() error {
	seen := map[string]protoreflect.FullName{}
	var err error
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if prev, ok := seen[string(md.Name())]; ok && prev != md.FullName() && err == nil {
			err = fmt.Errorf("duplicate bare message name %q (%s vs %s) — the corpus/parity bare-name scheme cannot represent it",
				md.Name(), prev, md.FullName())
			return
		}
		seen[string(md.Name())] = md.FullName()
	})
	return err
}
