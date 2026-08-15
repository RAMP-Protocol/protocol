// Package conformance — lookup_test.go holds the shared bare-name → message
// resolution used by every corpus- and doc-example-driven test.
//
// The corpus (Case.Message) and the {/* ramp-validate: X */} doc markers carry
// BARE message names — the same names the generated Pydantic/Zod classes use —
// so resolution tries each contract package in order. Bare names are unique
// across the packages; contract.go's AssertUniqueBareNames proves it (see
// TestContractBareNamesUnique) and corpusgen re-checks it at generation time.
package conformance

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// findContractMessage resolves a bare message name against ContractPackages().
func findContractMessage(short string) (protoreflect.MessageType, error) {
	var firstErr error
	for _, pkg := range ContractPackages() {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(pkg + "." + short))
		if err == nil {
			return mt, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// contractPackages is the resolution order, materialized once for error messages.
var contractPackages = ContractPackages()

// TestContractBareNamesUnique exercises the guard corpusgen relies on, inside the test
// binary too — so a cross-package name collision fails `go test ./...`, not only the
// next `go run ./conformance/corpusgen`.
func TestContractBareNamesUnique(t *testing.T) {
	if err := AssertUniqueBareNames(); err != nil {
		t.Fatal(err)
	}
	if len(Contract) == 0 {
		t.Fatal("no contract files — the guard would be vacuous")
	}
}

// TestBareNameSweepReachesEnums pins the SCOPE of the guard above, which the guard
// itself cannot report.
//
// AssertUniqueBareNames returning nil means "no duplicates found in what I looked
// at". For a long time it looked at messages only, and that was invisible: ramp.v1
// was the sole package defining enums, so no cross-package enum collision could
// exist to be missed. ramp.admin.v1 adding ObligationState is what made the gap
// reachable, and nothing would have failed when it did.
//
// So this asserts the walk actually reaches enums, and reaches them in more than
// one package. A future sweep that quietly stopped visiting them would leave
// TestContractBareNamesUnique green.
//
// The collision matters because merge_schema.py hoists enums into the same $defs
// map as messages and keys them by bare name with setdefault: the SECOND enum of a
// colliding pair is dropped, and every field referring to it silently takes the
// FIRST enum's value list. Generated Pydantic and Zod would then accept values the
// Go server rejects.
func TestBareNameSweepReachesEnums(t *testing.T) {
	byPackage := map[string]int{}
	total := 0
	EachEnum(func(ed protoreflect.EnumDescriptor) {
		total++
		byPackage[string(ed.ParentFile().Package())]++
	})

	if total == 0 {
		t.Fatal("EachEnum visited no enums — the enum half of AssertUniqueBareNames is wired to nothing")
	}
	if len(byPackage) < 2 {
		t.Fatalf("EachEnum reached enums in %d contract package(s) (%v); the guard exists for CROSS-package "+
			"collisions, so it is vacuous while only one package defines enums", len(byPackage), byPackage)
	}

	// Nested enums are the half a file-level-only walk would miss, and a message
	// containing one is where a bare-name collision is easiest to introduce by
	// accident, because the nesting hides the name from a reader scanning the file.
	var nested int
	EachMessage(func(md protoreflect.MessageDescriptor) { nested += md.Enums().Len() })
	var seenNested int
	EachEnum(func(ed protoreflect.EnumDescriptor) {
		if _, ok := ed.Parent().(protoreflect.MessageDescriptor); ok {
			seenNested++
		}
	})
	if seenNested != nested {
		t.Errorf("EachEnum saw %d nested enum(s), the contract declares %d — the walk skips nesting levels", seenNested, nested)
	}
}
