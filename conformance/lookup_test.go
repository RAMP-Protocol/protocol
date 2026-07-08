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
