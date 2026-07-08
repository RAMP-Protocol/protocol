// Package conformance — lookup_test.go holds the shared bare-name → message
// resolution used by every corpus- and doc-example-driven test.
//
// The corpus (Case.Message) and the {/* ramp-validate: X */} doc markers carry
// BARE message names — the same names the generated Pydantic/Zod classes use —
// so resolution tries each contract package in order. Bare names are unique
// across the packages (corpusgen guards this loudly at generation time).
package conformance

import (
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// contractPackages are the proto packages whose messages may appear in the
// corpus and in doc-example markers, in resolution order.
var contractPackages = []string{"ramp.v1", "ramp.admin.v1"}

// contractFiles are the descriptor files that make up the wire contract, in
// the same order as contractPackages. Descriptor-walking guards iterate these
// so a newly added contract package is covered by adding one entry.
var contractFiles = []protoreflect.FileDescriptor{
	rampv1.File_ramp_v1_ramp_proto,
	rampadminv1.File_ramp_admin_v1_admin_proto,
}

// findContractMessage resolves a bare message name against contractPackages.
func findContractMessage(short string) (protoreflect.MessageType, error) {
	var firstErr error
	for _, pkg := range contractPackages {
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
