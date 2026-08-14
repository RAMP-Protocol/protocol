// Command uniquegen emits unique_items.json: per message, the JSON field names of every
// repeated field declaring (buf.validate.field).repeated.unique — i.e. the fields whose
// items are a SET on the wire, where Go protovalidate rejects a duplicate.
//
// It exists because that rule reaches neither generated client on its own:
// protoschema-plugins emits no `uniqueItems` keyword at all, so the constraint is absent
// from the JSON Schema the Pydantic/Zod pipeline consumes. merge_schema.py reads this
// manifest and injects `uniqueItems: true` (json-schema-to-zod turns that into a
// `.refine(...)`), and scripts/sdk-types/gen_unique_py.py reads the SAME manifest to emit
// gen/python/wire/unique.py, which the hand-written wire/base.py seam enforces —
// datamodel-code-generator drops `uniqueItems` for Pydantic v2.
//
// Like requiredgen, this is a Go program because Go protovalidate is the authoritative
// view of the rules (the same engine the conformance corpus is labeled against), and the
// Python bridge must not re-implement rule semantics. Scope comes from conformance.Contract.
package main

import (
	"encoding/json"
	"os"
	"sort"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/RAMP-Protocol/protocol/conformance"
)

func main() {
	// Fail fast on a cross-package bare-name collision: this manifest (and
	// merge_schema.py + gen_unique_py.py, which consume it) key by bare message
	// name, so a duplicate would silently clobber one message's set-semantics
	// enforcement. Same guard as requiredgen and bytesgen.
	if err := conformance.AssertUniqueBareNames(); err != nil {
		panic(err)
	}
	out := "unique_items.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	uniq := map[string][]string{}
	conformance.EachRuledField(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, fr *validate.FieldRules) {
		if fd.IsList() && fr.GetRepeated().GetUnique() {
			uniq[string(md.Name())] = append(uniq[string(md.Name())], string(fd.Name()))
		}
	})
	for _, names := range uniq {
		sort.Strings(names)
	}
	b, err := json.MarshalIndent(uniq, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
