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

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/RAMP-Protocol/protocol/conformance"
)

func main() {
	out := "unique_items.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	uniq := map[string][]string{}
	conformance.EachMessage(func(md protoreflect.MessageDescriptor) {
		var names []string
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if uniqueItems(fd) {
				names = append(names, string(fd.Name()))
			}
		}
		if len(names) > 0 {
			sort.Strings(names)
			uniq[string(md.Name())] = names
		}
	})
	b, err := json.MarshalIndent(uniq, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// uniqueItems reports whether fd is a repeated field whose items must be unique.
func uniqueItems(fd protoreflect.FieldDescriptor) bool {
	if !fd.IsList() {
		return false
	}
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil || fr == nil {
		return false
	}
	return fr.GetRepeated().GetUnique()
}
