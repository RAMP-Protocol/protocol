// Command bytesgen emits bytes_len.json: per message, the JSON field names of
// every bytes field declaring a length rule, with the rule's kind and value —
// {"len": N} for (buf.validate.field).bytes.len (the evidence rows' raw
// 32-byte Ed25519 keys and sha256 signed_url_hash) or {"min_len": N} for
// bytes.min_len (the evidence rows' canonical-bytes fields).
//
// It exists because protoschema's translation of both rules is too loose:
//   - bytes.len=N renders as base64 with a minLength/maxLength window (43..44
//     chars for N=32) that also admits an N+1-byte value — 33 bytes encode to
//     44 unpadded chars, inside the window — so the generated Pydantic/Zod
//     accept a key length the Go server rejects.
//   - bytes.min_len=N renders as a pattern + minLength counting CHARACTERS,
//     so for N=1 the two-character string "==" (pure padding, zero payload
//     bytes) passes the generated clients while Go protojson refuses to
//     decode it.
//
// merge_schema.py reads this manifest and tightens each field: exact-length
// fields to the EXACT encoded forms of N bytes, minimum-length fields to a
// pattern requiring the encoded payload characters of at least N bytes —
// making byte length checkable at the schema layer without decoding.
//
// Any OTHER bytes rule member (max_len, pattern, prefix, …) fails this
// generator closed: protoschema's rendering of a shape this pipeline does not
// translate must not ship silently loose (the convention requiredgen uses for
// string.min_bytes).
//
// Like requiredgen and uniquegen, this is a Go program because Go protovalidate
// is the authoritative view of the rules (the same engine the conformance corpus
// is labeled against), and the Python bridge must not re-implement rule
// semantics. Scope comes from conformance.Contract.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/RAMP-Protocol/protocol/conformance"
)

func main() {
	// Fail fast on a cross-package bare-name collision: this manifest (and
	// merge_schema.py, which consumes it) key by bare message name, so a
	// duplicate would silently clobber one message's exact-length enforcement.
	// Same guard as requiredgen; without it, only the run order in
	// gen-sdk-types.sh protects a standalone bytesgen run.
	if err := conformance.AssertUniqueBareNames(); err != nil {
		panic(err)
	}
	out := "bytes_len.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	lens := map[string]map[string]map[string]uint64{}
	conformance.EachMessage(func(md protoreflect.MessageDescriptor) {
		fields := map[string]map[string]uint64{}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if r, ok := lengthRule(fd); ok {
				fields[string(fd.Name())] = r
			}
		}
		if len(fields) > 0 {
			lens[string(md.Name())] = fields
		}
	})
	b, err := json.MarshalIndent(lens, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// lengthRule reports fd's bytes length rule as a one-entry {"len": N} or
// {"min_len": N} map, if fd carries one. Any bytes rule member outside those
// two panics: merge_schema.py has no translation for it, so shipping it would
// keep protoschema's loose rendering with every gate green (fail closed, the
// requiredgen convention for string.min_bytes).
func lengthRule(fd protoreflect.FieldDescriptor) (map[string]uint64, bool) {
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil {
		// A resolution failure is not "no rule" — swallowing it would silently
		// drop the field from the manifest and lose its length enforcement.
		panic(fmt.Sprintf("bytesgen: resolving rules for field %s: %v", fd.FullName(), err))
	}
	if fr == nil {
		return nil, false
	}
	b := fr.GetBytes()
	if b == nil {
		return nil, false
	}
	b.ProtoReflect().Range(func(f protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		switch f.Name() {
		case "len", "min_len":
			return true
		default:
			panic(fmt.Sprintf("bytesgen: field %s carries bytes rule %q — merge_schema.py has no translation for it; teach tighten_bytes_len its shape before shipping it", fd.FullName(), f.Name()))
		}
	})
	if b.Len != nil {
		return map[string]uint64{"len": b.GetLen()}, true
	}
	if b.MinLen != nil {
		return map[string]uint64{"min_len": b.GetMinLen()}, true
	}
	return nil, false
}
