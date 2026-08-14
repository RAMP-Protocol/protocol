// Command bytesgen emits bytes_len.json: per message, the JSON field names of
// every bytes field declaring an exact length ((buf.validate.field).bytes.len),
// with that length in bytes — e.g. the evidence rows' raw 32-byte Ed25519 keys
// and sha256 signed_url_hash.
//
// It exists because protoschema's translation of bytes.len=N is too loose: it
// renders the field as base64 with a minLength/maxLength window (43..44 chars
// for N=32) that also admits an N+1-byte value — 33 bytes encode to 44 unpadded
// chars, inside the window — so the generated Pydantic/Zod accept a key length
// the Go server rejects. merge_schema.py reads this manifest and tightens each
// field to the EXACT encoded forms of N bytes (unpadded, or padded to the base64
// block), making byte length checkable at the schema layer without decoding.
//
// Like requiredgen and uniquegen, this is a Go program because Go protovalidate
// is the authoritative view of the rules (the same engine the conformance corpus
// is labeled against), and the Python bridge must not re-implement rule
// semantics. Scope comes from conformance.Contract.
package main

import (
	"encoding/json"
	"os"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/RAMP-Protocol/protocol/conformance"
)

func main() {
	out := "bytes_len.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	lens := map[string]map[string]uint64{}
	conformance.EachMessage(func(md protoreflect.MessageDescriptor) {
		fields := map[string]uint64{}
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if n, ok := exactLen(fd); ok {
				fields[string(fd.Name())] = n
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

// exactLen reports fd's bytes.len rule value, if it carries one.
func exactLen(fd protoreflect.FieldDescriptor) (uint64, bool) {
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil || fr == nil {
		return 0, false
	}
	b := fr.GetBytes()
	if b == nil || b.Len == nil {
		return 0, false
	}
	return b.GetLen(), true
}
