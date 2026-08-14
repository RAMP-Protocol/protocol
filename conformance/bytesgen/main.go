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
// Anything this pipeline cannot translate fails the generator closed, because
// protoschema's rendering of an untranslated shape must not ship silently loose
// (the convention requiredgen uses for string.min_bytes): any OTHER bytes rule
// member (max_len, pattern, prefix, …), len and min_len set together on one
// field, and an explicitly zero-valued length rule. See lengthRule for why each
// one is fatal rather than skipped.
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

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
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
	conformance.EachRuledField(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, fr *validate.FieldRules) {
		r, ok := lengthRule(fd, fr)
		if !ok {
			return
		}
		msg := string(md.Name())
		if lens[msg] == nil {
			lens[msg] = map[string]map[string]uint64{}
		}
		lens[msg][string(fd.Name())] = r
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
// {"min_len": N} map, if fd carries one. fr is the field's resolved rules
// (conformance.EachRuledField already turned a resolver error into a panic —
// it is not "no rule", and swallowing it would drop the field from the manifest
// and lose its length enforcement).
//
// Three shapes panic, all for the same reason: the manifest carries ONE rule
// kind per field, and merge_schema.py's tighten_bytes_len translates exactly
// that. Anything it cannot represent must stop the build rather than ship with
// protoschema's loose rendering and every gate green (fail closed, the
// requiredgen convention for string.min_bytes).
//
//  1. Any bytes rule member outside len/min_len (max_len, pattern, prefix, …):
//     no translation exists for it.
//  2. len AND min_len both set: the manifest entry would carry only the len
//     window and drop the floor silently across the boundary.
//  3. A zero-valued length rule (len: 0 / min_len: 0): it constrains nothing,
//     yet corpusgen, requiredgen, and the class-6 coverage guard all read bytes
//     rules by VALUE (GetMinLen() > 0), so a zero here would enter the manifest
//     while every other view of the contract treats the field as unruled. It is
//     a contract error, not a rule.
//
// With (3) fatal, the value checks below cannot disagree with a presence check
// on the same member — one reading of "carries a length rule" across the repo.
func lengthRule(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) (map[string]uint64, bool) {
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
	if b.Len != nil && b.MinLen != nil {
		panic(fmt.Sprintf("bytesgen: field %s carries BOTH bytes.len:%d and bytes.min_len:%d — the manifest holds one rule kind per field, so merge_schema.py would enforce the exact length and silently drop the floor; express the intent as a single rule", fd.FullName(), b.GetLen(), b.GetMinLen()))
	}
	if b.Len != nil && b.GetLen() == 0 {
		panic(fmt.Sprintf("bytesgen: field %s carries bytes.len:0 — an explicit zero length is a contract error, not a rule (corpusgen and the coverage guard read length rules by value and would treat the field as unruled)", fd.FullName()))
	}
	if b.MinLen != nil && b.GetMinLen() == 0 {
		panic(fmt.Sprintf("bytesgen: field %s carries bytes.min_len:0 — an explicit zero floor is a contract error, not a rule (corpusgen and the coverage guard read length rules by value and would treat the field as unruled)", fd.FullName()))
	}
	if b.GetLen() > 0 {
		return map[string]uint64{"len": b.GetLen()}, true
	}
	if b.GetMinLen() > 0 {
		return map[string]uint64{"min_len": b.GetMinLen()}, true
	}
	return nil, false
}
