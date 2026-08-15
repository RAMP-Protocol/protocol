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
// member (max_len, pattern, prefix, …) and a length rule sitting at
// repeated.items level both die in assertTranslatable, while len and min_len set
// together on one field and an explicitly zero-valued length rule die in
// conformance.BytesLength — they are contract errors for every consumer, not a
// bytesgen-only opinion.
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
	assertEveryBytesFieldRuledOrAllowed()
	out := "bytes_len.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	lens := map[string]map[string]map[string]uint64{}
	// EachRuleSet, not EachRuledField: the manifest can only express a length rule
	// on the field itself, so an item-level one must be caught rather than walked
	// past. assertTranslatable dies on it; the prefix check below keeps item rules
	// out of the manifest.
	conformance.EachRuleSet(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, prefix string, fr *validate.FieldRules) {
		assertTranslatable(fd, prefix, fr)
		if prefix != "" {
			return
		}
		r := conformance.MustBytesLength(fd, fr)
		if r == nil {
			return
		}
		msg := string(md.Name())
		if lens[msg] == nil {
			lens[msg] = map[string]map[string]uint64{}
		}
		lens[msg][string(fd.Name())] = map[string]uint64{r.Kind: r.Value}
	})
	b, err := json.MarshalIndent(lens, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// bytesFieldsAllowedUnruled names the bytes fields that ship with NO length rule
// and therefore keep protoschema's loose base64 rendering in the generated
// clients. Each entry is a standing exception, not a decision to leave alone: the
// value is the reason it is tolerable today.
//
// The rendering an entry accepts is `^[A-Za-z0-9+/]*={0,2}$` — no url-safe arm, and
// padding characters allowed anywhere the regex's tail permits. A generated client
// therefore accepts values Go protojson refuses to decode, and refuses url-safe
// values Go protojson accepts. Wrong in both directions, quietly.
var bytesFieldsAllowedUnruled = map[string]string{
	"ramp.v1.Delegation.token": "A JWS compact serialization, not a fixed-size or " +
		"minimum-size payload, so neither len nor min_len describes it — the shapes this " +
		"manifest can express are the wrong tool. What it needs is a base64url-faithful " +
		"PATTERN, which tighten_bytes_len cannot emit today. Tracked separately.",
}

// assertEveryBytesFieldRuledOrAllowed fails the generator on a bytes field that
// carries no length rule and is not an explicit exception.
//
// WHY THIS EXISTS. The manifest walk uses EachRuleSet, which visits fields that
// HAVE rules. A bytes field with none was never visited, so it fell through and
// shipped with protoschema's loose rendering — in a generator whose header says it
// fails closed on everything it cannot translate. The gap was invisible for the
// usual reason: a guard that only inspects what it was given cannot report what it
// was never given.
//
// The list is self-cleaning in both directions. A new unruled bytes field fails
// until someone decides about it, and an entry that stops naming a live unruled
// field also fails, so the exception cannot outlive the field it excuses.
func assertEveryBytesFieldRuledOrAllowed() {
	unruled := map[string]bool{}
	conformance.EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if fd.Kind() != protoreflect.BytesKind {
				continue
			}
			fr := conformance.FieldRules(fd)
			if fr.GetBytes() != nil || fr.GetRepeated().GetItems().GetBytes() != nil {
				continue
			}
			unruled[string(fd.FullName())] = true
		}
	})

	for name := range unruled {
		if _, ok := bytesFieldsAllowedUnruled[name]; !ok {
			panic(fmt.Sprintf("bytesgen: bytes field %s carries no length rule, so the generated "+
				"Pydantic/Zod keep protoschema's loose base64 pattern and disagree with Go protojson "+
				"in both directions. Give it a bytes.len or bytes.min_len rule, or add it to "+
				"bytesFieldsAllowedUnruled with the reason it cannot have one.", name))
		}
	}
	for name := range bytesFieldsAllowedUnruled {
		if !unruled[name] {
			panic(fmt.Sprintf("bytesgen: bytesFieldsAllowedUnruled names %s, which is no longer an "+
				"unruled bytes field — it gained a rule, was renamed, or was removed. Drop the entry.", name))
		}
	}
}

// assertTranslatable dies on any bytes rule shape merge_schema.py's
// tighten_bytes_len cannot translate. Anything it cannot represent must stop the
// build rather than ship with protoschema's loose rendering and every gate green
// (fail closed, the requiredgen convention for string.min_bytes).
//
// Two shapes are fatal here:
//
//  1. Any bytes rule member outside len/min_len (max_len, pattern, prefix, …):
//     no translation exists for it.
//  2. A bytes length rule at repeated.items level: the manifest keys by
//     "<Message>/<field>" and tighten_bytes_len rewrites the field's own schema
//     node, so it has no way to reach a list's items. Without this check the
//     rule would tighten nothing and every gate would stay green.
//
// The remaining two — len and min_len both set, and a zero-valued length — are
// rejected by conformance.BytesLength, so they are contract errors for every
// consumer rather than a bytesgen-only opinion.
func assertTranslatable(fd protoreflect.FieldDescriptor, prefix string, fr *validate.FieldRules) {
	b := fr.GetBytes()
	if b == nil {
		return
	}
	b.ProtoReflect().Range(func(f protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		switch f.Name() {
		case "len", "min_len":
			return true
		default:
			panic(fmt.Sprintf("bytesgen: field %s carries rule %sbytes.%s — merge_schema.py has no translation for it; teach tighten_bytes_len its shape before shipping it", fd.FullName(), prefix, f.Name()))
		}
	})
	if prefix != "" {
		panic(fmt.Sprintf("bytesgen: field %s carries a %sbytes length rule — the manifest holds one entry per FIELD and tighten_bytes_len rewrites that field's schema node, so it cannot reach list items; teach the manifest an item level before shipping it", fd.FullName(), prefix))
	}
}
