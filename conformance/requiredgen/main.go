// Command requiredgen emits required_fields.json: per message, the JSON field
// names whose proto ZERO value is rejected by the field's own protovalidate rule
// (an enum not_in:[0], a string min_len≥1 or a pattern that rejects "", a numeric
// gte≥1, or an explicit required). Those fields are required on the wire but the
// JSON Schema protoschema emits leaves them optional; merge_schema reads this
// manifest to mark them `required` (and drop the zero default) so the generated
// Pydantic/Zod reject omission, matching the Go server.
//
// This is the single, authoritative source of "is the zero value invalid" (the same
// Go protovalidate the conformance corpus is labeled against), consumed by
// scripts/gen-sdk-types.sh so the Python bridge does not re-implement the rule
// semantics.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/RAMP-Protocol/protocol/conformance"
)

func main() {
	// Fail fast on a cross-package bare-name collision: this manifest (and merge_schema.py,
	// which consumes it) key by bare message name, so a duplicate would silently clobber.
	// corpusgen guards the same way; doing it here closes the standalone gen-sdk-types.sh
	// path, which runs this generator but not corpusgen.
	if err := conformance.AssertUniqueBareNames(); err != nil {
		panic(err)
	}
	assertNoStringByteLengthRules()
	out := "required_fields.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	req := map[string][]string{}
	conformance.EachRuledField(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, fr *validate.FieldRules) {
		if zeroRejected(fd, fr) {
			req[string(md.Name())] = append(req[string(md.Name())], string(fd.Name()))
		}
	})
	for _, names := range req {
		sort.Strings(names)
	}
	b, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// assertNoStringByteLengthRules panics on any string byte-length rule
// (min_bytes/max_bytes), on any field, regardless of presence or `required`:
// protoschema renders them as JSON Schema minLength/maxLength, which count
// CHARACTERS, so a multibyte value the Go server rejects would pass the
// generated clients. This runs as its own sweep — not inside zeroRejected —
// so the required/HasPresence early returns there cannot skip it. No contract
// field carries these rules today; implement a byte-count refine in the
// sdk-types pipeline before adding one.
//
// The sweep is EachRuleSet, not EachRuledField: the rule is just as wrong at
// repeated.items.string.max_bytes, and the contract already uses item-level
// string rules on six fields, so a top-level-only sweep would be a guard with a
// hole exactly where the shape is most likely to be added.
func assertNoStringByteLengthRules() {
	conformance.EachRuleSet(func(_ protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, prefix string, fr *validate.FieldRules) {
		if member, n, ok := conformance.StringByteLength(fr); ok {
			panic(fmt.Sprintf("requiredgen: string byte-length rule %sstring.%s:%d on field %s — protoschema translates it to a CHARACTER count; implement a byte-count refine in the sdk-types pipeline first", prefix, member, n, fd.FullName()))
		}
	})
}

// zeroRejected reports whether fd's zero/absent value is rejected by its own
// field rule fr (already resolved by the EachRuledField walk, which panics
// rather than reading a resolver error as "no rules"). Fields with explicit
// presence (optional, message, oneof member) are exempt unless they carry an
// explicit `required` — protovalidate skips an unset presence-tracking field,
// so its absence is valid.
func zeroRejected(fd protoreflect.FieldDescriptor, fr *validate.FieldRules) bool {
	if fr.GetRequired() {
		return true
	}
	if fd.HasPresence() {
		return false
	}
	if e := fr.GetEnum(); e != nil {
		for _, n := range e.GetNotIn() {
			if n == 0 {
				return true
			}
		}
	}
	if s := fr.GetString(); s != nil {
		if s.GetMinLen() >= 1 {
			return true
		}
		// A non-empty const rejects the zero value "", so omission must be
		// rejected too (the pinned "EdDSA" algorithm labels).
		if s.Const != nil && s.GetConst() != "" {
			return true
		}
		if p := s.GetPattern(); p != "" {
			if re, err := regexp.Compile(p); err == nil && !re.MatchString("") {
				return true
			}
		}
	}
	if r := fr.GetRepeated(); r != nil && r.GetMinItems() >= 1 {
		// An empty list is the repeated zero value; min_items≥1 rejects it, and
		// proto-JSON omits an empty list entirely, so omission must be rejected
		// too (TransactionRequest.items — the corpus too_few mutant).
		return true
	}
	// Any bytes length rule rejects the zero value (empty bytes) — a floor of at
	// least 1 and an exact length of at least 1 both do — so omission must be
	// rejected by the clients too. These are the evidence rows' Ed25519 keys and
	// canonical-bytes fields. conformance.MustBytesLength owns the "at least 1"
	// part: a zero-valued length rule is a contract error there, not a rule that
	// reaches here.
	if conformance.MustBytesLength(fd, fr) != nil {
		return true
	}
	if i := fr.GetInt64(); i != nil {
		switch x := i.GetGreaterThan().(type) {
		case *validate.Int64Rules_Gte:
			if x.Gte >= 1 {
				return true
			}
		case *validate.Int64Rules_Gt:
			if x.Gt >= 0 {
				return true
			}
		}
	}
	if i := fr.GetInt32(); i != nil {
		switch x := i.GetGreaterThan().(type) {
		case *validate.Int32Rules_Gte:
			if x.Gte >= 1 {
				return true
			}
		case *validate.Int32Rules_Gt:
			if x.Gt >= 0 {
				return true
			}
		}
	}
	// Loud guard: only int64 and int32 numeric rules are evaluated above (Quota.limit,
	// the ramp.admin.v1 setters). A rule of another numeric kind would fall through as
	// "zero is valid" — the field would not be marked required and the generated
	// clients would accept an omission the Go server rejects. Fail instead of silently
	// under-marking.
	if fr.GetUint64() != nil || fr.GetUint32() != nil ||
		fr.GetSint64() != nil || fr.GetSint32() != nil || fr.GetFixed64() != nil ||
		fr.GetFixed32() != nil || fr.GetSfixed64() != nil || fr.GetSfixed32() != nil ||
		fr.GetFloat() != nil || fr.GetDouble() != nil {
		panic(fmt.Sprintf("requiredgen: unhandled numeric rule on field %s (kind %s) — extend zeroRejected to evaluate it", fd.FullName(), fd.Kind()))
	}
	return false
}
