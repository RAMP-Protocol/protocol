// Command requiredgen emits required_fields.json: per message, the JSON field
// names whose proto ZERO value is rejected by the field's own protovalidate rule
// (an enum not_in:[0], a string min_len≥1 or a pattern that rejects "", a numeric
// gte≥1, or an explicit required). Those fields are required on the wire but the
// JSON Schema protoschema emits leaves them optional; merge_schema reads this
// manifest to mark them `required` (and drop the zero default) so the generated
// Pydantic/Zod reject omission, matching the Go server.
//
// This is the single, authoritative source of "is the zero value invalid" — the
// same protovalidate view the conformance tests use — so the Python bridge does
// not re-implement the rule semantics.
package main

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"

	protovalidate "buf.build/go/protovalidate"
	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/reflect/protoreflect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

func main() {
	out := "required_fields.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	req := map[string][]string{}
	eachMessage(func(md protoreflect.MessageDescriptor) {
		var names []string
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if zeroRejected(fd) {
				names = append(names, fd.JSONName())
			}
		}
		if len(names) > 0 {
			sort.Strings(names)
			req[string(md.Name())] = names
		}
	})
	b, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// zeroRejected reports whether fd's zero/absent value is rejected by its own
// field rule. Fields with explicit presence (optional, message, oneof member)
// are exempt unless they carry an explicit `required` — protovalidate skips an
// unset presence-tracking field, so its absence is valid.
func zeroRejected(fd protoreflect.FieldDescriptor) bool {
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil || fr == nil {
		return false
	}
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
		if p := s.GetPattern(); p != "" {
			if re, err := regexp.Compile(p); err == nil && !re.MatchString("") {
				return true
			}
		}
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
	return false
}

func eachMessage(fn func(protoreflect.MessageDescriptor)) {
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			md := ms.Get(i)
			if !md.IsMapEntry() {
				fn(md)
			}
			walk(md.Messages())
		}
	}
	walk(rampv1.File_ramp_v1_ramp_proto.Messages())
}
