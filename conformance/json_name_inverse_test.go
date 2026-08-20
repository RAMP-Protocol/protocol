package conformance

// The lowerCamelCase→snake_case inverse must be exact for every contract field.
//
// One place on the RAMP wire is lowerCamelCase and cannot be made otherwise: the
// `debug` projection connect-go attaches to an error detail. It builds that projection
// with its own protojson codec at default options, inside a method on an unexported
// type, so no codec a server registers reaches it — the response BODY is snake_case and
// the error detail beside it is not. The JSON-only SDKs have no protobuf binary codec,
// so `debug` is the only form of the detail they can read, and they normalize its keys
// back to the proto names before parsing.
//
// That normalization is a plain textual inverse — insert an underscore before each
// uppercase letter and lowercase it — which is only sound while every field's json_name
// round-trips through it. protoc derives json_name by removing the underscores and
// capitalizing what follows, and that is not injective in general: a field named
// `field_2` yields `field2`, whose inverse is `field2`, not the name it came from. No
// contract field has that shape today. This guard is what keeps it that way, so the
// naming a normalizer relies on cannot be broken by a field added years later with no
// idea the dependency exists.
//
// On failure: either rename the field, or replace the textual inverse in the SDKs with
// an explicit json_name→name map generated from this descriptor. Do not relax the guard.

import (
	"strings"
	"testing"
	"unicode"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// snakeFromJSONName is the inverse the SDKs apply, transcribed here so the guard tests
// the real rule rather than a paraphrase of it.
func snakeFromJSONName(jsonName string) string {
	var b strings.Builder
	for _, r := range jsonName {
		if unicode.IsUpper(r) {
			b.WriteByte('_')
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestJSONNameInverseRecoversEveryFieldName(t *testing.T) {
	checked := 0
	EachMessage(func(md protoreflect.MessageDescriptor) {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			checked++
			if got := snakeFromJSONName(fd.JSONName()); got != string(fd.Name()) {
				t.Errorf("%s: json_name %q inverts to %q, not %q — the SDKs' camelCase "+
					"normalization would not recover this field",
					fd.FullName(), fd.JSONName(), got, fd.Name())
			}
		}
	})
	if checked == 0 {
		t.Fatal("no contract fields walked — the guard would pass vacuously")
	}
}

// TestJSONNameInverseDetectsANonInvertibleName proves the guard is not vacuous: it
// bites on the shape that would break it, which no contract field has today.
func TestJSONNameInverseDetectsANonInvertibleName(t *testing.T) {
	if got := snakeFromJSONName("field2"); got == "field_2" {
		t.Fatal("the inverse claims to recover field_2 from field2; it cannot, and a " +
			"guard that believes it does would pass on the one case it exists to catch")
	}
}

// errorDetailOpenMapMembers is what the SDK normalizers hold back from: a member whose
// KEYS are the emitter's data rather than proto field names, so rewriting them would
// corrupt the value. Both the Python and the TypeScript reader spell this set as the
// single name `metadata`.
var errorDetailOpenMapMembers = map[string]bool{"metadata": true}

// TestErrorDetailHasOneOpenMapMember pins the fact the SDK normalizers rely on.
//
// Reading a Connect error detail means rewriting the lowerCamelCase `debug` projection
// back to proto field names, and that rewrite must stop wherever the keys stop being
// field names — inside a map or a google.protobuf.Struct, where they are values the
// emitter chose. Today the ErrorDetail subtree has exactly one such member. A new one
// added later would silently have its caller-chosen keys rewritten, mangling the value
// while every test still passed, so the count is held here rather than left implicit in
// two hand-written name sets.
//
// On failure: add the member to _OPEN_MAP_MEMBERS in sdk/python/ramp_sdk/errordetail.py
// and OPEN_MAP_MEMBERS in sdk/ts/src/errordetail.ts, then extend this set.
func TestErrorDetailHasOneOpenMapMember(t *testing.T) {
	mt, err := findContractMessage("ErrorDetail")
	if err != nil {
		t.Fatalf("resolve ErrorDetail: %v", err)
	}
	root := mt.Descriptor()
	found := map[string]bool{}
	seen := map[protoreflect.FullName]bool{}

	var walk func(protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			if fd.IsMap() {
				found[string(fd.Name())] = true
				continue
			}
			if fd.Kind() != protoreflect.MessageKind {
				continue
			}
			if fd.Message().FullName() == "google.protobuf.Struct" ||
				fd.Message().FullName() == "google.protobuf.Value" {
				found[string(fd.Name())] = true
				continue
			}
			walk(fd.Message())
		}
	}
	walk(root)

	for name := range found {
		if !errorDetailOpenMapMembers[name] {
			t.Errorf("ErrorDetail subtree gained the open-map member %q — the SDK "+
				"camelCase normalizers would rewrite its caller-chosen keys", name)
		}
	}
	for name := range errorDetailOpenMapMembers {
		if !found[name] {
			t.Errorf("ErrorDetail subtree no longer has the open-map member %q — drop it "+
				"from the SDK normalizers' hold-back sets", name)
		}
	}
}
