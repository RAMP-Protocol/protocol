// Package conformance — enum_comment_paragraph_test.go keeps an enum-typed
// field's documentation from disappearing on its way to the generated clients.
//
// protoc-gen-jsonschema renders an enum-typed field with the enum TYPE NAME in
// the JSON Schema `title` slot. A leading proto comment is split at its first
// blank line: the part above becomes `title`, the rest becomes `description`.
// For an enum field the type name wins, so the part above the blank line is
// overwritten and never reaches gen/python/wire/models.py or
// gen/ts/wire/schemas.ts. A single-paragraph comment has no split and arrives
// whole.
//
// THE FAILURE THIS STOPS. Write a two-paragraph comment on an enum field. Go
// gets the whole thing, so the proto and the Go bindings read correctly and a
// reviewer sees nothing wrong. Every gate stays green. A Python or TypeScript
// integrator silently gets the comment without its opening claim. Three fields
// were already losing text this way — including one whose lost sentence said
// when the field is set and when it is unset — and it was found by accident.
//
// The fix belongs upstream in the plugin. Until it is there, this is the guard:
// the rule is cheap to follow (one paragraph) and impossible to remember, which
// is exactly the kind of rule a test should hold rather than a comment.
package conformance

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// splitsIntoParagraphs reports whether a leading comment contains a blank line,
// which is what the plugin splits on.
func splitsIntoParagraphs(comment string) bool {
	for _, line := range strings.Split(strings.Trim(comment, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			return true
		}
	}
	return false
}

func TestEnumFieldCommentsAreOneParagraph(t *testing.T) {
	// Detector first. Without this the whole test can pass by never recognising a
	// paragraph break, which is the one way a guard like this fails silently.
	for _, c := range []struct {
		name  string
		text  string
		split bool
	}{
		{"single paragraph", " One line.\n and its continuation.\n", false},
		{"blank line", " First.\n\n Second.\n", true},
		{"blank line with spaces", " First.\n   \n Second.\n", true},
		{"leading and trailing blanks only", "\n One paragraph.\n", false},
	} {
		if got := splitsIntoParagraphs(c.text); got != c.split {
			t.Fatalf("splitsIntoParagraphs(%s) = %v, want %v — the detector is broken, "+
				"so the sweep below proves nothing", c.name, got, c.split)
		}
	}

	// Comments live only in gen/descriptor.binpb: `buf build` keeps source info and
	// the generated Go packages strip it, so Contract's own descriptors cannot
	// answer this.
	raw, err := os.ReadFile("../gen/descriptor.binpb")
	if err != nil {
		t.Fatalf("read descriptor: %v", err)
	}
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &fds); err != nil {
		t.Fatalf("parse descriptor: %v", err)
	}
	files, err := protodesc.NewFiles(&fds)
	if err != nil {
		t.Fatalf("build descriptor files: %v", err)
	}

	contract := map[string]bool{}
	for _, p := range ContractPackages() {
		contract[p] = true
	}

	var offenders []string
	inspected := 0
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !contract[string(fd.Package())] {
			return true
		}
		locs := fd.SourceLocations()
		var walk func(protoreflect.MessageDescriptors)
		walk = func(ms protoreflect.MessageDescriptors) {
			for i := 0; i < ms.Len(); i++ {
				md := ms.Get(i)
				if !md.IsMapEntry() {
					for j := 0; j < md.Fields().Len(); j++ {
						f := md.Fields().Get(j)
						if f.Enum() == nil {
							continue
						}
						inspected++
						if splitsIntoParagraphs(locs.ByDescriptor(f).LeadingComments) {
							offenders = append(offenders, string(md.FullName())+"."+string(f.Name()))
						}
					}
				}
				walk(md.Messages())
			}
		}
		walk(fd.Messages())
		return true
	})

	if inspected == 0 {
		t.Fatal("no enum-typed contract fields were inspected — the descriptor carries no " +
			"source info, or the walk reaches nothing. Either way this guard is not guarding.")
	}
	if len(offenders) > 0 {
		t.Errorf("enum-typed field(s) whose leading comment has more than one paragraph: %v\n"+
			"Everything above the first blank line is dropped before the Python and Zod "+
			"clients are generated, silently and in those two languages only. Join the "+
			"comment into a single paragraph. Merging two paragraphs of three is not enough "+
			"— whatever ends up first is what disappears.", offenders)
	}
}
