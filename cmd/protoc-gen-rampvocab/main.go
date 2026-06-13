// Command protoc-gen-rampvocab is a buf/protoc plugin that reads the
// (ramp.v1.vocab) repeated-string field option off every annotated field and
// emits, per axis, a typed Go package with one string constant per registered
// token, an All slice, and an IsRegistered membership check.
//
// The token list is authored in exactly one place — the (ramp.v1.vocab)
// entries on the field — so the generated constants and the ingest-time
// membership check both derive from it and cannot drift. The plugin reads the
// option STRUCTURALLY (it does not parse CEL and emits no drift assertion).
//
// A generic plugin binary does not have ramp.v1's extension registered in its
// global proto registry, so reading FieldOptions through the global registry
// would silently miss (ramp.v1.vocab). To read it, the plugin builds a
// dynamicpb-backed extension resolver from the FileDescriptorProtos carried in
// the CodeGeneratorRequest and re-parses each field's raw options bytes through
// that resolver.
package main

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// vocabExtensionNumber is FieldOptions extension 50001 — (ramp.v1.vocab).
const vocabExtensionNumber = 50001

// axis maps a field name carrying (ramp.v1.vocab) to its generated Go package.
// Pilot scope is Pricing.unit only.
var axisPackage = map[string]string{
	"unit": "pricingunits",
}

func main() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)

		resolver, err := buildResolver(gen.Request.GetProtoFile())
		if err != nil {
			return fmt.Errorf("build extension resolver: %w", err)
		}
		ext := vocabExtension(resolver)
		if ext == nil {
			// This request carries no (ramp.v1.vocab) extension descriptor
			// (e.g. a sibling module split with no vocab-bearing field).
			// Nothing to generate.
			return nil
		}

		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}
			for _, msg := range f.Messages {
				if err := genMessage(gen, ext, msg); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// buildResolver constructs a protoregistry.Files from the request's
// FileDescriptorProtos so the (ramp.v1.vocab) extension type can be resolved.
// The CodeGeneratorRequest may list a transitive dependency more than once;
// protodesc.NewFiles rejects duplicate file paths, so dedupe by path first.
func buildResolver(protoFiles []*descriptorpb.FileDescriptorProto) (*protoregistry.Files, error) {
	seen := make(map[string]struct{}, len(protoFiles))
	deduped := make([]*descriptorpb.FileDescriptorProto, 0, len(protoFiles))
	for _, pf := range protoFiles {
		if _, ok := seen[pf.GetName()]; ok {
			continue
		}
		seen[pf.GetName()] = struct{}{}
		deduped = append(deduped, pf)
	}
	return protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: deduped})
}

// vocabExtension resolves the (ramp.v1.vocab) extension descriptor (FieldOptions
// extension 50001) from the request-derived registry. Returns nil when the
// request does not carry the extension descriptor — buf invokes the plugin once
// per code-generation request (one per module/file split), and a request whose
// files do not import ramp/v1/vocab.proto legitimately has nothing to generate.
func vocabExtension(files *protoregistry.Files) protoreflect.ExtensionTypeDescriptor {
	var found protoreflect.ExtensionDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		exts := fd.Extensions()
		for i := 0; i < exts.Len(); i++ {
			ed := exts.Get(i)
			if ed.FullName() == "ramp.v1.vocab" && ed.Number() == vocabExtensionNumber {
				found = ed
				return false
			}
		}
		return true
	})
	if found == nil {
		return nil
	}
	return dynamicpb.NewExtensionType(found).TypeDescriptor()
}

func genMessage(gen *protogen.Plugin, ext protoreflect.ExtensionTypeDescriptor, msg *protogen.Message) error {
	for _, nested := range msg.Messages {
		if err := genMessage(gen, ext, nested); err != nil {
			return err
		}
	}
	for _, field := range msg.Fields {
		tokens, ok := readVocab(ext, field.Desc)
		if !ok {
			continue
		}
		pkg, known := axisPackage[string(field.Desc.Name())]
		if !known {
			// Field carries vocab but is outside pilot scope — skip.
			continue
		}
		if err := emit(gen, pkg, field, tokens); err != nil {
			return err
		}
	}
	return nil
}

// readVocab reads the repeated-string (ramp.v1.vocab) values off a field's
// options, structurally, via the request-derived extension resolver. It
// re-parses the raw options bytes so the dynamic extension is recognized.
func readVocab(ext protoreflect.ExtensionTypeDescriptor, field protoreflect.FieldDescriptor) ([]string, bool) {
	opts, ok := field.Options().(*descriptorpb.FieldOptions)
	if !ok || opts == nil {
		return nil, false
	}

	// Re-marshal/unmarshal the options through a resolver that knows the
	// dynamic (ramp.v1.vocab) extension, so its bytes are decoded into the
	// dynamic extension rather than left in UnknownFields.
	raw, err := proto.Marshal(opts)
	if err != nil {
		return nil, false
	}
	decoded := &descriptorpb.FieldOptions{}
	if err := (proto.UnmarshalOptions{
		Resolver: resolverWith(ext),
	}).Unmarshal(raw, decoded); err != nil {
		return nil, false
	}

	val := decoded.ProtoReflect().Get(ext)
	list := val.List()
	if list.Len() == 0 {
		return nil, false
	}
	tokens := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		tokens = append(tokens, list.Get(i).String())
	}
	return tokens, true
}

// extResolver adapts a single ExtensionTypeDescriptor to the
// protoregistry.ExtensionTypeResolver interface used by Unmarshal.
type extResolver struct {
	ext protoreflect.ExtensionTypeDescriptor
}

func resolverWith(ext protoreflect.ExtensionTypeDescriptor) extResolver {
	return extResolver{ext: ext}
}

func (r extResolver) FindExtensionByName(field protoreflect.FullName) (protoreflect.ExtensionType, error) {
	if field == r.ext.FullName() {
		return r.ext.Type(), nil
	}
	return nil, protoregistry.NotFound
}

func (r extResolver) FindExtensionByNumber(message protoreflect.FullName, field protoreflect.FieldNumber) (protoreflect.ExtensionType, error) {
	if message == r.ext.ContainingMessage().FullName() && field == r.ext.Number() {
		return r.ext.Type(), nil
	}
	return nil, protoregistry.NotFound
}

func emit(gen *protogen.Plugin, pkg string, field *protogen.Field, tokens []string) error {
	filename := fmt.Sprintf("%s/%s.go", pkg, pkg)
	g := gen.NewGeneratedFile(filename, protogen.GoImportPath(""))

	g.P("// Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("//")
	g.P("// Source vocabulary: (ramp.v1.vocab) on field ", field.Desc.FullName(), ".")
	g.P("// The token list is authored solely in that field option; these")
	g.P("// constants and IsRegistered derive from it and cannot drift.")
	g.P()
	g.P("package ", pkg)
	g.P()

	// const block — PascalCase constant name → token string.
	g.P("const (")
	for _, tok := range tokens {
		g.P("\t", constName(tok), " = ", fmt.Sprintf("%q", tok))
	}
	g.P(")")
	g.P()

	// All slice — registered tokens in declaration order.
	g.P("// All lists every registered token in registration order.")
	g.P("var All = []string{")
	for _, tok := range tokens {
		g.P("\t", constName(tok), ",")
	}
	g.P("}")
	g.P()

	// registered set for O(1) membership.
	g.P("var registered = map[string]struct{}{")
	sorted := append([]string(nil), tokens...)
	sort.Strings(sorted)
	for _, tok := range sorted {
		g.P("\t", constName(tok), ": {},")
	}
	g.P("}")
	g.P()

	// IsRegistered membership check.
	g.P("// IsRegistered reports whether s is a registered bare token. Namespaced")
	g.P("// (vendor:token) values are NOT registered tokens and return false.")
	g.P("func IsRegistered(s string) bool {")
	g.P("\t_, ok := registered[s]")
	g.P("\treturn ok")
	g.P("}")

	return nil
}

// constName converts a vocabulary token to a PascalCase Go identifier.
// "accesses" → "Accesses", "units-manufactured" → "UnitsManufactured",
// "sq-km" → "SqKm".
func constName(token string) string {
	parts := strings.FieldsFunc(token, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}
