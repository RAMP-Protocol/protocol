// Command protoc-gen-rampvocab is a buf/protoc plugin that reads the RAMP
// vocabulary options off every annotated field and enum value and emits, per
// axis, a typed Go package with one string constant per registered token, an
// All slice, and an IsRegistered membership check.
//
// Two options carry the tokens, one per descriptor kind:
//   - (ramp.v1.vocab)      — FieldOptions extension 50001, on fields whose
//                            axis is the field itself (Pricing.unit, Quota.metric).
//   - (ramp.v1.vocab_enum) — EnumValueOptions extension 50002, on enum values
//                            that SELECT an axis (RestrictionKind values select
//                            the function / geography / user-type token lists
//                            carried in Restriction.permitted/prohibited).
//
// The token list is authored in exactly one place — the option entries on the
// field or enum value — so the generated constants and the ingest-time
// membership check both derive from it and cannot drift. The plugin reads the
// options STRUCTURALLY (it does not parse CEL and emits no drift assertion).
//
// A generic plugin binary does not have ramp.v1's extensions registered in its
// global proto registry, so reading options through the global registry would
// silently miss them. To read them, the plugin builds a dynamicpb-backed
// extension resolver from the FileDescriptorProtos carried in the
// CodeGeneratorRequest and re-parses each descriptor's raw options bytes
// through that resolver.
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

const (
	// vocabFieldExtNumber is FieldOptions extension 50001 — (ramp.v1.vocab).
	vocabFieldExtNumber = 50001
	// vocabEnumExtNumber is EnumValueOptions extension 50002 — (ramp.v1.vocab_enum).
	vocabEnumExtNumber = 50002

	vocabFieldExtName = "ramp.v1.vocab"
	vocabEnumExtName  = "ramp.v1.vocab_enum"
)

// fieldAxisPackage maps a field name carrying (ramp.v1.vocab) to its generated
// Go package.
var fieldAxisPackage = map[string]string{
	"unit":   "pricingunits",
	"metric": "quotametrics",
}

// enumAxisPackage maps an enum-value name carrying (ramp.v1.vocab_enum) to its
// generated Go package.
var enumAxisPackage = map[string]string{
	"RESTRICTION_KIND_FUNCTION":  "functiontokens",
	"RESTRICTION_KIND_GEOGRAPHY": "geographytokens",
	"RESTRICTION_KIND_USER_TYPE": "usertypes",
}

func main() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)

		resolver, err := buildResolver(gen.Request.GetProtoFile())
		if err != nil {
			return fmt.Errorf("build extension resolver: %w", err)
		}
		fieldExt := findExtension(resolver, vocabFieldExtName, vocabFieldExtNumber)
		enumExt := findExtension(resolver, vocabEnumExtName, vocabEnumExtNumber)
		if fieldExt == nil && enumExt == nil {
			// This request carries neither vocab extension descriptor (e.g. a
			// sibling module split with no vocab-bearing descriptor). Nothing
			// to generate.
			return nil
		}

		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}
			if fieldExt != nil {
				for _, msg := range f.Messages {
					if err := genMessage(gen, fieldExt, msg); err != nil {
						return err
					}
				}
			}
			if enumExt != nil {
				for _, enum := range f.Enums {
					if err := genEnum(gen, enumExt, enum); err != nil {
						return err
					}
				}
				// Enums nested in messages.
				for _, msg := range f.Messages {
					if err := genNestedEnums(gen, enumExt, msg); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// buildResolver constructs a protoregistry.Files from the request's
// FileDescriptorProtos so the vocab extension types can be resolved.
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

// findExtension resolves a named extension descriptor from the request-derived
// registry. Returns nil when the request does not carry the extension
// descriptor — buf invokes the plugin once per code-generation request, and a
// request whose files do not import ramp/v1/vocab.proto legitimately has
// nothing to generate.
func findExtension(files *protoregistry.Files, name protoreflect.FullName, number protoreflect.FieldNumber) protoreflect.ExtensionTypeDescriptor {
	var found protoreflect.ExtensionDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		exts := fd.Extensions()
		for i := 0; i < exts.Len(); i++ {
			ed := exts.Get(i)
			if ed.FullName() == name && ed.Number() == number {
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
		tokens, ok := readVocab(ext, field.Desc.Options())
		if !ok {
			continue
		}
		pkg, known := fieldAxisPackage[string(field.Desc.Name())]
		if !known {
			// Field carries vocab but is outside known scope — skip.
			continue
		}
		if err := emit(gen, pkg, string(field.Desc.FullName()), tokens); err != nil {
			return err
		}
	}
	return nil
}

func genNestedEnums(gen *protogen.Plugin, ext protoreflect.ExtensionTypeDescriptor, msg *protogen.Message) error {
	for _, enum := range msg.Enums {
		if err := genEnum(gen, ext, enum); err != nil {
			return err
		}
	}
	for _, nested := range msg.Messages {
		if err := genNestedEnums(gen, ext, nested); err != nil {
			return err
		}
	}
	return nil
}

func genEnum(gen *protogen.Plugin, ext protoreflect.ExtensionTypeDescriptor, enum *protogen.Enum) error {
	for _, val := range enum.Values {
		tokens, ok := readVocab(ext, val.Desc.Options())
		if !ok {
			continue
		}
		pkg, known := enumAxisPackage[string(val.Desc.Name())]
		if !known {
			// Enum value carries vocab but is outside known scope — skip.
			continue
		}
		if err := emit(gen, pkg, string(val.Desc.FullName()), tokens); err != nil {
			return err
		}
	}
	return nil
}

// readVocab reads the repeated-string vocab values off a descriptor's options,
// structurally, via the request-derived extension resolver. It re-parses the
// raw options bytes so the dynamic extension is recognized. opts is the
// descriptor's Options() (a *descriptorpb.FieldOptions or *EnumValueOptions);
// the extension determines which is expected.
func readVocab(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) ([]string, bool) {
	if opts == nil {
		return nil, false
	}
	// Re-marshal/unmarshal the options through a resolver that knows the dynamic
	// vocab extension, so its bytes are decoded into the dynamic extension
	// rather than left in UnknownFields.
	raw, err := proto.Marshal(opts)
	if err != nil {
		return nil, false
	}
	decoded := opts.ProtoReflect().New().Interface()
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

func emit(gen *protogen.Plugin, pkg, source string, tokens []string) error {
	filename := fmt.Sprintf("%s/%s.go", pkg, pkg)
	g := gen.NewGeneratedFile(filename, protogen.GoImportPath(""))

	g.P("// Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("//")
	g.P("// Source vocabulary: on ", source, ".")
	g.P("// The token list is authored solely in that option; these")
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
// "sq-km" → "SqKm", "news_publisher" → "NewsPublisher", "*" → "Worldwide".
//
// Two tokens are special-cased to avoid colliding with the package's own
// generated identifiers: "*" → "Worldwide" (not a valid Go ident otherwise),
// and "all" → "AllUses" (the bare PascalCase "All" would shadow the All slice).
func constName(token string) string {
	switch token {
	case "*":
		return "Worldwide"
	case "all":
		return "AllUses"
	}
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
