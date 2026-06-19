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

// fieldAxisPackage maps the FULL name of a field carrying (ramp.v1.vocab) to
// its generated Go package. Keyed by full name (not the bare field name) so two
// like-named fields in different messages cannot collide onto one package.
var fieldAxisPackage = map[string]string{
	"ramp.v1.Pricing.unit": "pricingunits",
	"ramp.v1.Quota.metric": "quotametrics",
}

// enumAxisPackage maps the FULL name of an enum value carrying
// (ramp.v1.vocab_enum) to its generated Go package.
var enumAxisPackage = map[string]string{
	"ramp.v1.RESTRICTION_KIND_FUNCTION":  "functiontokens",
	"ramp.v1.RESTRICTION_KIND_GEOGRAPHY": "geographytokens",
	"ramp.v1.RESTRICTION_KIND_USER_TYPE": "usertypes",
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
		tokens, err := readVocab(ext, field.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab) on %s: %w", field.Desc.FullName(), err)
		}
		if len(tokens) == 0 {
			continue
		}
		pkg, known := fieldAxisPackage[string(field.Desc.FullName())]
		if !known {
			return fmt.Errorf("field %s carries (ramp.v1.vocab) but is not mapped to a package; add %q to fieldAxisPackage in protoc-gen-rampvocab", field.Desc.FullName(), field.Desc.FullName())
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
		tokens, err := readVocab(ext, val.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab_enum) on %s: %w", val.Desc.FullName(), err)
		}
		if len(tokens) == 0 {
			continue
		}
		pkg, known := enumAxisPackage[string(val.Desc.FullName())]
		if !known {
			return fmt.Errorf("enum value %s carries (ramp.v1.vocab_enum) but is not mapped to a package; add %q to enumAxisPackage in protoc-gen-rampvocab", val.Desc.FullName(), val.Desc.FullName())
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
// Returns (nil, nil) when the descriptor legitimately carries no vocab option,
// and (nil, err) when decoding fails — the two are kept distinct so a real
// resolver/marshal failure surfaces instead of masquerading as "no vocab".
func readVocab(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) ([]string, error) {
	if opts == nil {
		return nil, nil
	}
	// Re-marshal/unmarshal the options through a resolver that knows the dynamic
	// vocab extension, so its bytes are decoded into the dynamic extension
	// rather than left in UnknownFields.
	raw, err := proto.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal options: %w", err)
	}
	decoded := opts.ProtoReflect().New().Interface()
	if err := (proto.UnmarshalOptions{
		Resolver: resolverWith(ext),
	}).Unmarshal(raw, decoded); err != nil {
		return nil, fmt.Errorf("unmarshal options through vocab resolver: %w", err)
	}

	val := decoded.ProtoReflect().Get(ext)
	list := val.List()
	if list.Len() == 0 {
		return nil, nil
	}
	tokens := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		tokens = append(tokens, list.Get(i).String())
	}
	return tokens, nil
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

// langSpec describes how one target language renders a vocab axis. The shared
// core — resolver, option reading, axis maps, token extraction, collision
// detection — is language-agnostic; only these per-language bits differ.
// Emitting every language from ONE plugin pass over ONE option set is what makes
// the three SDKs unable to drift from each other (no cross-language parity check
// is needed: all are produced from the same tokens in the same pass).
type langSpec struct {
	name      string
	filename  func(pkg string) string // path relative to the plugin out dir (../gen)
	identName func(token string) (string, error)
	render    func(g *protogen.GeneratedFile, pkg, source string, entries []constEntry)
}

var langs = []langSpec{
	{name: "go", filename: func(p string) string { return "go/vocab/" + p + "/" + p + ".go" }, identName: constName, render: renderGo},
	{name: "ts", filename: func(p string) string { return "ts/vocab/" + p + ".ts" }, identName: constName, render: renderTS},
	{name: "python", filename: func(p string) string { return "python/vocab/" + p + ".py" }, identName: pyConstName, render: renderPy},
}

// emit writes the vocab package for one axis in every target language. Paths are
// relative to the plugin's out dir (../gen), so files land in gen/go/vocab,
// gen/ts/vocab, and gen/python/vocab respectively.
func emit(gen *protogen.Plugin, pkg, source string, tokens []string) error {
	for _, l := range langs {
		entries, err := constEntriesFor(tokens, l.identName)
		if err != nil {
			return fmt.Errorf("%s vocab package %s (%s): %w", l.name, pkg, source, err)
		}
		g := gen.NewGeneratedFile(l.filename(pkg), protogen.GoImportPath(""))
		l.render(g, pkg, source, entries)
	}
	return nil
}

// sortedByToken returns entries token-sorted, for stable membership-set output.
func sortedByToken(entries []constEntry) []constEntry {
	sorted := append([]constEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].token < sorted[j].token })
	return sorted
}

func renderGo(g *protogen.GeneratedFile, pkg, source string, entries []constEntry) {
	g.P("// Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("//")
	g.P("// Source vocabulary: on ", source, ".")
	g.P("// The token list is authored solely in that option; these")
	g.P("// constants and IsRegistered derive from it and cannot drift.")
	g.P()
	g.P("package ", pkg)
	g.P()
	g.P("const (")
	for _, e := range entries {
		g.P("\t", e.ident, " = ", fmt.Sprintf("%q", e.token))
	}
	g.P(")")
	g.P()
	g.P("// All lists every registered token in registration order.")
	g.P("var All = []string{")
	for _, e := range entries {
		g.P("\t", e.ident, ",")
	}
	g.P("}")
	g.P()
	g.P("var registered = map[string]struct{}{")
	for _, e := range sortedByToken(entries) {
		g.P("\t", e.ident, ": {},")
	}
	g.P("}")
	g.P()
	g.P("// IsRegistered reports whether s is a registered bare token. Namespaced")
	g.P("// (vendor:token) values are NOT registered tokens and return false.")
	g.P("func IsRegistered(s string) bool {")
	g.P("\t_, ok := registered[s]")
	g.P("\treturn ok")
	g.P("}")
}

func renderTS(g *protogen.GeneratedFile, pkg, source string, entries []constEntry) {
	g.P("// Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("//")
	g.P("// Source vocabulary: on ", source, ".")
	g.P("// The token list is authored solely in that option; these constants and")
	g.P("// isRegistered derive from it and cannot drift.")
	g.P()
	for _, e := range entries {
		g.P("export const ", e.ident, " = ", fmt.Sprintf("%q", e.token), ";")
	}
	g.P()
	g.P("// All lists every registered token in registration order.")
	g.P("export const All = [")
	for _, e := range entries {
		g.P("  ", e.ident, ",")
	}
	g.P("] as const;")
	g.P()
	g.P("const registered: ReadonlySet<string> = new Set(All);")
	g.P()
	g.P("// isRegistered reports whether s is a registered bare token. Namespaced")
	g.P("// (vendor:token) values are NOT registered tokens and return false.")
	g.P("export function isRegistered(s: string): boolean {")
	g.P("  return registered.has(s);")
	g.P("}")
}

func renderPy(g *protogen.GeneratedFile, pkg, source string, entries []constEntry) {
	g.P("# Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("#")
	g.P("# Source vocabulary: on ", source, ".")
	g.P("# The token list is authored solely in that option; these constants and")
	g.P("# is_registered derive from it and cannot drift.")
	g.P()
	for _, e := range entries {
		g.P(e.ident, " = ", fmt.Sprintf("%q", e.token))
	}
	g.P()
	g.P("# ALL lists every registered token in registration order.")
	g.P("ALL = (")
	for _, e := range entries {
		g.P("    ", e.ident, ",")
	}
	g.P(")")
	g.P()
	g.P("_REGISTERED = frozenset(ALL)")
	g.P()
	g.P()
	g.P("def is_registered(s: str) -> bool:")
	g.P(`    """Return True if s is a registered bare token (namespaced vendor:token values return False)."""`)
	g.P("    return s in _REGISTERED")
}

// constEntry pairs a generated identifier with its source token.
type constEntry struct {
	ident string
	token string
}

// constEntriesFor converts tokens to (ident, token) pairs in declaration order
// using identName, erroring if any token does not yield a valid identifier or if
// two tokens map to the same one. Codegen fails loudly rather than emitting a
// broken or silently-shadowed constant. Collision detection is per-language: two
// tokens may collide in one language's identifier scheme but not another's.
func constEntriesFor(tokens []string, identName func(string) (string, error)) ([]constEntry, error) {
	entries := make([]constEntry, 0, len(tokens))
	byIdent := make(map[string]string, len(tokens))
	for _, tok := range tokens {
		id, err := identName(tok)
		if err != nil {
			return nil, err
		}
		if prev, dup := byIdent[id]; dup {
			return nil, fmt.Errorf("tokens %q and %q both map to identifier %q", prev, tok, id)
		}
		byIdent[id] = tok
		entries = append(entries, constEntry{ident: id, token: tok})
	}
	return entries, nil
}

// constEntries builds Go-identifier entries (used by the Go emitter and tests);
// other languages call constEntriesFor with their own identName.
func constEntries(tokens []string) ([]constEntry, error) {
	return constEntriesFor(tokens, constName)
}

// reservedIdents are identifiers the emitted package already defines; a token
// must not map onto one of them.
var reservedIdents = map[string]bool{
	"All":          true,
	"IsRegistered": true,
}

// constNameSpecial maps tokens that do not yield a valid, non-colliding exported
// identifier to an explicit one.
var constNameSpecial = map[string]string{
	"*":   "Worldwide", // "*" is not a legal Go identifier
	"all": "AllUses",   // bare "All" would shadow the emitted All slice
}

// constName converts a vocabulary token to an exported PascalCase Go identifier.
// "accesses" → "Accesses", "units-manufactured" → "UnitsManufactured",
// "sq-km" → "SqKm", "news_publisher" → "NewsPublisher", "*" → "Worldwide".
//
// It returns an error (rather than emitting a broken constant) when a token does
// not yield a valid exported identifier — e.g. a leading digit — or collides
// with one the package reserves; the fix is to add a constNameSpecial mapping.
func constName(token string) (string, error) {
	if s, ok := constNameSpecial[token]; ok {
		// A special-case mapping must itself be a valid, non-reserved identifier;
		// otherwise a bad entry would emit broken Go silently.
		if !isExportedIdent(s) {
			return "", fmt.Errorf("constNameSpecial[%q] = %q is not a valid exported Go identifier", token, s)
		}
		if reservedIdents[s] {
			return "", fmt.Errorf("constNameSpecial[%q] = %q collides with a reserved identifier", token, s)
		}
		return s, nil
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
	id := b.String()
	if !isExportedIdent(id) {
		return "", fmt.Errorf("token %q does not yield a valid exported Go identifier (got %q); add a constNameSpecial mapping", token, id)
	}
	if reservedIdents[id] {
		return "", fmt.Errorf("token %q maps to reserved identifier %q; add a constNameSpecial mapping", token, id)
	}
	return id, nil
}

// isExportedIdent reports whether s is a legal exported Go identifier over the
// ASCII token alphabet: an uppercase first letter, then letters/digits. The same
// rule applies to the TypeScript const names (TS uses the same PascalCase).
func isExportedIdent(s string) bool {
	if s == "" {
		return false
	}
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// pyConstNameSpecial / pyReservedIdents are the Python (UPPER_SNAKE) twins of
// constNameSpecial / reservedIdents above. ALL is the emitted tuple; the
// is_registered function is lowercase, so it never collides with an UPPER_SNAKE
// constant and need not be reserved.
var pyConstNameSpecial = map[string]string{
	"*":   "WORLDWIDE",
	"all": "ALL_USES", // bare "ALL" would shadow the emitted ALL tuple
}
var pyReservedIdents = map[string]bool{"ALL": true}

// pyConstName converts a vocabulary token to an UPPER_SNAKE_CASE Python constant:
// "accesses" → "ACCESSES", "units-manufactured" → "UNITS_MANUFACTURED",
// "sq-km" → "SQ_KM", "*" → "WORLDWIDE". It errors (rather than emitting broken
// Python) on a token that cannot form a valid constant — e.g. a leading digit —
// or that collides with a reserved name; the fix is a pyConstNameSpecial mapping.
func pyConstName(token string) (string, error) {
	if s, ok := pyConstNameSpecial[token]; ok {
		if !isUpperSnakeIdent(s) {
			return "", fmt.Errorf("pyConstNameSpecial[%q] = %q is not a valid UPPER_SNAKE identifier", token, s)
		}
		if pyReservedIdents[s] {
			return "", fmt.Errorf("pyConstNameSpecial[%q] = %q collides with a reserved identifier", token, s)
		}
		return s, nil
	}
	parts := strings.FieldsFunc(token, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for i, p := range parts {
		parts[i] = strings.ToUpper(p)
	}
	id := strings.Join(parts, "_")
	if !isUpperSnakeIdent(id) {
		return "", fmt.Errorf("token %q does not yield a valid Python constant (got %q); add a pyConstNameSpecial mapping", token, id)
	}
	if pyReservedIdents[id] {
		return "", fmt.Errorf("token %q maps to reserved identifier %q; add a pyConstNameSpecial mapping", token, id)
	}
	return id, nil
}

// isUpperSnakeIdent reports whether s is a legal UPPER_SNAKE Python identifier
// over the ASCII token alphabet: an uppercase first letter, then uppercase
// letters / digits / underscores.
func isUpperSnakeIdent(s string) bool {
	if s == "" {
		return false
	}
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}
