// Command protoc-gen-rampvocab is a buf/protoc plugin that reads the RAMP
// vocabulary options off every annotated field and enum value and emits, per
// axis and per SDK language (Go, TypeScript, Python), a typed package/module
// with one string constant per registered token, an All/ALL collection, and an
// IsRegistered/isRegistered/is_registered membership check.
//
// Two pairs of options carry the data, one pair per descriptor kind — the
// repeated tokens and the scalar generated-package name:
//   - (ramp.v1.vocab) / (ramp.v1.vocab_package)           — FieldOptions
//     extensions 50001/50003, on fields whose axis is the field itself
//     (Pricing.unit, Quota.metric).
//   - (ramp.v1.vocab_enum) / (ramp.v1.vocab_enum_package) — EnumValueOptions
//     extensions 50002/50004, on enum values that SELECT an axis (RestrictionKind
//     values select the function / geography / user-type token lists carried in
//     Restriction.permitted/prohibited).
//
// Everything — the tokens AND the target package name — is authored in exactly
// one place, the options on the field or enum value, so the generated constants,
// the membership check, and the package layout all derive from the proto and
// cannot drift. There is no hand-maintained axis→package table in this plugin.
// The plugin reads the options STRUCTURALLY (it does not parse CEL).
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
	// Token extensions — the repeated registered tokens for an axis.
	vocabFieldExtNumber = 50001 // (ramp.v1.vocab) on FieldOptions
	vocabEnumExtNumber  = 50002 // (ramp.v1.vocab_enum) on EnumValueOptions
	// Package extensions — the generated package/module name for the axis. These
	// replace the former hand-maintained axis→package maps: the mapping now lives
	// in the proto, next to the tokens, so adding an axis touches only the .proto
	// and never this plugin.
	vocabFieldPkgExtNumber = 50003 // (ramp.v1.vocab_package) on FieldOptions
	vocabEnumPkgExtNumber  = 50004 // (ramp.v1.vocab_enum_package) on EnumValueOptions
	// Alias extension — accepted spellings that canonicalise to a registered
	// token, authored beside the tokens as "alias=canonical" entries. Enum-value
	// axes only today; a field-axis twin takes the next slot when an axis needs
	// one.
	vocabEnumAliasExtNumber = 50005 // (ramp.v1.vocab_enum_alias) on EnumValueOptions

	vocabFieldExtName     = "ramp.v1.vocab"
	vocabEnumExtName      = "ramp.v1.vocab_enum"
	vocabFieldPkgExtName  = "ramp.v1.vocab_package"
	vocabEnumPkgExtName   = "ramp.v1.vocab_enum_package"
	vocabEnumAliasExtName = "ramp.v1.vocab_enum_alias"
)

func main() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)

		resolver, err := buildResolver(gen.Request.GetProtoFile())
		if err != nil {
			return fmt.Errorf("build extension resolver: %w", err)
		}
		fieldExt := findExtension(resolver, vocabFieldExtName, vocabFieldExtNumber)
		fieldPkgExt := findExtension(resolver, vocabFieldPkgExtName, vocabFieldPkgExtNumber)
		enumExt := findExtension(resolver, vocabEnumExtName, vocabEnumExtNumber)
		enumPkgExt := findExtension(resolver, vocabEnumPkgExtName, vocabEnumPkgExtNumber)
		enumAliasExt := findExtension(resolver, vocabEnumAliasExtName, vocabEnumAliasExtNumber)
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
					if err := genMessage(gen, fieldExt, fieldPkgExt, msg); err != nil {
						return err
					}
				}
			}
			if enumExt != nil {
				for _, enum := range f.Enums {
					if err := genEnum(gen, enumExt, enumPkgExt, enumAliasExt, enum); err != nil {
						return err
					}
				}
				// Enums nested in messages.
				for _, msg := range f.Messages {
					if err := genNestedEnums(gen, enumExt, enumPkgExt, enumAliasExt, msg); err != nil {
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

func genMessage(gen *protogen.Plugin, tokensExt, pkgExt protoreflect.ExtensionTypeDescriptor, msg *protogen.Message) error {
	for _, nested := range msg.Messages {
		if err := genMessage(gen, tokensExt, pkgExt, nested); err != nil {
			return err
		}
	}
	for _, field := range msg.Fields {
		tokens, err := readVocabList(tokensExt, field.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab) on %s: %w", field.Desc.FullName(), err)
		}
		if len(tokens) == 0 {
			continue
		}
		pkg, err := readVocabString(pkgExt, field.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab_package) on %s: %w", field.Desc.FullName(), err)
		}
		if pkg == "" {
			return fmt.Errorf("field %s carries (ramp.v1.vocab) but no (ramp.v1.vocab_package); add the package name on the field", field.Desc.FullName())
		}
		// A field axis carries no alias option today; it still emits the alias
		// face (empty) so every axis package has the same shape.
		if err := emit(gen, pkg, string(field.Desc.FullName()), tokens, nil); err != nil {
			return err
		}
	}
	return nil
}

func genNestedEnums(gen *protogen.Plugin, tokensExt, pkgExt, aliasExt protoreflect.ExtensionTypeDescriptor, msg *protogen.Message) error {
	for _, enum := range msg.Enums {
		if err := genEnum(gen, tokensExt, pkgExt, aliasExt, enum); err != nil {
			return err
		}
	}
	for _, nested := range msg.Messages {
		if err := genNestedEnums(gen, tokensExt, pkgExt, aliasExt, nested); err != nil {
			return err
		}
	}
	return nil
}

func genEnum(gen *protogen.Plugin, tokensExt, pkgExt, aliasExt protoreflect.ExtensionTypeDescriptor, enum *protogen.Enum) error {
	for _, val := range enum.Values {
		tokens, err := readVocabList(tokensExt, val.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab_enum) on %s: %w", val.Desc.FullName(), err)
		}
		if len(tokens) == 0 {
			continue
		}
		pkg, err := readVocabString(pkgExt, val.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab_enum_package) on %s: %w", val.Desc.FullName(), err)
		}
		if pkg == "" {
			return fmt.Errorf("enum value %s carries (ramp.v1.vocab_enum) but no (ramp.v1.vocab_enum_package); add the package name on the value", val.Desc.FullName())
		}
		rawAliases, err := readVocabList(aliasExt, val.Desc.Options())
		if err != nil {
			return fmt.Errorf("read (ramp.v1.vocab_enum_alias) on %s: %w", val.Desc.FullName(), err)
		}
		aliases, err := parseAliases(tokens, rawAliases)
		if err != nil {
			return fmt.Errorf("(ramp.v1.vocab_enum_alias) on %s: %w", val.Desc.FullName(), err)
		}
		if err := emit(gen, pkg, string(val.Desc.FullName()), tokens, aliases); err != nil {
			return err
		}
	}
	return nil
}

// aliasEntry is one accepted spelling and the registered token it canonicalises
// to. Emitted alias-sorted so the generated files are stable.
type aliasEntry struct {
	alias     string
	canonical string
}

// parseAliases reads "alias=canonical" entries against the axis's registered
// tokens and refuses anything the generated Canonical face could not honour:
// an alias that is itself a token (it would shadow a registration), a canonical
// that is not a token (it would canonicalise INTO an unregistered value), a
// duplicate alias, and an alias that is not already trimmed and lowercase (the
// SDK folds before it looks up, so an alias the fold can never produce is dead).
// Codegen fails loudly here rather than emitting a map that quietly misroutes.
func parseAliases(tokens []string, raw []string) ([]aliasEntry, error) {
	registered := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		registered[t] = true
	}
	seen := make(map[string]bool, len(raw))
	out := make([]aliasEntry, 0, len(raw))
	for _, entry := range raw {
		alias, canonical, ok := strings.Cut(entry, "=")
		if !ok || alias == "" || canonical == "" {
			return nil, fmt.Errorf("alias entry %q is not \"alias=canonical\"", entry)
		}
		if strings.Contains(canonical, "=") {
			return nil, fmt.Errorf("alias entry %q carries more than one '='", entry)
		}
		if alias != strings.ToLower(strings.TrimSpace(alias)) {
			return nil, fmt.Errorf("alias %q must be authored trimmed and lowercase — the SDK folds a token before it looks it up, so this spelling could never match", alias)
		}
		if registered[alias] {
			return nil, fmt.Errorf("alias %q is itself a registered token; an alias cannot shadow a registration", alias)
		}
		if !registered[canonical] {
			return nil, fmt.Errorf("alias %q canonicalises to %q, which is not a registered token on this axis", alias, canonical)
		}
		if seen[alias] {
			return nil, fmt.Errorf("alias %q is declared twice", alias)
		}
		seen[alias] = true
		out = append(out, aliasEntry{alias: alias, canonical: canonical})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].alias < out[j].alias })
	return out, nil
}

// decodeThroughExt re-parses a descriptor's options through a resolver that knows
// the dynamic vocab extension, so its bytes are decoded into the extension rather
// than left in UnknownFields. opts is the descriptor's Options() (a
// *descriptorpb.FieldOptions or *EnumValueOptions). A generic plugin binary has
// no ramp.v1 extensions registered globally, hence this request-derived resolver.
func decodeThroughExt(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) (protoreflect.Message, error) {
	raw, err := proto.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal options: %w", err)
	}
	decoded := opts.ProtoReflect().New().Interface()
	if err := (proto.UnmarshalOptions{Resolver: resolverWith(ext)}).Unmarshal(raw, decoded); err != nil {
		return nil, fmt.Errorf("unmarshal options through vocab resolver: %w", err)
	}
	return decoded.ProtoReflect(), nil
}

// readVocabList reads the repeated-string token values for ext off opts. Returns
// (nil, nil) when the descriptor legitimately carries no such option — including
// when ext is nil (the request did not carry the extension descriptor) — and
// (nil, err) only on a real decode failure, so a resolver/marshal fault surfaces
// instead of masquerading as "no vocab".
func readVocabList(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) ([]string, error) {
	if ext == nil || opts == nil {
		return nil, nil
	}
	m, err := decodeThroughExt(ext, opts)
	if err != nil {
		return nil, err
	}
	list := m.Get(ext).List()
	if list.Len() == 0 {
		return nil, nil
	}
	tokens := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		tokens = append(tokens, list.Get(i).String())
	}
	return tokens, nil
}

// readVocabString reads the scalar string value for ext off opts — the axis's
// generated package name. Returns "" when unset or when ext is nil.
func readVocabString(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) (string, error) {
	if ext == nil || opts == nil {
		return "", nil
	}
	m, err := decodeThroughExt(ext, opts)
	if err != nil {
		return "", err
	}
	if !m.Has(ext) {
		return "", nil
	}
	return m.Get(ext).String(), nil
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
	render    func(g *protogen.GeneratedFile, pkg, source string, entries []constEntry, aliases []aliasEntry)
}

var langs = []langSpec{
	{name: "go", filename: func(p string) string { return "go/vocab/" + p + "/" + p + ".go" }, identName: constName, render: renderGo},
	{name: "ts", filename: func(p string) string { return "ts/vocab/" + p + ".ts" }, identName: constName, render: renderTS},
	{name: "python", filename: func(p string) string { return "python/vocab/" + p + ".py" }, identName: pyConstName, render: renderPy},
}

// emit writes the vocab package for one axis in every target language. Paths are
// relative to the plugin's out dir (../gen), so files land in gen/go/vocab,
// gen/ts/vocab, and gen/python/vocab respectively.
func emit(gen *protogen.Plugin, pkg, source string, tokens []string, aliases []aliasEntry) error {
	for _, l := range langs {
		entries, err := constEntriesFor(tokens, l.identName)
		if err != nil {
			return fmt.Errorf("%s vocab package %s (%s): %w", l.name, pkg, source, err)
		}
		g := gen.NewGeneratedFile(l.filename(pkg), protogen.GoImportPath(""))
		l.render(g, pkg, source, entries, aliases)
	}
	return nil
}

// identFor returns the generated identifier for a registered token, so an alias
// map names its canonical target through the constant rather than restating the
// string. parseAliases has already proven the target is registered.
func identFor(entries []constEntry, token string) string {
	for _, e := range entries {
		if e.token == token {
			return e.ident
		}
	}
	return fmt.Sprintf("%q", token) // unreachable after parseAliases; keeps output valid
}

// sortedByToken returns entries token-sorted, for stable membership-set output.
func sortedByToken(entries []constEntry) []constEntry {
	sorted := append([]constEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].token < sorted[j].token })
	return sorted
}

func renderGo(g *protogen.GeneratedFile, pkg, source string, entries []constEntry, aliases []aliasEntry) {
	g.P("// Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("//")
	g.P("// Source vocabulary: on ", source, ".")
	g.P("// The token list is authored solely in that option; these")
	g.P("// constants, IsRegistered, Aliases and Canonical derive from it and cannot drift.")
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
	g.P()
	g.P("// Aliases maps an accepted alias spelling to the registered token it")
	g.P("// canonicalises to. Authored beside the tokens; an axis without aliases")
	g.P("// carries an empty map so every axis has the same face.")
	g.P("var Aliases = map[string]string{")
	for _, a := range aliases {
		g.P("\t", fmt.Sprintf("%q", a.alias), ": ", identFor(entries, a.canonical), ",")
	}
	g.P("}")
	g.P()
	g.P("// Canonical returns the registered token s is an alias of, or s unchanged")
	g.P("// when it is not an alias. It neither trims nor case-folds: the SDK folds a")
	g.P("// token before it looks it up here.")
	g.P("func Canonical(s string) string {")
	g.P("\tif c, ok := Aliases[s]; ok {")
	g.P("\t\treturn c")
	g.P("\t}")
	g.P("\treturn s")
	g.P("}")
}

func renderTS(g *protogen.GeneratedFile, pkg, source string, entries []constEntry, aliases []aliasEntry) {
	g.P("// Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("//")
	g.P("// Source vocabulary: on ", source, ".")
	g.P("// The token list is authored solely in that option; these constants,")
	g.P("// isRegistered, Aliases and canonical derive from it and cannot drift.")
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
	g.P()
	g.P("// Aliases maps an accepted alias spelling to the registered token it")
	g.P("// canonicalises to. Authored beside the tokens; an axis without aliases")
	g.P("// carries an empty map so every axis has the same face.")
	g.P("export const Aliases: ReadonlyMap<string, string> = new Map<string, string>([")
	for _, a := range aliases {
		g.P("  [", fmt.Sprintf("%q", a.alias), ", ", identFor(entries, a.canonical), "],")
	}
	g.P("]);")
	g.P()
	g.P("// canonical returns the registered token s is an alias of, or s unchanged")
	g.P("// when it is not an alias. It neither trims nor case-folds: the SDK folds a")
	g.P("// token before it looks it up here.")
	g.P("export function canonical(s: string): string {")
	g.P("  return Aliases.get(s) ?? s;")
	g.P("}")
}

func renderPy(g *protogen.GeneratedFile, pkg, source string, entries []constEntry, aliases []aliasEntry) {
	g.P("# Code generated by protoc-gen-rampvocab. DO NOT EDIT.")
	g.P("#")
	g.P("# Source vocabulary: on ", source, ".")
	g.P("# The token list is authored solely in that option; these constants,")
	g.P("# is_registered, ALIASES and canonical derive from it and cannot drift.")
	g.P()
	g.P("from collections.abc import Mapping")
	g.P("from types import MappingProxyType")
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
	g.P()
	g.P()
	g.P("# ALIASES maps an accepted alias spelling to the registered token it")
	g.P("# canonicalises to. Authored beside the tokens; an axis without aliases")
	g.P("# carries an empty mapping so every axis has the same face.")
	g.P("ALIASES: Mapping[str, str] = MappingProxyType({")
	for _, a := range aliases {
		g.P("    ", fmt.Sprintf("%q", a.alias), ": ", identFor(entries, a.canonical), ",")
	}
	g.P("})")
	g.P()
	g.P()
	g.P("def canonical(s: str) -> str:")
	g.P(`    """Return the registered token s is an alias of, or s unchanged (no trimming or case folding: the SDK folds first)."""`)
	g.P("    return ALIASES.get(s, s)")
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
	"Aliases":      true,
	"Canonical":    true,
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
var pyReservedIdents = map[string]bool{"ALL": true, "ALIASES": true}

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
