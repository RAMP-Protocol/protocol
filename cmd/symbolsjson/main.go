// Command symbolsjson renders the RAMP proto symbol table as a JSON view for the
// docs site. Like cmd/vocabjson it is a recomputed view, never a second source of
// truth: it walks the generated FileDescriptor (rampv1.File_ramp_v1_ramp_proto) and
// emits, for every message, field, enum, enum value, service and method, the
// reference-page anchor that symbol lives at.
//
// The rehype-proto-autolink plugin consumes this to turn bare `Message.field` /
// `Service.Method` / `ENUM_VALUE` / `TypeName` inline code spans in the docs into
// validated links — and to FAIL THE BUILD on a high-confidence proto reference that
// resolves to nothing (the deterministic drift guard). symbols.json is gitignored and
// regenerated on every docs build, so it cannot drift from the contract.
//
// It needs only the Go toolchain plus the protobuf runtime already in go.mod (no buf,
// no network), so the docs deploy build (AWS Amplify) can regenerate it in a preBuild
// step, exactly like cmd/vocabjson.
//
// Usage:
//
//	go run ./cmd/symbolsjson -o website/src/data/symbols.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// refPage is the docs URL path where the proto reference renders. Every type heads a
// `### <Name>` section there, so a symbol's anchor is the slugged heading name. Fields,
// enum values and methods have no heading of their own, so they point at their owning
// message / enum / service heading.
const refPage = "/reference/proto-ramp/"

type symbol struct {
	Kind string `json:"kind"`
	Page string `json:"page"`
	// Heading is the reference-page heading text; the autolink plugin slugs it
	// (github-slugger) to build the anchor. Empty means resolved-but-ambiguous
	// (e.g. a short enum-value form shared by two enums): valid for the guard,
	// but not linked.
	Heading string `json:"heading"`
}

// buildSymbols walks the RAMP file descriptor and returns the full symbol table.
func buildSymbols() map[string]symbol {
	syms := map[string]symbol{}
	add := func(key string, s symbol) {
		if existing, ok := syms[key]; ok {
			// Collision (e.g. a short enum-value form shared across enums): keep it
			// resolvable for the guard, but drop the now-ambiguous link target.
			if existing.Heading != "" {
				existing.Heading = ""
				syms[key] = existing
			}
			return
		}
		syms[key] = s
	}

	fd := rampv1.File_ramp_v1_ramp_proto
	walkMessages(fd.Messages(), add)
	walkEnums(fd.Enums(), add)
	for i := 0; i < fd.Services().Len(); i++ {
		svc := fd.Services().Get(i)
		name := string(svc.Name())
		add(name, symbol{Kind: "service", Page: refPage, Heading: name})
		for j := 0; j < svc.Methods().Len(); j++ {
			m := svc.Methods().Get(j)
			add(name+"."+string(m.Name()), symbol{Kind: "method", Page: refPage, Heading: name})
		}
	}
	return syms
}

func main() {
	out := flag.String("o", "", "output path for symbols.json (default: stdout)")
	flag.Parse()

	data, err := json.MarshalIndent(buildSymbols(), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "symbolsjson: marshal: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if *out == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "symbolsjson: write %s: %v\n", *out, err)
		os.Exit(1)
	}
}

func walkMessages(mds protoreflect.MessageDescriptors, add func(string, symbol)) {
	for i := 0; i < mds.Len(); i++ {
		md := mds.Get(i)
		if md.IsMapEntry() {
			continue // synthetic map<k,v> entry types are not user-visible
		}
		name := string(md.Name())
		add(name, symbol{Kind: "message", Page: refPage, Heading: name})
		for j := 0; j < md.Fields().Len(); j++ {
			f := md.Fields().Get(j)
			add(name+"."+string(f.Name()), symbol{Kind: "field", Page: refPage, Heading: name})
			// Docs may use the proto3-JSON camelCase field name; index it too so a
			// `Message.fieldName` reference resolves and links.
			if jn := f.JSONName(); jn != "" && jn != string(f.Name()) {
				add(name+"."+jn, symbol{Kind: "field", Page: refPage, Heading: name})
			}
		}
		walkMessages(md.Messages(), add) // nested messages
		walkEnums(md.Enums(), add)       // nested enums
	}
}

func walkEnums(eds protoreflect.EnumDescriptors, add func(string, symbol)) {
	for i := 0; i < eds.Len(); i++ {
		ed := eds.Get(i)
		name := string(ed.Name())
		add(name, symbol{Kind: "enum", Page: refPage, Heading: name})
		prefix := screamingSnake(name) + "_"
		for j := 0; j < ed.Values().Len(); j++ {
			full := string(ed.Values().Get(j).Name())
			add(full, symbol{Kind: "enum_value", Page: refPage, Heading: name})
			// Docs commonly use the short form (PER_UNIT for PRICING_MODEL_PER_UNIT);
			// index it too so it links and resolves. Collisions across enums become
			// validate-only via add()'s dedup.
			if short := strings.TrimPrefix(full, prefix); short != full && short != "" {
				add(short, symbol{Kind: "enum_value", Page: refPage, Heading: name})
			}
		}
	}
}

// screamingSnake converts a PascalCase type name to its SCREAMING_SNAKE_CASE enum
// value prefix (PricingModel -> PRICING_MODEL). If a given enum doesn't follow the
// convention the computed prefix simply won't match, and no short form is emitted.
func screamingSnake(pascal string) string {
	var b strings.Builder
	for i, r := range pascal {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}
