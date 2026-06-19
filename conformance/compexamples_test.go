package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	compv1 "github.com/RAMP-Protocol/protocol/gen/go/comp/v1"
)

// compExamplesDir holds the canonical CoMP V1 worked examples vendored verbatim
// from the published standard (CoMP-1.0.md, "Implementation Guidance" section,
// finalized 2026-04-28). Each example in the spec wraps its payload in a single
// envelope key ("aisystem" or "package"); the vendored files contain the INNER
// object only, because that inner object is the actual CoMP root type the proto
// models (comp.v1.AISystem / comp.v1.Package). The envelope key is encoded in
// the filename suffix (.aisystem.json / .package.json) so the test can pick the
// correct generated root type per file.
const compExamplesDir = "testdata/comp_v1_examples"

// TestCompV1ExamplesRoundTrip is an adversarial conformance gate for the
// re-baselined comp.proto. For every canonical CoMP V1 example it:
//
//  1. Unmarshals the spec payload into the generated comp.v1 root type using
//     DEFAULT protojson options — i.e. DiscardUnknown is false, so unknown-field
//     rejection is ON. Any field present in the standard's example but ABSENT
//     from our proto surfaces here as an unmarshal error, proving a missing
//     field rather than silently dropping it.
//  2. Re-marshals the message and compares it (JSON-normalized, semantically)
//     against the original payload, catching any dropped or mutated value that a
//     successful-but-lossy unmarshal could hide.
//
// A green run is executable proof that comp.proto can losslessly carry every
// documented CoMP V1 example. A red run names the exact example and field.
func TestCompV1ExamplesRoundTrip(t *testing.T) {
	entries, err := os.ReadDir(compExamplesDir)
	if err != nil {
		t.Fatalf("reading %s: %v", compExamplesDir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)

	// Sanity floor: the standard ships 8 examples, each with a request
	// (AISystem) and a response (Package) payload — 16 vendored files. If the
	// testdata set is ever truncated, fail loudly rather than pass vacuously.
	if len(files) < 16 {
		t.Fatalf("expected at least 16 vendored CoMP V1 example payloads, found %d in %s", len(files), compExamplesDir)
	}

	for _, name := range files {
		name := name
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(compExamplesDir, name))
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}

			msg := rootTypeFor(t, name)

			// DEFAULT options: DiscardUnknown defaults to false, so any field in
			// the spec example that our proto does not declare is a hard error.
			if err := protojson.Unmarshal(raw, msg); err != nil {
				t.Fatalf("protojson.Unmarshal into %T FAILED (unknown/typed field in the CoMP V1 example is absent or mistyped in comp.proto): %v",
					msg, err)
			}

			// Re-marshal with enum-as-number (the CoMP V1 wire form uses the
			// integer List codes, e.g. "aiauth": 0, not "AUTH_METHOD_USER_AGENT")
			// and emit default values so an explicitly-set zero in the spec
			// example (e.g. "aiauth": 0, "resdis": 0) is not elided by proto3's
			// default-scalar omission and thus survives the value comparison.
			out, err := protojson.MarshalOptions{
				UseEnumNumbers:    true,
				EmitDefaultValues: true,
			}.Marshal(msg)
			if err != nil {
				t.Fatalf("protojson.Marshal of %T: %v", msg, err)
			}

			assertJSONSemanticEqual(t, name, raw, out)
		})
	}
}

// rootTypeFor returns a fresh generated root message based on the filename
// envelope suffix.
func rootTypeFor(t *testing.T, name string) proto.Message {
	t.Helper()
	switch {
	case strings.HasSuffix(name, ".aisystem.json"):
		return &compv1.AISystem{}
	case strings.HasSuffix(name, ".package.json"):
		return &compv1.Package{}
	default:
		t.Fatalf("cannot determine root type for %q: name must end in .aisystem.json or .package.json", name)
		return nil
	}
}

// assertJSONSemanticEqual compares the original spec payload to the re-marshaled
// proto output as normalized JSON values. It is order- and whitespace-
// insensitive but value-exact: a dropped field, a changed number, or a string
// mutation fails the comparison and reports the diverging key path.
func assertJSONSemanticEqual(t *testing.T, name string, original, roundtripped []byte) {
	t.Helper()

	var want, got any
	if err := json.Unmarshal(original, &want); err != nil {
		t.Fatalf("%s: original payload is not valid JSON: %v", name, err)
	}
	if err := json.Unmarshal(roundtripped, &got); err != nil {
		t.Fatalf("%s: round-tripped payload is not valid JSON: %v", name, err)
	}

	// Directional, value-exact containment: every key/value present in the spec
	// example MUST appear, byte-for-byte equal, in the proto round-trip output.
	// The proto output is permitted to carry ADDITIONAL keys (proto3 emits all
	// scalar defaults under EmitDefaultValues, and the spec examples omit
	// default-valued optional fields); those extras are not a conformance fault.
	// A MISSING spec key or a CHANGED value IS a fault and is reported with its
	// path. This catches the "unmarshal succeeded but silently dropped/mutated a
	// value" failure mode that a successful Unmarshal alone cannot.
	if path, w, g, ok := firstMissingOrChanged("", want, got); ok {
		t.Fatalf("%s: round-trip lost or changed a spec value at %q: spec has %#v, proto round-trip produced %#v",
			name, path, w, g)
	}
}

// firstMissingOrChanged walks the spec tree (want) and asserts each value is
// present and equal in the proto round-trip tree (got). Extra keys in got are
// ignored. Returns the first diverging path.
func firstMissingOrChanged(path string, want, got any) (string, any, any, bool) {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return path, want, got, true
		}
		keys := make([]string, 0, len(w))
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			gv, gok := g[k]
			if !gok {
				return joinPath(path, k), w[k], nil, true
			}
			if p, a, b, ok := firstMissingOrChanged(joinPath(path, k), w[k], gv); ok {
				return p, a, b, true
			}
		}
		return "", nil, nil, false
	case []any:
		g, ok := got.([]any)
		if !ok || len(w) != len(g) {
			return path, want, got, true
		}
		for i := range w {
			if p, a, b, ok := firstMissingOrChanged(indexPath(path, i), w[i], g[i]); ok {
				return p, a, b, true
			}
		}
		return "", nil, nil, false
	default:
		if !numericEqual(want, got) && !reflect.DeepEqual(want, got) {
			return path, want, got, true
		}
		return "", nil, nil, false
	}
}

// numericEqual compares two decoded-JSON scalars treating all JSON numbers as
// float64 (which is how encoding/json decodes them on both sides).
func numericEqual(a, b any) bool {
	af, aok := a.(float64)
	bf, bok := b.(float64)
	if aok && bok {
		return af == bf
	}
	return false
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

func indexPath(base string, i int) string {
	return base + "[" + itoa(i) + "]"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
