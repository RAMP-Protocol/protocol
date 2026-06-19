package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
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
	files := jsonFilesIn(t, compExamplesDir)

	// Sanity floor: the standard ships 8 examples, each with a request
	// (AISystem) and a response (Package) payload — 16 vendored files. If the
	// testdata set is ever truncated, fail loudly rather than pass vacuously.
	if len(files) < 16 {
		t.Fatalf("expected at least 16 vendored CoMP V1 example payloads, found %d in %s", len(files), compExamplesDir)
	}

	for _, name := range files {
		name := name
		t.Run(name, func(t *testing.T) {
			roundTripExample(t, compExamplesDir, name)
		})
	}
}

// jsonFilesIn returns the sorted *.json file names directly under dir.
func jsonFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	return files
}

// roundTripExample runs the adversarial conformance round-trip for one example
// payload and returns its raw bytes. The two load-bearing properties:
//
//   - Unmarshal uses DEFAULT protojson options — DiscardUnknown is false, so any
//     field present in the payload but ABSENT from our proto is a hard error
//     (a missing field surfaces here rather than being silently dropped).
//   - Re-marshal uses enum-as-number (CoMP's integer List codes) with
//     EmitDefaultValues so an explicitly-set zero is not elided, then
//     assertJSONSemanticEqual proves every payload value survived the round-trip.
func roundTripExample(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}

	msg := rootTypeFor(t, name)

	if err := protojson.Unmarshal(raw, msg); err != nil {
		t.Fatalf("protojson.Unmarshal of %s into %T FAILED (a typed field in the payload is absent or mistyped in comp.proto): %v",
			name, msg, err)
	}

	out, err := protojson.MarshalOptions{
		UseEnumNumbers:    true,
		EmitDefaultValues: true,
	}.Marshal(msg)
	if err != nil {
		t.Fatalf("protojson.Marshal of %T (%s): %v", msg, name, err)
	}

	assertJSONSemanticEqual(t, name, raw, out)
	return raw
}

// syntheticExamplesDir holds RAMP-authored conformance fixtures that are NOT
// part of the verbatim IAB CoMP V1 worked-example set. The published examples
// leave the Scope commercial block (ause/pricetype/pricetier/unitprice/cur/
// country/licensedur) and the per-asset language/update fields unpopulated, so
// those proto fields would round-trip green even if renamed, retyped, or
// renumbered. These fixtures exercise that surface so such drift fails the gate.
// They are kept in a separate directory (with their own README) so the verbatim
// IAB set stays a clean, blob-pinned mirror. See testdata/comp_v1_synthetic.
const syntheticExamplesDir = "testdata/comp_v1_synthetic"

// requiredSyntheticCoverage declares, per synthetic fixture, the spec-value JSON
// paths the fixture MUST populate. It is an anti-vacuity floor: if a future edit
// drops one of these fields, the coverage the fixture exists to provide silently
// disappears — so presence is asserted explicitly rather than assumed.
var requiredSyntheticCoverage = map[string][]string{
	"commercial_terms.package.json": {
		"packager",
		"reporturl",
		"scope.ause",
		"scope.pricetype",
		"scope.pricetier",
		"scope.unitprice",
		"scope.cur",
		"scope.country",
		"scope.licensedur",
		"scope.text[0].update",
		"scope.text[0].language",
	},
}

// TestCompV1SyntheticCoverageRoundTrip round-trips the RAMP-authored fixtures
// with the same adversarial properties as the verbatim set, then asserts each
// fixture still populates the proto fields it was authored to cover.
func TestCompV1SyntheticCoverageRoundTrip(t *testing.T) {
	files := jsonFilesIn(t, syntheticExamplesDir)
	if len(files) == 0 {
		t.Fatalf("no RAMP-authored synthetic fixtures found in %s", syntheticExamplesDir)
	}

	for _, name := range files {
		name := name
		t.Run(name, func(t *testing.T) {
			raw := roundTripExample(t, syntheticExamplesDir, name)

			paths, ok := requiredSyntheticCoverage[name]
			if !ok {
				t.Fatalf("synthetic fixture %s has no entry in requiredSyntheticCoverage; "+
					"declare the proto fields it covers or remove the file", name)
			}

			var tree any
			if err := json.Unmarshal(raw, &tree); err != nil {
				t.Fatalf("%s: not valid JSON: %v", name, err)
			}
			for _, p := range paths {
				if _, ok := lookupJSONPath(tree, p); !ok {
					t.Errorf("%s: required coverage path %q is absent — the proto field this "+
						"fixture exists to exercise is no longer present", name, p)
				}
			}
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
	return base + "[" + strconv.Itoa(i) + "]"
}

// lookupJSONPath resolves a dotted path with optional single [i] array indices
// (e.g. "scope.text[0].language") against a decoded-JSON tree and reports
// whether a value exists there. Used by the synthetic-coverage anti-vacuity
// check; it does not assert on the value, only its presence.
func lookupJSONPath(tree any, path string) (any, bool) {
	cur := tree
	for _, seg := range strings.Split(path, ".") {
		key := seg
		idx := -1
		if lb := strings.IndexByte(seg, '['); lb >= 0 {
			rb := strings.IndexByte(seg, ']')
			if rb < lb+1 {
				return nil, false
			}
			n, err := strconv.Atoi(seg[lb+1 : rb])
			if err != nil {
				return nil, false
			}
			key = seg[:lb]
			idx = n
		}

		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[key]
		if !ok {
			return nil, false
		}
		if idx >= 0 {
			arr, ok := v.([]any)
			if !ok || idx >= len(arr) {
				return nil, false
			}
			v = arr[idx]
		}
		cur = v
	}
	return cur, true
}
