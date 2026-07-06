// Package conformance — vocab_parity_test.go asserts the generated vocabulary
// CONSTANTS agree across languages.
//
// The per-file drift gate proves each generated vocab file matches its own
// generator's output; it never proves the THREE generators (Go, Python, TS
// rampvocab emitters) agree with each other. A bug in one emitter — a dropped or
// mistyped token in only the Zod or Pydantic output — passes the drift gate but
// would hand consumers a different registry per language. This test reads the
// token sets straight from the three generated files and requires them identical,
// per axis. Axes are discovered from gen/go/vocab (opt-out: a new axis is covered
// the moment its package is generated).
package conformance

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// Token VALUES are the quoted string literals in each language's const block.
// The `All`/`registered` collections reference those consts by name (no quotes),
// so matching the `<name> = "<token>"` definition lines captures each token once.
var (
	goToken = regexp.MustCompile(`(?m)^\s*[A-Za-z0-9_]+\s*=\s*"([^"]+)"`)
	pyToken = regexp.MustCompile(`(?m)^[A-Z0-9_]+ = "([^"]+)"`)
	tsToken = regexp.MustCompile(`(?m)^export const \w+ = "([^"]+)";`)
)

func extractTokens(t *testing.T, path string, re *regexp.Regexp) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

func TestVocabConstantsParity(t *testing.T) {
	const root = ".." // conformance/ -> repo root
	axisDirs, err := filepath.Glob(filepath.Join(root, "gen", "go", "vocab", "*"))
	if err != nil || len(axisDirs) == 0 {
		t.Fatalf("no vocab axes under gen/go/vocab (glob err=%v) — discovery drifted", err)
	}
	for _, dir := range axisDirs {
		axis := filepath.Base(dir)
		t.Run(axis, func(t *testing.T) {
			goTokens := extractTokens(t, filepath.Join(root, "gen", "go", "vocab", axis, axis+".go"), goToken)
			pyTokens := extractTokens(t, filepath.Join(root, "gen", "python", "vocab", axis+".py"), pyToken)
			tsTokens := extractTokens(t, filepath.Join(root, "gen", "ts", "vocab", axis+".ts"), tsToken)
			if len(goTokens) == 0 {
				t.Fatalf("%s: no tokens extracted from the Go package — extraction drifted", axis)
			}
			if !equalStrings(goTokens, pyTokens) {
				t.Errorf("%s: Python tokens differ from Go.\n  go=%v\n  py=%v", axis, goTokens, pyTokens)
			}
			if !equalStrings(goTokens, tsTokens) {
				t.Errorf("%s: TS tokens differ from Go.\n  go=%v\n  ts=%v", axis, goTokens, tsTokens)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
