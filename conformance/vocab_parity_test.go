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

// The alias maps get the same treatment as the token sets, for the same reason: an
// alias the Go emitter wrote and the Python emitter dropped would canonicalise a
// publisher's token in one language and warn about it in another, from one proto
// option. Alias ENTRIES name their canonical target through the token's constant,
// so an entry line is `"alias": Ident,` (Go / Python) or `["alias", Ident],` (TS)
// and the constant is resolved back to its token through the definition lines.
var (
	goAlias    = regexp.MustCompile(`(?m)^\s*"([^"]+)":\s*([A-Za-z0-9_]+),`)
	pyAlias    = regexp.MustCompile(`(?m)^\s+"([^"]+)": ([A-Z0-9_]+),`)
	tsAlias    = regexp.MustCompile(`(?m)^\s+\["([^"]+)", ([A-Za-z0-9_]+)\],`)
	goTokenDef = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]+)"`)
	pyTokenDef = regexp.MustCompile(`(?m)^([A-Z0-9_]+) = "([^"]+)"`)
	tsTokenDef = regexp.MustCompile(`(?m)^export const (\w+) = "([^"]+)";`)
)

// extractAliases returns alias→canonical-token pairs, resolving each entry's
// identifier through the file's own token definitions so the comparison is over
// TOKENS, not per-language identifier spellings.
func extractAliases(t *testing.T, path string, def, entry *regexp.Regexp) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)
	idents := map[string]string{}
	for _, m := range def.FindAllStringSubmatch(src, -1) {
		idents[m[1]] = m[2]
	}
	out := map[string]string{}
	for _, m := range entry.FindAllStringSubmatch(src, -1) {
		canonical, ok := idents[m[2]]
		if !ok {
			t.Fatalf("%s: alias %q targets identifier %q, which is not a token constant in that file", path, m[1], m[2])
		}
		out[m[1]] = canonical
	}
	return out
}

// TestVocabAliasParity holds the three generated alias maps to one answer per
// axis, and to the registry: every alias target must be a registered token of
// its axis, or the generated Canonical face would canonicalise INTO a value
// IsRegistered refuses.
func TestVocabAliasParity(t *testing.T) {
	const root = ".."
	axisDirs, err := filepath.Glob(filepath.Join(root, "gen", "go", "vocab", "*"))
	if err != nil || len(axisDirs) == 0 {
		t.Fatalf("no vocab axes under gen/go/vocab (glob err=%v) — discovery drifted", err)
	}
	var aliasedAxes int
	for _, dir := range axisDirs {
		axis := filepath.Base(dir)
		goPath := filepath.Join(root, "gen", "go", "vocab", axis, axis+".go")
		goAliases := extractAliases(t, goPath, goTokenDef, goAlias)
		pyAliases := extractAliases(t, filepath.Join(root, "gen", "python", "vocab", axis+".py"), pyTokenDef, pyAlias)
		tsAliases := extractAliases(t, filepath.Join(root, "gen", "ts", "vocab", axis+".ts"), tsTokenDef, tsAlias)
		if !equalStringMaps(goAliases, pyAliases) {
			t.Errorf("%s: Python aliases differ from Go.\n  go=%v\n  py=%v", axis, goAliases, pyAliases)
		}
		if !equalStringMaps(goAliases, tsAliases) {
			t.Errorf("%s: TS aliases differ from Go.\n  go=%v\n  ts=%v", axis, goAliases, tsAliases)
		}
		registered := map[string]bool{}
		for _, tok := range extractTokens(t, goPath, goToken) {
			registered[tok] = true
		}
		for alias, canonical := range goAliases {
			if registered[alias] {
				t.Errorf("%s: alias %q is itself a registered token", axis, alias)
			}
			if !registered[canonical] {
				t.Errorf("%s: alias %q canonicalises to %q, which is not a registered token", axis, alias, canonical)
			}
		}
		if len(goAliases) > 0 {
			aliasedAxes++
		}
	}
	// Guard the guard: the function and user-type axes author aliases, so an
	// extraction that finds none anywhere has drifted from the emitted shape and
	// would hold three empty maps equal forever.
	if aliasedAxes < 2 {
		t.Fatalf("alias extraction found aliases on %d axes; at least the function and user-type axes carry them — the entry regexes drifted from the emitters", aliasedAxes)
	}
}

func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
