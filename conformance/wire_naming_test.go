// Package conformance — wire_naming_test.go guards the snake_case wire naming
// contract forever.
//
// DECISION (feature/go-sdk-extraction): the RAMP wire is snake_case proto-JSON
// everywhere — proto field names on the wire, in the corpus, and in the generated
// clients. This guard fails if any JSON object key in the committed corpus files
// contains a lowercase→uppercase transition (which is the defining property of
// lowerCamelCase). A stray UseProtoNames=false on any corpus-emitting site would
// silently re-introduce camelCase naming; this test catches it before any client
// parity test sees the regression.
package conformance

import (
	"encoding/json"
	"os"
	"testing"
	"unicode"
)

// hasCamelKey reports whether any JSON object key (at any depth) contains a
// lowercase-to-uppercase character transition, which is the defining property of
// lowerCamelCase names. Snake-case names only contain lowercase letters, digits,
// and underscores, so this check is tight. It recurses into nested objects and
// arrays.
func hasCamelKey(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if isCamelCase(k) {
				return k, true
			}
			if bad, found := hasCamelKey(child); found {
				return bad, true
			}
		}
	case []any:
		for _, item := range t {
			if bad, found := hasCamelKey(item); found {
				return bad, true
			}
		}
	}
	return "", false
}

// isCamelCase reports true when key contains at least one lowercase→uppercase
// character transition (i.e. is lowerCamelCase such as "offerId", "unitCost").
// Pure snake_case, SCREAMING_SNAKE, all-lower, or all-upper names all return
// false.
func isCamelCase(key string) bool {
	runes := []rune(key)
	for i := 1; i < len(runes); i++ {
		if unicode.IsLower(runes[i-1]) && unicode.IsUpper(runes[i]) {
			return true
		}
	}
	return false
}

func loadJSONFile(t *testing.T, path string) any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

// TestWireIsSnakeCase scans every JSON object key (recursively) in the committed
// conformance corpus files and FAILS if any key is lowerCamelCase. The corpus
// MUST use snake_case proto-JSON field names throughout. This guard stays forever:
// protojson still ACCEPTS camelCase input, so a stray UseProtoNames=false would
// silently re-introduce camelCase naming into the corpus — this catches it.
func TestWireIsSnakeCase(t *testing.T) {
	for _, path := range []string{
		"corpus/cases.json",
		"corpus/crossfield.json",
	} {
		t.Run(path, func(t *testing.T) {
			v := loadJSONFile(t, path)
			if bad, found := hasCamelKey(v); found {
				t.Errorf("%s: found camelCase key %q — corpus must use snake_case proto-JSON field names (regenerate with UseProtoNames:true)", path, bad)
			}
		})
	}
}
