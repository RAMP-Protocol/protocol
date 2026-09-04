package helpers

// Manifest-version golden-vector emitter.
//
// The rule this locks is normative — WellKnownManifest.ver states it — and has
// no protovalidate rule, so the only thing pinning the three SDKs to one verdict
// is this corpus. Each row is run through the real CheckWellKnownManifestVersion
// and the emitted verdict is the oracle's, never the table's: a row whose intent
// disagrees with the oracle fails the emitter rather than publishing a wrong
// expectation.
//
// `present` is a column of its own because "absent" is not a string value — a
// replay in a language whose JSON decoder yields null or undefined for a missing
// member must drive the ABSENT case through that path, not through "".
//
// Verification no-op by default (asserts the committed file matches a fresh
// emit); (re)writes under RAMP_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"os"
	"path/filepath"
	"testing"
)

// manifestVersionVector is one CheckWellKnownManifestVersion case: the ver the
// manifest carried (meaningless when Present is false), whether the member was
// present at all, and whether the rule accepts the document. Accepted carries no
// reason string on purpose — the three languages phrase their errors in their own
// vocabularies.
type manifestVersionVector struct {
	Name     string `json:"name"`
	Ver      string `json:"ver"`
	Present  bool   `json:"present"`
	Accepted bool   `json:"accepted"`
}

func buildManifestVersionVectors(t *testing.T) []manifestVersionVector {
	t.Helper()
	rows := []struct {
		name    string
		ver     string
		present bool
		want    bool
	}{
		{"current", WellKnownManifestVersion, true, true},
		{"same_major_next_minor", "1.1", true, true},
		{"same_major_large_minor", "1.99", true, true},
		{"next_major", "2.0", true, false},
		{"prerelease_major", "0.3", true, false},
		{"two_digit_major", "10.0", true, false},
		{"absent", "", false, false},
		{"empty", "", true, false},
		{"major_only", "1", true, false},
		{"patch_component", "1.0.0", true, false},
		{"leading_v", "v1.0", true, false},
		{"non_digit_minor", "1.a", true, false},
		{"leading_space", " 1.0", true, false},
		{"trailing_dot", "1.", true, false},
		{"leading_zero_major", "01.0", true, false},
	}
	out := make([]manifestVersionVector, 0, len(rows))
	for _, r := range rows {
		got := CheckWellKnownManifestVersion(r.ver) == nil
		if got != r.want {
			t.Fatalf("%s: CheckWellKnownManifestVersion(%q) accepted=%v, table says %v; fix the table or the rule",
				r.name, r.ver, got, r.want)
		}
		out = append(out, manifestVersionVector{Name: r.name, Ver: r.ver, Present: r.present, Accepted: got})
	}
	return out
}

// TestGenerateManifestVersionVectors emits testdata/manifest-version-vectors.json.
func TestGenerateManifestVersionVectors(t *testing.T) {
	doc := map[string]any{"manifest_version": buildManifestVersionVectors(t)}
	path := filepath.Join("testdata", "manifest-version-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
