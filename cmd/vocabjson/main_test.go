package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/RAMP-Protocol/protocol/gen/go/vocab/functiontokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/geographytokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/quotametrics"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/usertypes"
)

// TestAxesCoverGeneratedPackages asserts the docs-facing axes map exposes every
// generated vocab package under gen/go/vocab — and that each package is wired to
// exactly one axis. Without this, adding a new axis package would silently fail to
// reach the docs, and a mis-wired axis (e.g. "function": geographytokens.All) would
// pass a count-only check — the exact "doc table drifted from the proto" disease.
func TestAxesCoverGeneratedPackages(t *testing.T) {
	const vocabDir = "../../gen/go/vocab"
	entries, err := os.ReadDir(vocabDir)
	if err != nil {
		t.Fatalf("read %s: %v", vocabDir, err)
	}
	pkgCount := 0
	for _, e := range entries {
		if e.IsDir() {
			pkgCount++
		}
	}
	if pkgCount == 0 {
		t.Fatalf("no generated vocab packages under %s — generation drifted?", vocabDir)
	}

	// Count guard: a newly generated package bumps the dir count and fails here
	// (and below, since `expected` won't include it) until axes is extended.
	if len(axes) != pkgCount {
		t.Errorf("axes map has %d entries but gen/go/vocab has %d packages; extend axes in main.go to cover every generated package.", len(axes), pkgCount)
	}

	// Correspondence guard: every generated package's token list must be wired to
	// exactly one axis. Compares by content, so a swapped or duplicated package is
	// caught — not just a count mismatch.
	expected := map[string][]string{
		"functiontokens":  functiontokens.All,
		"geographytokens": geographytokens.All,
		"usertypes":       usertypes.All,
		"pricingunits":    pricingunits.All,
		"quotametrics":    quotametrics.All,
	}
	if len(expected) != pkgCount {
		t.Errorf("test's expected package set has %d entries but gen/go/vocab has %d — a package was added/removed; update this test (and axes).", len(expected), pkgCount)
	}
	matchedAxes := map[string]bool{}
	for pkg, toks := range expected {
		if len(toks) == 0 {
			t.Errorf("generated package %s exposes no tokens — generation failed", pkg)
		}
		n := 0
		for id, ax := range axes {
			if reflect.DeepEqual(ax, toks) {
				n++
				matchedAxes[id] = true
			}
		}
		if n != 1 {
			t.Errorf("generated package %s is wired to %d axes, want exactly 1 (a mis-wired or duplicated axis)", pkg, n)
		}
	}
	for id := range axes {
		if !matchedAxes[id] {
			t.Errorf("axis %q is not backed by any generated package (wrong or stale wiring)", id)
		}
	}
}
