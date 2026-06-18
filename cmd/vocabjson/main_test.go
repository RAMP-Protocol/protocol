package main

import (
	"os"
	"testing"
)

// TestAxesCoverGeneratedPackages asserts the docs-facing axes map exposes every
// generated vocab package under gen/go/vocab. Without this, adding a new axis
// package (a new (ramp.v1.vocab*) option group) would silently fail to reach the
// docs — the exact "the doc table drifted from the proto" disease, one layer up.
func TestAxesCoverGeneratedPackages(t *testing.T) {
	const vocabDir = "../../gen/go/vocab"
	entries, err := os.ReadDir(vocabDir)
	if err != nil {
		t.Fatalf("read %s: %v", vocabDir, err)
	}

	// One axis entry must exist per generated package. We can't key the dir name
	// to the axis id directly (they differ: "functiontokens" vs "function"), so
	// assert counts match and that the map is non-empty — a new package bumps the
	// dir count and fails until axes is extended.
	pkgCount := 0
	for _, e := range entries {
		if e.IsDir() {
			pkgCount++
		}
	}
	if pkgCount == 0 {
		t.Fatalf("no generated vocab packages under %s — generation drifted?", vocabDir)
	}
	if len(axes) != pkgCount {
		t.Errorf("axes map has %d entries but gen/go/vocab has %d packages; extend axes in main.go to cover every generated package (a new axis must not be dropped from the docs).", len(axes), pkgCount)
	}
	for id, toks := range axes {
		if len(toks) == 0 {
			t.Errorf("axis %q resolves to an empty token list — wrong package wired or generation failed", id)
		}
	}
}
