package helpers

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestManifestVersionCorpusReplays drives every row of the shared corpus through
// CheckWellKnownManifestVersion and asserts the committed verdict. The emitter
// proves the file matches the oracle at emit time; this replay proves the oracle
// still agrees with the file, which is what the Python and TypeScript replays
// assert against their own ports.
func TestManifestVersionCorpusReplays(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "manifest-version-vectors.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var doc struct {
		Cases []manifestVersionVector `json:"manifest_version"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("corpus is empty; the replay would be vacuous")
	}
	var accepted, refused, absent int
	for _, c := range doc.Cases {
		ver := c.Ver
		if !c.Present {
			ver = "" // an absent member arrives as the zero value in Go
			absent++
		}
		err := CheckWellKnownManifestVersion(ver)
		if c.Accepted {
			accepted++
			if err != nil {
				t.Errorf("%s: ver=%q present=%v: refused (%v), corpus says accepted", c.Name, c.Ver, c.Present, err)
			}
			continue
		}
		refused++
		if err == nil {
			t.Errorf("%s: ver=%q present=%v: accepted, corpus says refused", c.Name, c.Ver, c.Present)
		} else if !errors.Is(err, ErrManifestVersionRefused) {
			t.Errorf("%s: error %v does not carry ErrManifestVersionRefused", c.Name, err)
		}
	}
	if accepted == 0 || refused == 0 || absent == 0 {
		t.Fatalf("corpus must carry accepted, refused and absent rows; got %d/%d/%d", accepted, refused, absent)
	}
}
