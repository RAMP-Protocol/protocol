package helpers_test

// Go replay of the wire-name and hex corpus (wire-names-vectors.json).
//
// Go replays it too rather than only emitting it — a corpus its own oracle does not
// consume proves nothing about the oracle. The hex half is checked against the STDLIB
// decoder rather than against the emitter's own call, so the vectors record what Go's
// hex.DecodeString actually does and the other two languages are held to that.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestWireNamesCorpusReplay(t *testing.T) {
	raw, err := os.ReadFile(wireNamesVectorsPath) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", wireNamesVectorsPath, err)
	}
	var doc struct {
		Snake []snakeCase `json:"snake_from_json_name"`
		Hex   []hexCase   `json:"hex_decode"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", wireNamesVectorsPath, err)
	}
	if len(doc.Snake) == 0 || len(doc.Hex) == 0 {
		t.Fatalf("%s carries %d name and %d hex vectors — the replay would assert nothing",
			wireNamesVectorsPath, len(doc.Snake), len(doc.Hex))
	}

	for _, v := range doc.Snake {
		t.Run("snake/"+v.Name, func(t *testing.T) {
			if got := snakeFromJSONName(v.JSONName); got != v.Snake {
				t.Errorf("snakeFromJSONName(%q) = %q, want %q", v.JSONName, got, v.Snake)
			}
		})
	}
	var refused int
	for _, v := range doc.Hex {
		t.Run("hex/"+v.Name, func(t *testing.T) {
			decoded, err := hex.DecodeString(v.Hex)
			if (err == nil) != v.Ok {
				t.Fatalf("hex.DecodeString(%q) ok = %v, want %v", v.Hex, err == nil, v.Ok)
			}
			if v.Ok && hex.EncodeToString(decoded) != v.Bytes {
				t.Errorf("hex.DecodeString(%q) = %x, want %s", v.Hex, decoded, v.Bytes)
			}
		})
		if !v.Ok {
			refused++
		}
	}
	// Both verdicts present, or the corpus asserts only half a rule.
	if refused == 0 || refused == len(doc.Hex) {
		t.Errorf("hex corpus refuses %d of %d — both outcomes are needed", refused, len(doc.Hex))
	}
}
