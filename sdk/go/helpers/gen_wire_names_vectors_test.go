package helpers_test

// Wire-name and hex cross-language golden-vector emitter.
//
// Two textual rules that every SDK applies to bytes a PEER chose, and that had drifted
// into one transcription per language.
//
// The first recovers a proto field name from protojson's lowerCamelCase spelling of it.
// Connect's error-detail `debug` projection is lowerCamelCase and no server option changes
// it, so every JSON client normalizes that projection; and a whole response body in that
// spelling means the peer is not speaking the contract, so every JSON client refuses one.
// Three copies existed and they did not agree: two tested an ASCII-uppercase predicate and
// one tested "not equal to its own lowercase", which answer differently for a titlecase
// character — `ǅ` becomes `_ǆ` in one and is left alone by the others. The rule is now
// ASCII `A-Z` and nothing else, which is exactly what protojson can produce: it uppercases
// the character after each underscore, and a proto field name is [a-z_][a-z0-9_]*.
//
// The second is hex, which is how Offer.signature and the acceptance signature arrive.
// Every language had its own leniency here and none of them matched: JavaScript's parseInt
// accepts a sign, leading whitespace and a trailing tail, and Python's bytes.fromhex skips
// ASCII whitespace BETWEEN bytes (CPython has done so since 3.7), so "00 ff" decoded to two
// bytes there and to nothing in Go. The value is a peer's and carries no proto pattern
// constraint, so the three had to be made to agree on what is a signature and what is not.
//
// Neither rule is captured from a round trip, because neither involves one — they are
// pure string decisions. What the corpus does is make the three languages answer the same
// question with the same inputs, which is the thing that was not true.
//
// Like the other emitters this is a verification no-op by default and (re)writes the file
// under RAMP_UPDATE_VECTORS=1. It is TEST INFRASTRUCTURE, not the code under test.

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"unicode"

	"github.com/RAMP-Protocol/protocol/sdk/go/internal/vectorio"
)

const wireNamesVectorsPath = "testdata/wire-names-vectors.json"

type snakeCase struct {
	Name string `json:"name"`
	// JSONName is protojson's spelling, or a value chosen to separate the three rules.
	JSONName string `json:"json_name"`
	// Snake is what every language must recover from it.
	Snake string `json:"snake"`
}

type hexCase struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
	// Ok is whether this decodes at all. When false, Bytes is empty.
	Ok bool `json:"ok"`
	// Bytes is the decoding, lowercase hex of the result — trivially itself for a valid
	// input, and present so a replay compares the VALUE rather than only the verdict.
	Bytes string `json:"bytes"`
}

// snakeFromJSONName is the rule, stated once here and replayed everywhere.
func snakeFromJSONName(jsonName string) string {
	var b strings.Builder
	for _, r := range jsonName {
		// ASCII A-Z only. A Unicode uppercase predicate answers differently for characters
		// protojson never emits, which is how the three copies drifted.
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

var snakeCases = []struct{ name, jsonName string }{
	{"single_word", "exchange"},
	{"two_words", "transactionId"},
	{"three_words", "agentIdentityHash"},
	{"already_snake", "transaction_id"},
	{"trailing_digit", "c2paStatus"},
	{"consecutive_capitals", "uriDigest"},
	{"empty", ""},
	// The character the three copies disagreed about: titlecase Dž is not ASCII uppercase,
	// and protojson cannot emit it, so it passes through untouched.
	{"unicode_titlecase", "aǅb"},
	{"unicode_uppercase_non_ascii", "aÉb"},
}

var hexCases = []struct{ name, value string }{
	{"valid_lower", "00ff10"},
	{"valid_upper", "00FF10"},
	{"valid_empty", ""},
	{"odd_length", "abc"},
	{"leading_sign_minus", "-1"},
	{"leading_sign_plus", "+f"},
	{"leading_space", " a"},
	{"trailing_space", "a "},
	// Whitespace BETWEEN bytes, with an even count on either side of it. The earlier two
	// cases were passing in Python for the wrong reason — stripping left an odd length —
	// so neither of them saw the divergence they were meant to catch.
	{"embedded_space", "00 ff"},
	{"embedded_tab", "00\tff"},
	{"non_hex_letter", "zz"},
	{"embedded_null", "0\x00"},
}

func buildWireNameVectors() ([]snakeCase, []hexCase) {
	snakes := make([]snakeCase, 0, len(snakeCases))
	for _, c := range snakeCases {
		snakes = append(snakes, snakeCase{
			Name: c.name, JSONName: c.jsonName, Snake: snakeFromJSONName(c.jsonName),
		})
	}
	hexes := make([]hexCase, 0, len(hexCases))
	for _, c := range hexCases {
		decoded, err := hex.DecodeString(c.value)
		hexes = append(hexes, hexCase{
			Name:  c.name,
			Hex:   c.value,
			Ok:    err == nil,
			Bytes: map[bool]string{true: hex.EncodeToString(decoded), false: ""}[err == nil],
		})
	}
	return snakes, hexes
}

func TestGenerateWireNamesVectors(t *testing.T) {
	snakes, hexes := buildWireNameVectors()
	doc := map[string]any{
		"note": "Textual rules every SDK applies to bytes a peer chose. snake_from_json_name " +
			"inverts protojson's lowerCamelCase spelling (ASCII A-Z is the only boundary it " +
			"can produce); hex is the Offer.signature encoding, where a sign, whitespace or " +
			"an odd length is not a signature.",
		"snake_from_json_name": snakes,
		"hex_decode":           hexes,
	}
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(wireNamesVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", wireNamesVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(wireNamesVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", wireNamesVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", wireNamesVectorsPath)
	}
}
