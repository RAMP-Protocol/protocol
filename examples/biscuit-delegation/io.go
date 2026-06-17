package main

import (
	"encoding/base64"
	"flag"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
)

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// stripComments removes `//` comments from Datalog before handing it to the
// parser, which only tolerates a leading comment block. It is quote-aware so a
// `//` inside a string literal (e.g. an https:// URL) is preserved. Blank lines
// left behind are dropped.
func stripComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		inQuote := false
		cut := -1
		for i := 0; i < len(line); i++ {
			if line[i] == '"' {
				inQuote = !inQuote
				continue
			}
			if !inQuote && line[i] == '/' && i+1 < len(line) && line[i+1] == '/' {
				cut = i
				break
			}
		}
		if cut >= 0 {
			line = line[:cut]
		}
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// writeToken serializes a Biscuit and writes it base64-encoded. The serialized
// bytes are exactly what RAMP carries in Delegation.token (with token_format
// "biscuit-v3"); base64 here is just so the file is text.
func writeToken(path string, tok *biscuit.Biscuit) error {
	raw, err := tok.Serialize()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o644)
}

func readToken(path string) (*biscuit.Biscuit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	return biscuit.Unmarshal(raw)
}
