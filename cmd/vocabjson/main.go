// Command vocabjson renders the RAMP vocabulary as a JSON view for the docs
// site. It is NOT a second source of truth: it imports the generated, drift-
// gated token packages under gen/go/vocab (themselves emitted from the
// (ramp.v1.vocab)/(ramp.v1.vocab_enum) options by protoc-gen-rampvocab) and
// marshals their All slices. The proto stays the single source; this is a view
// recomputed on every docs build, never hand-edited and never committed.
//
// The generated packages are import-free (plain string constants), so this
// command needs only the Go toolchain — no buf, no network — which lets the
// docs deploy build (AWS Amplify) regenerate the view in a preBuild step.
//
// Usage:
//
//	go run ./cmd/vocabjson -o website/src/data/vocab.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/RAMP-Protocol/protocol/gen/go/vocab/functiontokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/geographytokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/quotametrics"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/usertypes"
)

// axes maps the docs-facing axis id to its generated token list. The keys are
// the values a <VocabTable axis="..."> component references. A guard test
// (main_test.go) asserts this map covers every package under gen/go/vocab, so a
// newly generated axis cannot be silently dropped from the docs.
var axes = map[string][]string{
	"function":     functiontokens.All,
	"geography":    geographytokens.All,
	"user-type":    usertypes.All,
	"pricing-unit": pricingunits.All,
	"quota-metric": quotametrics.All,
}

func main() {
	out := flag.String("o", "", "output path for vocab.json (default: stdout)")
	flag.Parse()

	data, err := json.MarshalIndent(axes, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "vocabjson: marshal: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if *out == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "vocabjson: write %s: %v\n", *out, err)
		os.Exit(1)
	}
}
