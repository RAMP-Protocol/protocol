// Package core_test — requestid_contract_test.go ties ValidRequestID to the wire
// rule it claims to implement.
//
// ValidRequestID is a hand-written byte loop. The authority is the protovalidate
// rule on ramp.admin.v1.RequestCorrelation.request_id. Two statements of one rule,
// and until this file nothing compared them.
//
// THE FAILURE THAT WAS POSSIBLE. Narrow the rule in the proto — max_len to 128,
// say, or the charset to exclude a metacharacter. Every Go test passes, the corpus
// regenerates cleanly, both generated clients tighten. ValidRequestID keeps
// accepting what it always accepted, so RequestIDMiddleware keeps stamping ids the
// receiving Exchange must now refuse, and the correlation the middleware exists to
// create is silently broken on the write path.
//
// This is a DIFFERENTIAL test, not a restatement: it asks protovalidate for the
// verdict and asks ValidRequestID for the verdict and requires them to agree. No
// literal from the rule — no 255, no `^[!-~]+$` — appears here. A guard that
// spelled the rule a third time would add a third thing to drift.
//
// It lives in sdk/go/core rather than in conformance/ because conformance/ is the
// descriptor-level layer BELOW the SDKs and imports nothing from sdk/. Here the
// direction is the ordinary one: sdk/go/core already imports gen/go.
package core_test

import (
	"strings"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
)

// wireAcceptsRequestID reports what the CONTRACT says about s, by validating a
// RequestCorrelation carrying it and looking only at violations on request_id.
//
// Only that field's violations count: `minted` is a bare bool with no rule today,
// but a rule added there later must not silently turn this guard into a test of
// the wrong field.
func wireAcceptsRequestID(t *testing.T, v protovalidate.Validator, s string) bool {
	t.Helper()
	err := v.Validate(&rampadminv1.RequestCorrelation{RequestId: s})
	if err == nil {
		return true
	}
	verr, ok := err.(*protovalidate.ValidationError)
	if !ok {
		t.Fatalf("validating request_id=%q: unexpected error type %T: %v", s, err, err)
	}
	for _, viol := range verr.Violations {
		if els := viol.Proto.GetField().GetElements(); len(els) > 0 &&
			els[0].GetFieldName() == "request_id" {
			return false
		}
	}
	return true
}

func TestValidRequestIDMatchesTheWireRule(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	// The table is chosen to straddle every edge the rule can have, so a change to
	// ANY of its three clauses shows up as a disagreement rather than as two
	// implementations quietly drifting together. Nothing here asserts a verdict of
	// its own — each row is judged by both sides and only the agreement is checked.
	cases := []string{
		"", " ", "\x1f", "\x20", "\x21", "\x7e", "\x7f", "ÿ",
		"a", "abc", "trace-id-1", "trace:id{1}", "with space", "tab\there",
		"new\nline", "null\x00byte", "café", "🙂",
		strings.Repeat("a", 1),
		strings.Repeat("a", 127),
		strings.Repeat("a", 128),
		strings.Repeat("a", 129),
		strings.Repeat("a", 254),
		strings.Repeat("a", 255),
		strings.Repeat("a", 256),
		strings.Repeat("a", 512),
		// Multi-byte: 255 CHARACTERS but more than 255 bytes. The rule counts
		// characters and ValidRequestID counts bytes; they agree only because every
		// character the charset admits is one ASCII byte. This row is what proves
		// that reasoning instead of asserting it.
		strings.Repeat("é", 255),
	}

	for _, s := range cases {
		want := wireAcceptsRequestID(t, v, s)
		if got := core.ValidRequestID(s); got != want {
			t.Errorf("ValidRequestID(%q) = %v, but the wire rule on "+
				"ramp.admin.v1.RequestCorrelation.request_id says %v.\n"+
				"The SDK's copy of the rule has drifted from the contract. Update "+
				"ValidRequestID to match the descriptor, not this table.", s, got, want)
		}
	}
}

// TestMintRequestIDAlwaysConforms pins the property every stamping site relies on:
// whatever a caller's mint returns, what comes out is something the admin plane can
// persist. Each site used to re-derive this, and the one that forgot shipped.
func TestMintRequestIDAlwaysConforms(t *testing.T) {
	for name, mint := range map[string]core.RequestIDFunc{
		"nil":           nil,
		"empty":         func() string { return "" },
		"space":         func() string { return "trace id" },
		"newline":       func() string { return "trace\nid" },
		"non-ascii":     func() string { return "café" },
		"too long":      func() string { return strings.Repeat("a", 256) },
		"already valid": func() string { return "abc-123" },
	} {
		got := core.MintRequestID(mint)()
		if !core.ValidRequestID(got) {
			t.Errorf("%s mint: MintRequestID produced %q, which the wire rule refuses", name, got)
		}
	}
	// A conforming mint is passed through, not replaced — otherwise the caller's
	// trace id never reaches the header and the feature is pointless.
	if got := core.MintRequestID(func() string { return "abc-123" })(); got != "abc-123" {
		t.Errorf("MintRequestID replaced a conforming value: got %q, want %q", got, "abc-123")
	}
}
