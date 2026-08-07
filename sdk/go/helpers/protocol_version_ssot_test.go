package helpers_test

// Structural SSOT guard for the RAMP protocol version — the Go analogue of the
// reference implementation's own Ver-SSOT guard, lifted here because this is the
// repository that DEFINES the wire and therefore the only place the value can be
// owned once.
//
// The disease: a message builder that stamps `Ver: "1.0"` as a bare literal. Each
// one is individually harmless and collectively fatal — a protocol bump then has
// to find every site, and the one it misses skews a subset of authored messages
// while every test still passes, because nothing reads `ver` off an inbound
// message. That is not hypothetical: it is how a "0.3" builder survived alongside
// "1.0" builders in the reference implementation long enough to be filed as a
// release blocker.
//
// helpers.ProtocolVersion is the one source. This guard pins that: no non-test
// file under sdk/go may assign a string literal to a `Ver:` field. Echo sites
// (`Ver: req.GetVer()`) relay an inbound peer's own version verbatim and are not
// system-authored, so they never trip it — the matcher requires a quoted literal.
//
// The guard is green the day it lands (there are no such sites today) and that is
// the point: it is a ratchet against the regression, not a cleanup of one.
//
// Scope note: this binds what this project emits. It cannot bind a third party —
// `ver` carries no protovalidate rule and is advisory on receive by design. See
// "Protocol version" in ramp.proto for that decision and its reasoning.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bareVerLiteralRe matches a `Ver:` struct-literal field assigned a quoted
// string. `Ver:` is required immediately before the colon, so `Verifier:` and
// `VerifiedOffer:` never match; a quoted literal is required, so the echo form
// `Ver: req.GetVer()` and the constant form `Ver: helpers.ProtocolVersion` do not.
var bareVerLiteralRe = regexp.MustCompile(`\bVer:\s*"[^"]*"`)

// stampsBareVerLiteral is the pure predicate, extracted so the meta-tests can
// exercise it without touching the filesystem.
func stampsBareVerLiteral(source string) bool {
	return bareVerLiteralRe.MatchString(source)
}

// sdkGoSources returns every non-test .go file under sdk/go (this package's
// parent), so a new package under the SDK tree is in scope the moment it exists.
func sdkGoSources(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		out = append(out, filepath.ToSlash(path))
		return nil
	})
	if err != nil {
		t.Fatalf("walk sdk/go sources: %v", err)
	}
	return out
}

func TestProtocolVersionSSOT_NoBareVerLiteral(t *testing.T) {
	sources := sdkGoSources(t)
	if len(sources) == 0 {
		t.Fatal("no sdk/go sources found — the SSOT guard would vacuously pass")
	}
	for _, name := range sources {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if stampsBareVerLiteral(string(b)) {
			t.Errorf("%s stamps a bare string literal on a Ver field — use helpers.ProtocolVersion so a protocol bump is one edit and cannot skew a subset of authored messages", name)
		}
	}
}

// --- meta-tests: exercise the detector against synthetic source ---------------

func TestProtocolVersionSSOT_MetaPositive(t *testing.T) {
	for _, src := range []string{
		`&rampv1.TransactionResponse{Ver: "1.0"}`,
		`&rampv1.ResourceQuery{Ver:"1.0"}`,
		`msg := rampv1.UsageReport{Ver: "0.3", IdempotencyKey: k}`,
	} {
		if !stampsBareVerLiteral(src) {
			t.Errorf("detector missed a bare Ver literal: %q", src)
		}
	}
}

func TestProtocolVersionSSOT_MetaNegative(t *testing.T) {
	for _, src := range []string{
		`&rampv1.TransactionResponse{Ver: helpers.ProtocolVersion}`,
		`&rampv1.TransactionResponse{Ver: req.GetVer()}`,
		`ProtocolVersion = "1.0"`,                // the declaration itself
		`v := Verifier{Name: "x"}`,               // Verifier, not Ver
		`o := VerifiedOffer{Signature: "sig"}`,   // VerifiedOffer, not Ver
		`h.Set("Connect-Protocol-Version", "1")`, // the transport version
	} {
		if stampsBareVerLiteral(src) {
			t.Errorf("detector false-positived: %q", src)
		}
	}
}
