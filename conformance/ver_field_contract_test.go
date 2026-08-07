package conformance

// Structural guard for the `ver` envelope field's documented contract.
//
// Every message of the wire contract carries `ver` at field 1, and the value is
// "1.0". That was true before this guard existed too — but only ONE of the 29
// fields said so: WellKnownManifest.ver. The other 28 read "Protocol version"
// and nothing more, and one (DiscoveryResponse.ver) carried no comment at all.
// Nobody removed those statements; they were never written, because a per-field
// doc obligation that lives only in a reviewer's head is complete the day it is
// discharged and silently incomplete the day the next message is added.
//
// So this guard derives its scope from the contract rather than from a list: it
// reads the proto SOURCE of every package in Contract (contract.go) and requires
// each `ver` field to state the expected value, and — outside the documented
// exemption — the advisory-on-receive rule. A message added tomorrow with a
// silent `ver` fails on the day it is written.
//
// It reads the .proto source, not the descriptor, because the obligation is on
// the comment text and the generated Go descriptor does not retain source
// comments. That also matches what a human reads when integrating.
//
// This guard binds the comments; the value itself is owned one tier out, by the
// SDK's ProtocolVersion constant. Neither can bind a third party — `ver` is
// deliberately advisory on the wire, with no protovalidate rule. See "Protocol
// version" in ramp.proto for why.
//
// The expected value is READ from that owner rather than restated here. This
// package cannot import sdk/go — nothing in conformance depends on sdk/, by
// design: it is the descriptor/source-level layer BELOW the SDKs (contract.go).
// So it reads the committed wire-constants vector, which is generated from the
// real Go constant and already replayed by the Python and TS parity suites. That
// is a data read, exactly like the corpus and the doc scans, not a dependency —
// and it means a version bump that misses either side goes red instead of
// leaving two copies of the literal to drift apart.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var (
	verFieldRe  = regexp.MustCompile(`^\s*string ver = 1\b`)
	messageDecl = regexp.MustCompile(`^\s*message (\w+) \{`)
	commentLine = regexp.MustCompile(`^\s*//`)
)

// verExemptMessages are messages whose `ver` is NOT the RPC envelope version and
// therefore carries a different, stronger contract. Each entry is proved both
// USED and NECESSARY on every run: an entry naming no real `ver` field fails as
// stale, and an entry whose comment has since adopted the standard advisory
// wording fails as a no-longer-needed exemption.
var verExemptMessages = map[string]string{
	"WellKnownManifest": "the /.well-known/ramp.json document's own schema version — a separate " +
		"namespace from the RPC envelope, stated MUST-equal rather than advisory",
}

// wireConstantsVectors is the committed cross-language oracle for the SDK's wire
// constants, emitted from the real Go constants by the sdk/go/helpers vector
// generator. Read as data (see the file header on why this is not an import).
const wireConstantsVectors = "../sdk/go/helpers/testdata/wire-constants-vectors.json"

// protocolVersion returns the RAMP protocol version the SDK exports, read from the
// committed vector so this guard never restates the literal. Errors are fatal
// rather than skipped: a missing file or entry means the guard has lost its
// anchor, and silently passing would be worse than failing.
var protocolVersion = sync.OnceValues(func() (string, error) {
	b, err := os.ReadFile(wireConstantsVectors)
	if err != nil {
		return "", err
	}
	var doc struct {
		Vectors []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", err
	}
	for _, v := range doc.Vectors {
		if v.Name == "ProtocolVersion" {
			return v.Value, nil
		}
	}
	return "", errNoProtocolVersionVector
})

var errNoProtocolVersionVector = errors.New(
	wireConstantsVectors + " carries no ProtocolVersion entry — this guard reads the expected `ver` value from there")

// expectedVersionToken is the quoted form a `ver` comment must contain, e.g. `"1.0"`.
func expectedVersionToken(t *testing.T) string {
	t.Helper()
	v, err := protocolVersion()
	if err != nil {
		t.Fatalf("read the SDK protocol version: %v", err)
	}
	return strconv.Quote(v)
}

// statesExpectedValue is the obligation on EVERY `ver` comment: an integrator
// reading the field must learn what to stamp. Required of exempt fields too —
// the exemption is from the advisory rule, not from naming the value. `token` is
// the SDK's version in quoted form, so the value lives in one place.
func statesExpectedValue(comment, token string) bool {
	return strings.Contains(comment, token)
}

// statesAdvisoryContract is the obligation on every RPC-envelope `ver`: the
// receive-side rule, which is what stops a reader assuming the field is
// enforced. Exempt messages state a stronger rule instead.
func statesAdvisoryContract(comment string) bool {
	return strings.Contains(comment, "advisory on receive")
}

// verField is one `ver` declaration found in proto source.
type verField struct {
	file    string
	line    int // 1-indexed
	message string
	comment string // the contiguous // block directly above, joined
}

// collectVerFields reads the proto source of every contract package and returns
// every `ver` field with its leading comment block. Enclosing message is the
// most recent `message X {` — `ver` is field 1, so it is always declared before
// any nested message could shadow the attribution.
func collectVerFields(t *testing.T) []verField {
	t.Helper()
	var out []verField
	for _, cf := range Contract {
		// Contract carries the descriptor path (e.g. "ramp/v1/ramp.proto"); the
		// buf module root is ../proto relative to this package's test dir.
		path := filepath.Join("..", "proto", cf.File.Path())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read proto source for %s: %v", cf.Package, err)
		}
		lines := strings.Split(string(b), "\n")
		msg := ""
		for i, ln := range lines {
			if m := messageDecl.FindStringSubmatch(ln); m != nil {
				msg = m[1]
			}
			if !verFieldRe.MatchString(ln) {
				continue
			}
			var block []string
			for j := i - 1; j >= 0 && commentLine.MatchString(lines[j]); j-- {
				block = append([]string{strings.TrimSpace(lines[j])}, block...)
			}
			out = append(out, verField{
				file:    filepath.ToSlash(path),
				line:    i + 1,
				message: msg,
				comment: strings.Join(block, " "),
			})
		}
	}
	return out
}

func TestVerFieldsDocumentTheirContract(t *testing.T) {
	fields := collectVerFields(t)
	if len(fields) == 0 {
		t.Fatal("no `ver` fields found in the contract protos — the guard would vacuously pass; check the source paths derived from Contract")
	}

	token := expectedVersionToken(t)
	for _, f := range fields {
		if f.comment == "" {
			t.Errorf("%s:%d %s.ver carries no doc comment — every `ver` must state the expected value and its receive-side rule",
				f.file, f.line, f.message)
			continue
		}
		if !statesExpectedValue(f.comment, token) {
			t.Errorf("%s:%d %s.ver does not state the expected value — the comment must name %s (the SDK's ProtocolVersion, per %s) so an integrator learns what to stamp",
				f.file, f.line, f.message, token, wireConstantsVectors)
		}
		if _, exempt := verExemptMessages[f.message]; exempt {
			continue
		}
		if !statesAdvisoryContract(f.comment) {
			t.Errorf("%s:%d %s.ver does not state the receive-side rule — say it is advisory on receive, or add %s to verExemptMessages with a reason",
				f.file, f.line, f.message, f.message)
		}
	}
}

// TestVerExemptionsAreUsedAndNecessary keeps the exemption list from outliving
// its reasons — the failure mode every hand-maintained list in this package is
// written to avoid.
func TestVerExemptionsAreUsedAndNecessary(t *testing.T) {
	fields := collectVerFields(t)
	byMessage := map[string]verField{}
	for _, f := range fields {
		byMessage[f.message] = f
	}
	for msg, reason := range verExemptMessages {
		if reason == "" {
			t.Errorf("exemption for %s carries no reason", msg)
		}
		f, ok := byMessage[msg]
		if !ok {
			t.Errorf("stale exemption: %s declares no `ver` field — drop it from verExemptMessages", msg)
			continue
		}
		if statesAdvisoryContract(f.comment) {
			t.Errorf("stale exemption: %s.ver now states the standard advisory contract — drop it from verExemptMessages", msg)
		}
	}
}

// --- meta-tests: exercise the detectors against synthetic comment text -------

func TestVerContractDetectors_MetaPositive(t *testing.T) {
	token := expectedVersionToken(t)
	// Built from the token rather than a baked literal, so these fixtures cannot
	// drift away from the real comments on a version bump.
	std := "// RAMP protocol version — " + token + ". Stamped by the sender from a single " +
		`// constant; advisory on receive. See "Protocol version" in the file header.`
	if !statesExpectedValue(std, token) {
		t.Error("detector missed the expected value in the standard comment")
	}
	if !statesAdvisoryContract(std) {
		t.Error("detector missed the advisory rule in the standard comment")
	}
	manifest := "// RAMP protocol version of THIS MANIFEST DOCUMENT's schema. MUST equal " + token + ";"
	if !statesExpectedValue(manifest, token) {
		t.Error("detector missed the expected value in the manifest comment")
	}
}

// TestVerExpectedValueComesFromTheSDK pins the anchor itself: the token is READ
// from the wire-constants vector, not restated here. A comment naming some other
// version must fail — which is what makes a half-finished bump (constant moved,
// comments not, or the reverse) go red instead of silently disagreeing.
func TestVerExpectedValueComesFromTheSDK(t *testing.T) {
	token := expectedVersionToken(t)
	if token == "" || !strings.HasPrefix(token, `"`) {
		t.Fatalf("expected a quoted version token, got %q", token)
	}
	other := `"9.9"`
	if token == other {
		t.Fatalf("the SDK version collides with this test's counter-example %s; pick another", other)
	}
	if statesExpectedValue("// RAMP protocol version — "+other+". advisory on receive.", token) {
		t.Errorf("a comment naming %s satisfied the check against %s — the guard is not anchored to the SDK constant", other, token)
	}
}

func TestVerContractDetectors_MetaNegative(t *testing.T) {
	token := expectedVersionToken(t)
	for _, c := range []string{
		"// Protocol version",
		"// RAMP protocol version.",
		"",
	} {
		if statesExpectedValue(c, token) {
			t.Errorf("detector false-positived on a comment that names no value: %q", c)
		}
		if statesAdvisoryContract(c) {
			t.Errorf("detector false-positived on a comment that states no receive rule: %q", c)
		}
	}
	// The manifest comment states a value but NOT the advisory rule — that
	// asymmetry is exactly what makes its exemption necessary.
	if statesAdvisoryContract("// MUST equal " + token + "; consumers REJECT unrecognised major versions.") {
		t.Error("detector treated the MUST-equal manifest rule as the advisory contract")
	}
}

// TestVerFieldScanner_MetaRegexSlip pins the field matcher against the shapes it
// must and must not see, so a loosened regex cannot silently shrink the scope.
func TestVerFieldScanner_MetaRegexSlip(t *testing.T) {
	for _, ln := range []string{"  string ver = 1;", "  string ver = 1 [deprecated = true];"} {
		if !verFieldRe.MatchString(ln) {
			t.Errorf("field matcher missed a `ver` declaration: %q", ln)
		}
	}
	for _, ln := range []string{
		"  string verifier = 1;",
		"  string version = 1;",
		"  repeated string protocol_versions_supported = 16;",
		"  // string ver = 1;",
	} {
		if verFieldRe.MatchString(ln) {
			t.Errorf("field matcher false-positived: %q", ln)
		}
	}
}
