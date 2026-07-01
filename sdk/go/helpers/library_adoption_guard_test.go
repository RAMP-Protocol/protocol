package helpers_test

// Structural guard for the SDK-quality library-adoption refactor
// (partial-adoption decision under ADR-020 L1). This is a behavior-PRESERVING
// upgrade whose Core Invariant is BYTE-PARITY, so there is no new
// runtime-observable behavior to pin — the shared-vector tests
// (thumbprint-vectors.json, verify_test.go, keyresolver_test.go, the
// multisig_chain tests) remain the behavioral safety net and MUST stay green.
//
// This file is the sanctioned "structural check IS the test" exception: it
// FAILS while the hand-rolled crypto / JWK-decode / RFC-8941-parser instances
// still exist in the three MIGRATE sites, and PASSES once implementation swaps
// them for the vetted libraries. It is designed to be re-run verbatim by the
// sweep-verify atom.
//
// Scope (partial adoption — ONLY these three sites):
//  1. thumbprint.go       — hand-rolled fmt.Sprintf canonical-JWK + sha256.Sum256
//                           -> go-jose JSONWebKey.Thumbprint(crypto.SHA256)
//  2. keyresolver.go +    — manual kty/crv EqualFold + RawURLEncoding.DecodeString(k.X)
//     endpointresolver.go   + the hand-rolled wellKnownDoc.Keys JWK struct
//                           -> go-jose jose.JSONWebKeySet decode
//  3. verify.go           — hand-rolled RFC 8941 parser cluster
//                           (parseSignatureInput/parseComponentList/splitParams/
//                            parseSignatureField)
//                           -> dunglas/httpsfv UnmarshalDictionary
//
// DELIBERATELY OUT OF SCOPE — the retained hand-built signature BASE builder in
// sigbase.go (buildSignatureBase/renderComponent/renderParamsTail/
// reconstructTargetURI) and sign.go: per ADR-020 L1 the base is the cross-language
// BYTE CONTRACT (injectable clock, pluggable Signer), NOT a reinvented crypto
// primitive. This guard MUST NOT flag those sites, and it does not read them.

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// readHelperSource returns the source of a helper file in this package
// directory. The guard reads source text on purpose: the disease it pins is a
// source-level construction choice with no runtime-observable footprint.
func readHelperSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// forbiddenPattern is a hand-rolled disease instance that MUST be gone after the
// refactor. requiredPattern is the library replacement that MUST be present.
type siteGuard struct {
	file      string
	forbidden []string // substrings that must NOT appear (hand-rolled disease)
	required  []string // substrings that MUST appear (vetted-library replacement)
}

// TestLibraryAdoptionGuard_ThumbprintUsesGoJose pins that thumbprint.go no
// longer hand-builds the canonical JWK string and hashes it directly, and
// instead computes the RFC 7638 thumbprint via go-jose.
func TestLibraryAdoptionGuard_ThumbprintUsesGoJose(t *testing.T) {
	assertSite(t, siteGuard{
		file: "thumbprint.go",
		forbidden: []string{
			`fmt.Sprintf(` + "`" + `{"crv":"Ed25519","kty":"OKP","x":%q}` + "`", // hand-built canonical JWK
			"sha256.Sum256([]byte(canonical))",                                 // hand-rolled hash over it
		},
		required: []string{
			"go-jose/go-jose/v4", // go-jose import
			".Thumbprint(",       // JSONWebKey.Thumbprint(crypto.SHA256)
		},
	})
}

// TestLibraryAdoptionGuard_KeyResolverUsesGoJoseJWKS pins that the JWKS decode
// path (keyresolver.go) and the shared wellKnownDoc.Keys struct
// (endpointresolver.go) no longer hand-roll the OKP/Ed25519 match and the raw
// base64url decode of the JWK `x` member, and instead decode via go-jose's
// jose.JSONWebKeySet.
func TestLibraryAdoptionGuard_KeyResolverUsesGoJoseJWKS(t *testing.T) {
	assertSite(t, siteGuard{
		file: "keyresolver.go",
		forbidden: []string{
			`strings.EqualFold(k.Kty, "OKP")`,               // manual kty match
			"base64.RawURLEncoding.DecodeString(k.X)",       // manual JWK x decode
		},
		required: []string{
			"jose.JSONWebKeySet", // go-jose JWKS decode
		},
	})
	// The hand-rolled JWK struct the key face decodes lives in the shared
	// wellKnownDoc.Keys in endpointresolver.go (scope refinement coupling #2/#3).
	src := readHelperSource(t, "endpointresolver.go")
	for _, forbidden := range []string{
		"Kty string `json:\"kty\"`",
		"Crv string `json:\"crv\"`",
		"X   string `json:\"x\"`",
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("endpointresolver.go still declares the hand-rolled JWK struct field %q; "+
				"the key face must decode via go-jose jose.JSONWebKeySet (json.RawMessage split), "+
				"keeping only the Endpoint field", forbidden)
		}
	}
}

// TestLibraryAdoptionGuard_VerifyUsesHTTPSFVParser pins that verify.go no longer
// hand-rolls the RFC 8941 structured-field parser cluster and instead parses the
// Signature-Input / Signature dictionaries via dunglas/httpsfv.
//
// It deliberately does NOT touch sigbase.go's retained signature-BASE builder:
// buildSignatureBase and its helpers stay hand-built (ADR-020 L1 byte contract).
func TestLibraryAdoptionGuard_VerifyUsesHTTPSFVParser(t *testing.T) {
	assertSite(t, siteGuard{
		file: "verify.go",
		forbidden: []string{
			"func parseSignatureInput(",
			"func parseComponentList(",
			"func splitParams(",
			"func parseSignatureField(",
		},
		required: []string{
			"dunglas/httpsfv",     // httpsfv import
			"httpsfv.UnmarshalDictionary", // RFC 8941 parser entrypoint
		},
	})
}

// evalSite is the pure guard predicate: it returns one message per violation
// (a forbidden hand-rolled instance still present, or a required vetted-library
// marker absent) in src. Extracted from assertSite so the guard logic itself is
// meta-testable against synthetic source without touching the real files.
func evalSite(src string, g siteGuard) []string {
	var violations []string
	for _, forbidden := range g.forbidden {
		if strings.Contains(src, forbidden) {
			violations = append(violations,
				fmt.Sprintf("%s still contains hand-rolled disease instance %q; it must be replaced by a vetted library", g.file, forbidden))
		}
	}
	for _, required := range g.required {
		if !strings.Contains(src, required) {
			violations = append(violations,
				fmt.Sprintf("%s is missing the vetted-library replacement %q; the hand-rolled path was not upgraded", g.file, required))
		}
	}
	return violations
}

func assertSite(t *testing.T, g siteGuard) {
	t.Helper()
	for _, v := range evalSite(readHelperSource(t, g.file), g) {
		t.Error(v)
	}
}

// --- Meta-tests: prove the guard both CATCHES a re-introduction (positive) and
// PASSES clean library-based source (negative). This guard is substring-based,
// not regex-based, so there is no regex-slip case to cover. ---

// syntheticGuard is a stand-in disease spec used only by the meta-tests, so they
// do not depend on the real file contents.
var syntheticGuard = siteGuard{
	file:      "synthetic.go",
	forbidden: []string{"sha256.Sum256([]byte(canonical))"},
	required:  []string{"go-jose/go-jose/v4"},
}

// TestLibraryAdoptionGuard_Meta_CatchesReintroduction is the positive meta-test:
// source that re-introduces the hand-rolled form AND drops the library must
// produce exactly two violations (disease present + library absent).
func TestLibraryAdoptionGuard_Meta_CatchesReintroduction(t *testing.T) {
	bad := "package p\nfunc f() { _ = sha256.Sum256([]byte(canonical)) }\n"
	got := evalSite(bad, syntheticGuard)
	if len(got) != 2 {
		t.Fatalf("guard must flag BOTH the re-introduced disease and the missing library; got %d: %v", len(got), got)
	}
}

// TestLibraryAdoptionGuard_Meta_PassesCleanSource is the negative meta-test:
// library-based source with none of the forbidden forms must produce zero
// violations, so the guard cannot false-positive on a correctly-upgraded file.
func TestLibraryAdoptionGuard_Meta_PassesCleanSource(t *testing.T) {
	good := "package p\n" +
		"import jose \"github.com/go-jose/go-jose/v4\"\n" +
		"func f() { _, _ = (&jose.JSONWebKey{}).Thumbprint(0) }\n"
	if got := evalSite(good, syntheticGuard); len(got) != 0 {
		t.Fatalf("guard must PASS clean library-based source; got violations: %v", got)
	}
}
