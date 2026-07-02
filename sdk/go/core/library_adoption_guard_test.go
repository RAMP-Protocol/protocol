package core_test

// Structural guard for the sdk/go L2 low-tier packages after the core/connect
// split. Two invariants are pinned here:
//
//  1. L1 COMPOSITION — the L2 client sign face, the offer Verifier, and the server
//     verify seam compose the sdk/go/helpers L1 primitives (SignRequest,
//     VerifyOffer, VerifyMultisigRequestResolved) rather than re-hand-rolling RFC
//     9421 sign/verify. If a future edit reintroduces the disease — a bespoke
//     sign/verify in L2 — a required marker disappears and the guard fails.
//
//  2. TRANSPORT NEUTRALITY — no non-test .go file in sdk/go/core OR sdk/go/helpers
//     may import connectrpc.com/*. That is the Core Invariant of the split: a
//     grpc-go / plain net/http / any-transport consumer of core (and of the L1
//     helpers it builds on) compiles ZERO Connect. Connect lives ONLY in the
//     bindings sdk/go/connect (client) and sdk/go/connectserver (server). This
//     source-scan is the fast complement to the authoritative `go list -deps`
//     closure gate (which the CI + the acceptance criteria run); the two are NOT
//     equivalent (a scan cannot see a transitive import via another package), so
//     both are kept — this file is the scan half for core + helpers.
//
// SCOPE — deliberately the sdk/go L2/L1 packages ONLY. A tree-wide ban on
// hand-rolled sign/verify would false-fire on the app's internal/httpsig +
// internal/ramphttpsig, which MUST still exist until their deletion in the
// downstream adoption ticket. The tree-wide guard belongs to that ticket; here the
// guard is correctly scoped to the new canonical L2 substance.
//
// The behavioral guards (client sign→verify round-trip, fail-closed
// {verified,rejected}, replay rejection, the compile-guard in
// doc_compileguard_test.go) remain the primary safety net; this file adds the
// source-level composition + neutrality guards the sweep atom asks for.

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// evalSite is the pure guard predicate: it returns one message per violation (a
// required L1-composition marker absent, or a forbidden reinvention present) in
// src. Extracted so the meta-tests exercise the guard logic against synthetic
// source without touching the real files.
func evalSite(src, file string, required, forbidden []string) []string {
	var violations []string
	for _, req := range required {
		if !strings.Contains(src, req) {
			violations = append(violations,
				fmt.Sprintf("%s is missing the L1-composition marker %q; the L2 face must compose sdk/go/helpers, not reinvent it", file, req))
		}
	}
	for _, bad := range forbidden {
		if strings.Contains(src, bad) {
			violations = append(violations,
				fmt.Sprintf("%s contains the reinvention marker %q; route it through sdk/go/helpers instead", file, bad))
		}
	}
	return violations
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestLibraryAdoptionGuard_ClientSignComposesL1 pins that the client sign face
// signs via helpers.SignRequest (the L1 primitive) rather than a bespoke RFC
// 9421 signer.
func TestLibraryAdoptionGuard_ClientSignComposesL1(t *testing.T) {
	for _, v := range evalSite(readSource(t, "transport.go"), "transport.go",
		[]string{"helpers.SignRequest"}, nil) {
		t.Error(v)
	}
}

// TestLibraryAdoptionGuard_OfferVerifyComposesL1 pins that the unified offer
// Verifier verifies via helpers.VerifyOffer rather than a bespoke check.
func TestLibraryAdoptionGuard_OfferVerifyComposesL1(t *testing.T) {
	for _, v := range evalSite(readSource(t, "verifier.go"), "verifier.go",
		[]string{"helpers.VerifyOffer"}, nil) {
		t.Error(v)
	}
}

// TestLibraryAdoptionGuard_ServerVerifyComposesL1 pins that the server verify
// seam runs the L1 request verifier rather than a bespoke RFC 9421 verify.
func TestLibraryAdoptionGuard_ServerVerifyComposesL1(t *testing.T) {
	for _, v := range evalSite(readSource(t, "../connectserver/verify.go"), "connectserver/verify.go",
		[]string{"helpers.VerifyMultisigRequestResolved"}, nil) {
		t.Error(v)
	}
}

// --- Meta-tests for the L1-composition guard: prove it CATCHES a reintroduction
// (positive) and PASSES clean composed source (negative). Substring-based, so no
// regex-slip case exists. ---

func TestLibraryAdoptionGuard_Meta_CatchesReinvention(t *testing.T) {
	// L1 marker dropped AND a bespoke ed25519 sign reintroduced → two violations.
	bad := "package core\nfunc sign() { _ = ed25519.Sign(priv, base) }\n"
	got := evalSite(bad, "synthetic.go",
		[]string{"helpers.SignRequest"}, []string{"ed25519.Sign("})
	if len(got) != 2 {
		t.Fatalf("guard must flag BOTH the missing L1 marker and the reinvention; got %d: %v", len(got), got)
	}
}

func TestLibraryAdoptionGuard_Meta_PassesCleanSource(t *testing.T) {
	good := "package core\nfunc sign() { _ = helpers.SignRequest(ctx, req, body, s, o) }\n"
	if got := evalSite(good, "synthetic.go",
		[]string{"helpers.SignRequest"}, []string{"ed25519.Sign("}); len(got) != 0 {
		t.Fatalf("guard must PASS clean composed source; got: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Transport-neutrality guard: no connectrpc.com import in core/*.go or helpers/*.go.
// ---------------------------------------------------------------------------

const connectrpcModulePrefix = "connectrpc.com"

// importsConnectrpc parses src as Go source and reports whether ANY of its import
// specs has a path under connectrpc.com. It returns the offending import path (for a
// precise failure message) and true when the forbidden dependency is present.
// Parsing (rather than substring scanning) is what makes a "connectrpc.com" mention
// in a COMMENT a non-match — only a real import spec triggers the guard.
func importsConnectrpc(t *testing.T, filename, src string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, spec := range f.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if path == connectrpcModulePrefix || strings.HasPrefix(path, connectrpcModulePrefix+"/") {
			return path, true
		}
	}
	return "", false
}

// scanNoConnectrpc asserts no non-test .go file in dir imports connectrpc.com/*.
func scanNoConnectrpc(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		src := readSource(t, filepath.Join(dir, name))
		if path, bad := importsConnectrpc(t, name, src); bad {
			t.Errorf(
				"%s/%s imports %q; this package must be transport-neutral (zero Connect) so a non-Connect consumer compiles no connectrpc — the Connect binding lives ONLY in sdk/go/connect",
				dir, name, path)
		}
	}
	if scanned == 0 {
		t.Fatalf("scanned 0 non-test .go files in %s; the guard is not looking at the right directory", dir)
	}
}

// TestCoreConnectrpcFree pins that no non-test .go file in sdk/go/core imports
// connectrpc.com/* — the transport-neutral L2 substance imposes no Connect
// dependency.
func TestCoreConnectrpcFree(t *testing.T) {
	scanNoConnectrpc(t, ".")
	if _, statErr := os.Stat("verifier.go"); statErr != nil {
		t.Fatalf("expected sdk/go/core/verifier.go to exist as the guard's anchor: %v", statErr)
	}
}

// TestHelpersConnectrpcFree pins that no non-test .go file in sdk/go/helpers imports
// connectrpc.com/* — the L1 helpers a core consumer builds on stay Connect-free too
// (the AsConnectError/ErrorDetailFrom bridge moved to sdk/go/connect). The helpers
// package also carries its own copy of this scan (connectrpc_free_test.go); this
// assertion is the core-side dual so the neutrality of BOTH layers is pinned from
// the guard that owns the core/connect boundary.
func TestHelpersConnectrpcFree(t *testing.T) {
	scanNoConnectrpc(t, "../helpers")
	if _, statErr := os.Stat(filepath.Join("../helpers", "errordetail.go")); statErr != nil {
		t.Fatalf("expected sdk/go/helpers/errordetail.go to exist as the guard's anchor: %v", statErr)
	}
}

// --- Meta-tests for the neutrality predicate: prove it CATCHES a real connectrpc
// import (positive) and does NOT fire on a comment-only mention or a clean file
// (negative). Parser-based, so the doc-comment false-positive class a raw substring
// scan would hit cannot occur. ---

func TestConnectrpcFree_Meta_CatchesRealImport(t *testing.T) {
	src := "package core\n\nimport (\n\t\"errors\"\n\n\t\"connectrpc.com/connect\"\n)\n\nvar _ = errors.New\nvar _ = connect.CodeUnauthenticated\n"
	path, bad := importsConnectrpc(t, "synthetic.go", src)
	if !bad {
		t.Fatal("guard must flag a real connectrpc.com/connect import")
	}
	if path != "connectrpc.com/connect" {
		t.Fatalf("guard must report the offending import path; got %q", path)
	}
}

func TestConnectrpcFree_Meta_IgnoresCommentMention(t *testing.T) {
	src := "package core\n\n// This wraps connectrpc.com/validate under the hood, but imports nothing from it.\nimport \"sync\"\n\nvar _ sync.Mutex\n"
	if _, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatal("guard must NOT fire on a comment-only connectrpc.com mention")
	}
}

func TestConnectrpcFree_Meta_PassesCleanSource(t *testing.T) {
	src := "package core\n\nimport (\n\t\"errors\"\n\n\trampv1 \"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1\"\n)\n\nvar _ = errors.New\nvar _ *rampv1.ErrorDetail\n"
	if path, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatalf("guard must PASS a connect-free file; flagged %q", path)
	}
}
