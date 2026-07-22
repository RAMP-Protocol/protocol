package helpers_test

// Structural neutrality guard for the sdk/go L1 helpers package (the
// core/connect split with the folded-in AsConnectError decouple). The Core
// Invariant of that refactor is transport neutrality: a grpc-go / plain
// net/http / any-transport consumer that only wants the neutral L1 mechanics
// (ErrorDetail builders, sign/verify, key-resolution, money, signed URLs) must
// compile ZERO Connect. Today that invariant is VIOLATED — errordetail.go
// imports connectrpc.com/connect for AsConnectError(connect.Code, ...) and the
// connect.Error unwrap path in ErrorDetailFrom — so this guard FAILS now (TDD
// red). The refactor moves AsConnectError into the connect binding, at which
// point the only connectrpc importer left in helpers disappears and this guard
// passes.
//
// This is a STRUCTURAL guard, not a behavior test: the refactor it pins is
// behavior-preserving, so the byte-level behavior net lives in the L2 suites
// (sdk/go/core/*, sdk/go/connect/*) which must stay green through the move. This
// guard pins the package-boundary invariant those suites cannot see.
//
// SCOPE — the sdk/go/helpers directory ONLY. It is the fast source-scan
// complement to the authoritative deps-closure gate
// (`go list -deps ./sdk/go/helpers | grep -c connectrpc == 0`), which the
// IMPLEMENT step adds alongside the core-side neutrality guard. A source scan
// and the deps-closure gate are NOT equivalent (the scan cannot see a
// transitive import pulled in via another package), so both are kept; this file
// is the scan half for helpers.
//
// Import detection uses go/parser (real import specs), NOT a raw substring
// match, so a doc comment that merely mentions "connectrpc.com" (e.g.
// validate.go's prose about connectrpc.com/validate) is correctly NOT flagged —
// only an actual import counts.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const connectrpcModulePrefix = "connectrpc.com"

// importsConnectrpc is the pure guard predicate: it parses src as Go source and
// reports whether ANY of its import specs has a path under connectrpc.com. It
// returns the offending import path (for a precise failure message) and true
// when the forbidden dependency is present. Parsing (rather than substring
// scanning) is what makes a "connectrpc.com" mention in a COMMENT a non-match —
// only a real import spec triggers the guard. filename is used solely for the
// parser's error position reporting.
func importsConnectrpc(t *testing.T, filename, src string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, spec := range f.Imports {
		// spec.Path.Value is the quoted import path, e.g. "connectrpc.com/connect".
		path := strings.Trim(spec.Path.Value, `"`)
		if path == connectrpcModulePrefix || strings.HasPrefix(path, connectrpcModulePrefix+"/") {
			return path, true
		}
	}
	return "", false
}

func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestHelpersConnectrpcFree pins the neutrality invariant: no non-test .go file
// in sdk/go/helpers may import connectrpc.com/*. It FAILS today because
// errordetail.go imports connectrpc.com/connect; it passes once the refactor
// moves AsConnectError into the connect binding.
func TestHelpersConnectrpcFree(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read helpers dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		src := readSourceFile(t, name)
		if path, bad := importsConnectrpc(t, name, src); bad {
			t.Errorf(
				"sdk/go/helpers/%s imports %q; the L1 helpers package must be transport-neutral (zero Connect) so a non-Connect consumer compiles no connectrpc — move the Connect-coupled code (AsConnectError / connect.Error unwrap) into the connect binding",
				name, path)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned 0 non-test .go files in sdk/go/helpers; the guard is not looking at the right directory")
	}
	// Cross-check the scan is anchored on the real package, not an empty cwd.
	if _, statErr := os.Stat(filepath.Join(".", "errordetail.go")); statErr != nil {
		t.Fatalf("expected sdk/go/helpers/errordetail.go to exist as the guard's anchor: %v", statErr)
	}
}

// --- Meta-tests: prove the predicate CATCHES a real connectrpc import
// (positive) and does NOT fire on a comment-only mention or a clean file
// (negative). Parser-based, so the doc-comment false-positive class that a raw
// substring scan would hit cannot occur. ---

func TestHelpersConnectrpcFree_Meta_CatchesRealImport(t *testing.T) {
	src := "package helpers\n\nimport (\n\t\"errors\"\n\n\t\"connectrpc.com/connect\"\n)\n\nvar _ = errors.New\nvar _ = connect.CodeUnauthenticated\n"
	path, bad := importsConnectrpc(t, "synthetic.go", src)
	if !bad {
		t.Fatal("guard must flag a real connectrpc.com/connect import")
	}
	if path != "connectrpc.com/connect" {
		t.Fatalf("guard must report the offending import path; got %q", path)
	}
}

func TestHelpersConnectrpcFree_Meta_IgnoresCommentMention(t *testing.T) {
	// A file that only MENTIONS connectrpc.com in a comment (as validate.go does)
	// must NOT be flagged — only real imports count.
	src := "package helpers\n\n// This wraps connectrpc.com/validate under the hood, but imports nothing from it.\nimport \"sync\"\n\nvar _ sync.Mutex\n"
	if _, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatal("guard must NOT fire on a comment-only connectrpc.com mention")
	}
}

func TestHelpersConnectrpcFree_Meta_PassesCleanSource(t *testing.T) {
	src := "package helpers\n\nimport (\n\t\"errors\"\n\n\trampv1 \"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1\"\n)\n\nvar _ = errors.New\nvar _ *rampv1.ErrorDetail\n"
	if path, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatalf("guard must PASS a connect-free file; flagged %q", path)
	}
}
