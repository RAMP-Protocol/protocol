package ramp_test

// Structural guard for the sdk/go L2 low-tier relocation (ixs7u.9). This is the
// class-level counter-measure the sweep-verify atom requires: it pins that the
// L2 client/server faces stay TWO FACES OVER THE L1 helpers (the Core
// Invariant) and do not re-hand-roll the signing / verification the L1 package
// already owns. If a future edit reintroduces the disease — a bespoke RFC 9421
// sign/verify in L2 instead of composing sdk/go/helpers — a required-marker
// disappears and this test fails.
//
// SCOPE — deliberately the sdk/go L2 packages ONLY. A tree-wide ban on
// hand-rolled sign/verify would false-fire on the app's internal/httpsig +
// internal/ramphttpsig, which MUST still exist until their deletion in the
// downstream adoption ticket (ixs7u.11). The tree-wide guard belongs to that
// ticket; here the guard is correctly scoped to the new canonical L2.
//
// The behavioral guards (client sign→verify round-trip, fail-closed
// {verified,rejected}, replay rejection, the compile-guard in
// doc_compileguard_test.go) remain the primary safety net; this file adds the
// source-level composition guard the sweep atom asks for.

import (
	"fmt"
	"os"
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
	for _, v := range evalSite(readSource(t, "../rampconnect/verify.go"), "rampconnect/verify.go",
		[]string{"helpers.VerifyMultisigRequestResolved"}, nil) {
		t.Error(v)
	}
}

// --- Meta-tests: prove the guard CATCHES a reintroduction (positive) and
// PASSES clean composed source (negative). Substring-based, so no regex-slip
// case exists. ---

func TestLibraryAdoptionGuard_Meta_CatchesReinvention(t *testing.T) {
	// L1 marker dropped AND a bespoke ed25519 sign reintroduced → two violations.
	bad := "package ramp\nfunc sign() { _ = ed25519.Sign(priv, base) }\n"
	got := evalSite(bad, "synthetic.go",
		[]string{"helpers.SignRequest"}, []string{"ed25519.Sign("})
	if len(got) != 2 {
		t.Fatalf("guard must flag BOTH the missing L1 marker and the reinvention; got %d: %v", len(got), got)
	}
}

func TestLibraryAdoptionGuard_Meta_PassesCleanSource(t *testing.T) {
	good := "package ramp\nfunc sign() { _ = helpers.SignRequest(ctx, req, body, s, o) }\n"
	if got := evalSite(good, "synthetic.go",
		[]string{"helpers.SignRequest"}, []string{"ed25519.Sign("}); len(got) != 0 {
		t.Fatalf("guard must PASS clean composed source; got: %v", got)
	}
}
