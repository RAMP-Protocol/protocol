package helpers_test

// Golden-vector emitter for the cross-language revocation-set-membership parity
// corpus. sdk/ts `revoked()` and sdk/python `revoked()` assert their verdict
// matches this sdk/go oracle for EVERY labelled case.
//
// The vector carries a served WBA directory (keys + validity windows), a served
// revocation snapshot (as_of + revoked thumbprints), a prime thumbprint (a
// directory-listed key resolved to populate the snapshot), and the labelled
// cases with their expected `revoked()` verdict. The verdicts are produced by
// RUNNING the real Go resolver against a real httptest origin — Go is the oracle,
// never a hand-authored table.
//
// DETERMINISM: every key is derived from a FIXED seed and every instant is a
// FIXED constant, so re-running reproduces byte-identical output. Default
// `go test` asserts the committed file matches a fresh emit; RAMP_UPDATE_VECTORS=1
// rewrites it (same drift-gate shape as gen_vectors_test.go).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// revMembershipJWK is one served directory key (snake_case, protojson shape).
type revMembershipJWK struct {
	X         string `json:"x"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// revMembershipCase is one labelled thumbprint and the oracle's revoked() verdict.
type revMembershipCase struct {
	Label           string `json:"label"`
	Thumbprint      string `json:"thumbprint"`
	ExpectedRevoked bool   `json:"expected_revoked"`
}

// revMembershipVector is the whole served-doc + cases corpus. The TS/python
// parity ports serve DirectoryKeys + a revocation snapshot built from AsOf +
// Revoked, resolve PrimeThumbprint to prime the snapshot, then assert revoked(tp)
// matches every case.
type revMembershipVector struct {
	Note            string              `json:"note"`
	AsOf            string              `json:"as_of"`
	DirectoryKeys   []revMembershipJWK  `json:"directory_keys"`
	Revoked         []string            `json:"revoked"`
	PrimeThumbprint string              `json:"prime_thumbprint"`
	Cases           []revMembershipCase `json:"cases"`
}

// revMembershipAnchor is the fixed instant the emitter clocks the resolver at —
// well inside the emitted validity windows.
var revMembershipAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// buildRevocationMembershipVector constructs the served docs, runs the real Go
// resolver as the oracle, and returns the vector with oracle-produced verdicts.
func buildRevocationMembershipVector(t *testing.T) revMembershipVector {
	t.Helper()
	windowStart := revMembershipAnchor.Add(-time.Hour)
	windowEnd := revMembershipAnchor.Add(1000 * time.Hour)

	presentPriv, presentJWK := newSigningKey("present.v1", windowStart, windowEnd)
	tpPresent := mustThumbprint(t, presentPriv.Public().(ed25519.PublicKey))
	absentPriv, _ := newSigningKey("absent-revoked.v1", windowStart, windowEnd)
	tpAbsentRevoked := mustThumbprint(t, absentPriv.Public().(ed25519.PublicKey))
	unknownPriv, _ := newSigningKey("unknown.v1", windowStart, windowEnd)
	tpUnknown := mustThumbprint(t, unknownPriv.Public().(ed25519.PublicKey))

	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBAWithRevocation(presentJWK, origin.revocationURL()))
	origin.setRevocation(marshalRevocation(revMembershipAnchor, tpAbsentRevoked))

	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		Now:    func() time.Time { return revMembershipAnchor },
	})
	if _, err := r.Resolve(ctx, tpPresent); err != nil {
		t.Fatalf("prime resolve: %v", err)
	}

	cases := []revMembershipCase{
		{Label: "directory-absent-but-revoked", Thumbprint: tpAbsentRevoked, ExpectedRevoked: r.Revoked(tpAbsentRevoked)},
		{Label: "directory-present-not-revoked", Thumbprint: tpPresent, ExpectedRevoked: r.Revoked(tpPresent)},
		{Label: "unknown", Thumbprint: tpUnknown, ExpectedRevoked: r.Revoked(tpUnknown)},
	}
	// Sanity: the oracle must produce the semantics the labels claim.
	assertRevMembershipSemantics(t, cases)

	return revMembershipVector{
		Note:            "revoked() reports revocation-set membership independent of WBA directory membership; verdicts produced by the sdk/go oracle",
		AsOf:            revMembershipAnchor.UTC().Format(time.RFC3339),
		DirectoryKeys:   []revMembershipJWK{{X: presentJWK.GetX(), NotBefore: presentJWK.GetNotBefore(), NotAfter: presentJWK.GetNotAfter()}},
		Revoked:         []string{tpAbsentRevoked},
		PrimeThumbprint: tpPresent,
		Cases:           cases,
	}
}

func assertRevMembershipSemantics(t *testing.T, cases []revMembershipCase) {
	t.Helper()
	want := map[string]bool{
		"directory-absent-but-revoked":  true,
		"directory-present-not-revoked": false,
		"unknown":                       false,
	}
	for _, c := range cases {
		exp, ok := want[c.Label]
		if !ok {
			t.Fatalf("unexpected case label %q", c.Label)
		}
		if c.ExpectedRevoked != exp {
			t.Fatalf("oracle verdict for %q = %v, want %v", c.Label, c.ExpectedRevoked, exp)
		}
	}
}

// TestGenerateRevocationMembershipVector emits the revocation-membership golden
// vector. Default run asserts the committed file is byte-identical to a fresh
// emit; RAMP_UPDATE_VECTORS=1 rewrites it.
func TestGenerateRevocationMembershipVector(t *testing.T) {
	t.Parallel()
	vec := buildRevocationMembershipVector(t)
	path := filepath.Join("testdata", "revocation-membership-vectors.json")

	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeRevMembershipVector(t, path, vec)
		return
	}
	want, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", path)
	}
}

func writeRevMembershipVector(t *testing.T, path string, vec revMembershipVector) {
	t.Helper()
	b, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // committed test vector
		t.Fatalf("write %s: %v", path, err)
	}
}
