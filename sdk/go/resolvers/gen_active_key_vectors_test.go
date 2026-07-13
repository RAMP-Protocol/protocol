package resolvers_test

// Golden-vector emitter for the cross-language active-Ed25519-key selector parity
// corpus. sdk/python `active_ed25519_key(_with_expiry)` and sdk/ts
// `activeEd25519Key(WithExpiry)` REPLAY this corpus and MUST reproduce the sdk/go
// `ActiveEd25519Key` oracle's selection for EVERY vector.
//
// Each vector is a WBA directory (keys[] with validity windows + JWK `x`), an
// optional max_scan, and the oracle's verdict: the selected key's DOCUMENT-ORDER
// index (-1 = none), its raw public key (base64url), and its not_after. The
// verdict is produced by RUNNING the real Go selector against the built directory
// — Go is the oracle, never a hand-authored table — and a per-vector sanity gate
// asserts the oracle picked the index the vector was constructed to exercise.
//
// COVERAGE (the edges the three languages must agree on): the H2 base64 edges
// (standard-alphabet `x`, `=`-padded `x`, valid unpadded `x`), the C1 timestamp
// edges (offset-less/naive bounds, date-only bounds, empty/missing bounds, the
// not_before==now and not_after==now half-open boundaries), and the max_scan DoS
// cap (winner just inside the cap, just past it, and reachable once the cap is
// raised). Replaying it in all three languages is what LOCKS parity and would
// have caught the H2/C1 divergences.
//
// DETERMINISM: every key is derived from a FIXED seed and every instant is a
// FIXED offset from wbaAnchor, so re-running reproduces byte-identical output.
// Default `go test` asserts the committed file matches a fresh emit;
// RAMP_UPDATE_VECTORS=1 rewrites it (same drift-gate shape as
// gen_revocation_membership_vectors_test.go).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// activeKeyJWK is one served directory key (snake_case, protojson shape). Only
// the members the selector reads are emitted; use/alg are irrelevant to selection.
type activeKeyJWK struct {
	Kty       string `json:"kty"`
	Crv       string `json:"crv"`
	X         string `json:"x"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// activeKeyVector is one served directory + the oracle's selection verdict.
type activeKeyVector struct {
	Label            string         `json:"label"`
	Note             string         `json:"note"`
	MaxScan          *int           `json:"max_scan"` // null → the selector's default cap
	Keys             []activeKeyJWK `json:"keys"`
	ExpectedIndex    int            `json:"expected_index"`     // -1 = no key qualifies
	ExpectedPub      string         `json:"expected_pub"`       // base64url raw pub; "" when none
	ExpectedNotAfter string         `json:"expected_not_after"` // RFC3339; "" when none
}

// activeKeyCorpus is the whole served-doc + verdicts corpus.
type activeKeyCorpus struct {
	Note    string            `json:"note"`
	Now     string            `json:"now"`
	Vectors []activeKeyVector `json:"vectors"`
}

// kb pairs a built directory JWK with its raw public key. pub is nil when the key
// is deliberately unselectable (malformed `x`, wrong kty/crv, wrong length) so the
// index-of-selected lookup never spuriously matches it.
type kb struct {
	jwk activeKeyJWK
	pub []byte
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func toAKJWK(j *rampv1.JsonWebKey) activeKeyJWK {
	return activeKeyJWK{Kty: j.GetKty(), Crv: j.GetCrv(), X: j.GetX(), NotBefore: j.GetNotBefore(), NotAfter: j.GetNotAfter()}
}

// activeKB / expiredKB / futureKB build a valid OKP/Ed25519 key whose window
// straddles (or excludes) wbaAnchor. pub is the real 32-byte public key.
func activeKB(seed string) kb {
	priv, j := newSigningKey(seed, wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	return kb{jwk: toAKJWK(j), pub: priv.Public().(ed25519.PublicKey)}
}

func expiredKB(seed string) kb {
	priv, j := newSigningKey(seed, wbaAnchor.Add(-2*time.Hour), wbaAnchor.Add(-time.Hour))
	return kb{jwk: toAKJWK(j), pub: priv.Public().(ed25519.PublicKey)}
}

func futureKB(seed string) kb {
	priv, j := newSigningKey(seed, wbaAnchor.Add(time.Hour), wbaAnchor.Add(2*time.Hour))
	return kb{jwk: toAKJWK(j), pub: priv.Public().(ed25519.PublicKey)}
}

// withBounds overrides an active key's window bounds (for the naive/date-only/
// empty/boundary timestamp edges) and clears pub only when the key stays inactive.
func withBounds(base kb, notBefore, notAfter string, selectable bool) kb {
	base.jwk.NotBefore = notBefore
	base.jwk.NotAfter = notAfter
	if !selectable {
		base.pub = nil
	}
	return base
}

// stdAlphaKB builds a window-active key whose `x` is UNPADDED STANDARD base64
// (contains + or /), which py/ts previously lenient-decoded but Go's
// RawURLEncoding rejects → strict-unselectable (pub nil). Deterministic: the first
// seed whose std encoding actually differs from urlsafe.
func stdAlphaKB() kb {
	for i := 0; ; i++ {
		priv, j := newSigningKey(fmt.Sprintf("stdalpha-%d", i), wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
		pub := priv.Public().(ed25519.PublicKey)
		std := base64.RawStdEncoding.EncodeToString(pub)
		if strings.ContainsAny(std, "+/") {
			ak := toAKJWK(j)
			ak.X = std
			return kb{jwk: ak, pub: nil}
		}
	}
}

// paddedKB builds a window-active key whose `x` is urlsafe base64 WITH `=`
// padding — same alphabet as a valid key, only the padding differs — which py/ts
// previously accepted but Go's RawURLEncoding rejects → strict-unselectable.
func paddedKB() kb {
	priv, j := newSigningKey("padded", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	ak := toAKJWK(j)
	ak.X = base64.URLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) // urlsafe + '=' pad
	return kb{jwk: ak, pub: nil}
}

// mutateActive clones a window-active key and applies a field mutation that makes
// it unselectable (non-OKP, wrong crv, wrong length, undecodable x).
func mutateActive(seed string, mutate func(*activeKeyJWK)) kb {
	base := activeKB(seed)
	mutate(&base.jwk)
	base.pub = nil
	return base
}

func intp(v int) *int { return &v }

// buildVector assembles the directory, runs the real Go selector as the oracle,
// asserts it selected wantIndex (the sanity gate), and returns the vector with
// oracle-produced verdict fields. Both the plain and with-expiry faces are run and
// asserted to agree.
func buildVector(t *testing.T, label, note string, maxScan *int, keys []kb, wantIndex int) activeKeyVector {
	t.Helper()
	jwks := make([]*rampv1.JsonWebKey, len(keys))
	aks := make([]activeKeyJWK, len(keys))
	for i, k := range keys {
		jwks[i] = &rampv1.JsonWebKey{Kty: k.jwk.Kty, Crv: k.jwk.Crv, X: k.jwk.X, NotBefore: k.jwk.NotBefore, NotAfter: k.jwk.NotAfter}
		aks[i] = k.jwk
	}
	dir := &rampv1.WBAFile{Keys: jwks}
	var scanArgs []int
	if maxScan != nil {
		scanArgs = []int{*maxScan}
	}

	pub, notAfter, err := resolvers.ActiveEd25519KeyWithExpiry(dir, wbaAnchor, scanArgs...)
	plain, plainErr := resolvers.ActiveEd25519Key(dir, wbaAnchor, scanArgs...)
	assertFacesAgree(t, label, pub, err, plain, plainErr)

	gotIndex, expPub, expNotAfter := oracleVerdict(keys, pub, notAfter, err)
	if gotIndex != wantIndex {
		t.Fatalf("%s: oracle selected index %d, vector was built for %d", label, gotIndex, wantIndex)
	}
	return activeKeyVector{Label: label, Note: note, MaxScan: maxScan, Keys: aks, ExpectedIndex: gotIndex, ExpectedPub: expPub, ExpectedNotAfter: expNotAfter}
}

// oracleVerdict turns the selector's (pub, notAfter, err) into the recorded
// (index, base64url-pub, RFC3339-not_after). index is the document-order position
// of the selected key (matched by its known public key), or -1 when none.
func oracleVerdict(keys []kb, pub ed25519.PublicKey, notAfter time.Time, err error) (int, string, string) {
	if err != nil {
		return -1, "", ""
	}
	for i, k := range keys {
		if k.pub != nil && bytes.Equal(k.pub, pub) {
			return i, base64.RawURLEncoding.EncodeToString(pub), rfc(notAfter)
		}
	}
	return -1, base64.RawURLEncoding.EncodeToString(pub), rfc(notAfter)
}

func assertFacesAgree(t *testing.T, label string, pub ed25519.PublicKey, err error, plain ed25519.PublicKey, plainErr error) {
	t.Helper()
	if (err == nil) != (plainErr == nil) {
		t.Fatalf("%s: faces disagree on error: withExpiry=%v plain=%v", label, err, plainErr)
	}
	if err == nil && !bytes.Equal(pub, plain) {
		t.Fatalf("%s: faces disagree on selected key", label)
	}
}

func buildBasicVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	return []activeKeyVector{
		buildVector(t, "selects-first-active", "two active keys: the first in document order wins", nil,
			[]kb{activeKB("a1"), activeKB("a2")}, 0),
		buildVector(t, "skips-retired-then-active", "a retired key ahead of the active one is skipped", nil,
			[]kb{expiredKB("dead"), activeKB("live")}, 1),
		buildVector(t, "skips-future-then-active", "a not-yet-valid key ahead of the active one is skipped", nil,
			[]kb{futureKB("early"), activeKB("live")}, 1),
		buildVector(t, "empty-directory-none", "an empty directory selects nothing", nil,
			[]kb{}, -1),
		buildVector(t, "all-inactive-none", "a directory of only retired/future keys selects nothing", nil,
			[]kb{expiredKB("x"), futureKB("y")}, -1),
	}
}

func buildBase64Vectors(t *testing.T) []activeKeyVector {
	t.Helper()
	return []activeKeyVector{
		buildVector(t, "valid-unpadded-x-selected", "a valid unpadded-urlsafe x decodes and is selected (H2 unchanged path)", nil,
			[]kb{activeKB("valid")}, 0),
		buildVector(t, "standard-alphabet-x-then-valid", "an active key with a STANDARD-alphabet x (+//) is skipped; the next valid key wins (H2)", nil,
			[]kb{stdAlphaKB(), activeKB("valid")}, 1),
		buildVector(t, "standard-alphabet-x-only-none", "the only key has a STANDARD-alphabet x; Go rejects it → none (H2: py/ts once selected it)", nil,
			[]kb{stdAlphaKB()}, -1),
		buildVector(t, "padded-x-then-valid", "an active key with a '='-PADDED urlsafe x is skipped; the next valid key wins (H2)", nil,
			[]kb{paddedKB(), activeKB("valid")}, 1),
		buildVector(t, "padded-x-only-none", "the only key has a '='-PADDED x; Go rejects it → none (H2: py/ts once selected it)", nil,
			[]kb{paddedKB()}, -1),
		buildVector(t, "non-okp-then-valid", "a window-active non-OKP key is skipped; the next valid key wins", nil,
			[]kb{mutateActive("rsa", func(j *activeKeyJWK) { j.Kty = "RSA" }), activeKB("valid")}, 1),
		buildVector(t, "wrong-crv-then-valid", "a window-active non-Ed25519 key is skipped; the next valid key wins", nil,
			[]kb{mutateActive("p256", func(j *activeKeyJWK) { j.Crv = "P-256" }), activeKB("valid")}, 1),
		buildVector(t, "wrong-length-x-then-valid", "a window-active key whose x decodes to 31 bytes is skipped", nil,
			[]kb{mutateActive("short", func(j *activeKeyJWK) { j.X = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) }), activeKB("valid")}, 1),
		buildVector(t, "undecodable-x-then-valid", "a window-active key whose x is not base64url is skipped", nil,
			[]kb{mutateActive("junk", func(j *activeKeyJWK) { j.X = "!!!!" }), activeKB("valid")}, 1),
	}
}

func buildTimestampVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	naive := func(seed string) kb {
		return withBounds(activeKB(seed), "2026-05-01T11:00:00", "2026-05-01T13:00:00", false)
	}
	dateOnly := func(seed string) kb {
		return withBounds(activeKB(seed), "2026-05-01", "2026-05-02", false)
	}
	empty := func(seed string) kb { return withBounds(activeKB(seed), "", "", false) }
	nbEqNow := withBounds(activeKB("nbnow"), rfc(wbaAnchor), rfc(wbaAnchor.Add(time.Hour)), true)
	naEqNow := withBounds(activeKB("nanow"), rfc(wbaAnchor.Add(-time.Hour)), rfc(wbaAnchor), false)
	return []activeKeyVector{
		buildVector(t, "offset-less-bound-then-valid", "an offset-less (naive) window is inactive; the next valid key wins (C1)", nil,
			[]kb{naive("naive"), activeKB("valid")}, 1),
		buildVector(t, "offset-less-bound-only-none", "the only key has offset-less bounds → none (C1)", nil,
			[]kb{naive("naive")}, -1),
		buildVector(t, "date-only-bound-then-valid", "a date-only (no time) bound is unparseable → inactive; the next valid key wins", nil,
			[]kb{dateOnly("dateonly"), activeKB("valid")}, 1),
		buildVector(t, "date-only-bound-only-none", "the only key has date-only bounds → none", nil,
			[]kb{dateOnly("dateonly")}, -1),
		buildVector(t, "empty-bounds-then-valid", "empty/missing window bounds are inactive; the next valid key wins", nil,
			[]kb{empty("empty"), activeKB("valid")}, 1),
		buildVector(t, "boundary-not-before-equals-now", "not_before==now is INSIDE the half-open window → selected", nil,
			[]kb{nbEqNow}, 0),
		buildVector(t, "boundary-not-after-equals-now-none", "not_after==now is OUTSIDE the half-open window → none", nil,
			[]kb{naEqNow}, -1),
		buildVector(t, "boundary-not-after-equals-now-then-valid", "a not_after==now key is inactive; the next valid key wins", nil,
			[]kb{naEqNow, activeKB("valid")}, 1),
	}
}

func buildCapVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	fillers := func(n int) []kb {
		out := make([]kb, 0, n)
		for i := range n {
			out = append(out, expiredKB(fmt.Sprintf("filler-%d", i)))
		}
		return out
	}
	winnerAt9 := append(fillers(9), activeKB("target"))
	winnerAt10 := append(fillers(10), activeKB("target"))
	return []activeKeyVector{
		buildVector(t, "winner-within-default-cap", "a valid key at index 9 is within the default scan cap → selected", nil,
			winnerAt9, 9),
		buildVector(t, "winner-past-default-cap-none", "a valid key at index 10 is past the default cap → unreachable → none", nil,
			winnerAt10, -1),
		buildVector(t, "winner-reached-with-raised-cap", "raising max_scan to 11 reaches the index-10 key", intp(11),
			winnerAt10, 10),
	}
}

func buildActiveKeyCorpus(t *testing.T) activeKeyCorpus {
	t.Helper()
	vectors := buildBasicVectors(t)
	vectors = append(vectors, buildBase64Vectors(t)...)
	vectors = append(vectors, buildTimestampVectors(t)...)
	vectors = append(vectors, buildCapVectors(t)...)
	return activeKeyCorpus{
		Note:    "active_ed25519_key document-order selection verdicts produced by the sdk/go oracle; py/ts replay and must match every vector",
		Now:     rfc(wbaAnchor),
		Vectors: vectors,
	}
}

// TestGenerateActiveKeyVector emits the active-key golden vector. Default run
// asserts the committed file is byte-identical to a fresh emit; RAMP_UPDATE_VECTORS=1
// rewrites it.
func TestGenerateActiveKeyVector(t *testing.T) {
	t.Parallel()
	corpus := buildActiveKeyCorpus(t)
	path := filepath.Join("testdata", "active-ed25519-key-vectors.json")

	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeActiveKeyVector(t, path, corpus)
		return
	}
	want, err := json.MarshalIndent(corpus, "", "  ")
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

func writeActiveKeyVector(t *testing.T, path string, corpus activeKeyCorpus) {
	t.Helper()
	b, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // committed test vector
		t.Fatalf("write %s: %v", path, err)
	}
}
