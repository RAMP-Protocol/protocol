package resolvers_test

// wbakeyresolver_active_key_test.go — behavior suite for ActiveEd25519Key, the
// document-order active-key selector that complements the thumbprint-keyed
// WBAKeyResolver.Resolve. Byte-parity with the Python active_ed25519_key / TS
// activeEd25519Key oracles: iterate the directory's keys in DOCUMENT ORDER —
// UNBOUNDED by default (ActiveKeyScanOptions.MaxScan is an OPTIONAL cap) — return the
// FIRST window-active well-formed OKP/Ed25519 key whose x decodes to 32 bytes;
// skip-and-continue past any failing key; ErrUnknownKey when no well-formed candidate
// exists, ErrKeyExpired when a candidate existed but none was selectable. Pure logic
// over a *rampv1.WBAFile — no HTTP origin. Reuses the file-local newSigningKey /
// wbaAnchor fixtures; intp lives in gen_active_key_vectors_test.go (same package).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// activeWindowJWK / expiredWindowJWK / futureWindowJWK build a directory JWK
// member for the given x whose validity window straddles (or excludes) wbaAnchor.
func activeWindowJWK(seed string) (ed25519.PublicKey, *rampv1.JsonWebKey) {
	priv, jwk := newSigningKey(seed, wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	return priv.Public().(ed25519.PublicKey), jwk
}

func expiredWindowJWK(seed string) *rampv1.JsonWebKey {
	_, jwk := newSigningKey(seed, wbaAnchor.Add(-2*time.Hour), wbaAnchor.Add(-time.Hour))
	return jwk
}

func futureWindowJWK(seed string) *rampv1.JsonWebKey {
	_, jwk := newSigningKey(seed, wbaAnchor.Add(time.Hour), wbaAnchor.Add(2*time.Hour))
	return jwk
}

// longWindowJWK is window-active at wbaAnchor with a FAR not_after (anchor +
// 1000h), so a with-expiry test can assert a not_after distinct from the short
// activeWindowJWK bound.
func longWindowJWK(seed string) (ed25519.PublicKey, *rampv1.JsonWebKey) {
	priv, jwk := newSigningKey(seed, wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	return priv.Public().(ed25519.PublicKey), jwk
}

// naiveBoundsJWK builds a directory JWK whose validity bounds carry NO UTC
// offset. The span (11:00..13:00) straddles wbaAnchor (12:00Z), so a parser that
// wrongly accepted an offset-less bound would treat the key as active;
// time.Parse(time.RFC3339) rejects it, so the key is inactive (fail closed).
func naiveBoundsJWK(seed string) *rampv1.JsonWebKey {
	_, jwk := newSigningKey(seed, wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	jwk.NotBefore = "2026-05-01T11:00:00"
	jwk.NotAfter = "2026-05-01T13:00:00"
	return jwk
}

func wbaDirectory(keys ...*rampv1.JsonWebKey) *rampv1.WBAFile {
	return &rampv1.WBAFile{Keys: keys}
}

func TestActiveEd25519Key_SelectsFirstActive(t *testing.T) {
	t.Parallel()
	pub1, k1 := activeWindowJWK("a1")
	_, k2 := activeWindowJWK("a2")
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(k1, k2), wbaAnchor)
	if err != nil {
		t.Fatalf("ActiveEd25519Key: %v", err)
	}
	if !got.Equal(pub1) {
		t.Fatal("expected the FIRST active key in document order")
	}
}

func TestActiveEd25519Key_SkipsRetiredThenSelectsActive(t *testing.T) {
	t.Parallel()
	pub, active := activeWindowJWK("live")
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(expiredWindowJWK("dead"), active), wbaAnchor)
	if err != nil {
		t.Fatalf("ActiveEd25519Key: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("retired key ahead of the active one must be skipped")
	}
}

func TestActiveEd25519Key_SkipsFutureThenSelectsActive(t *testing.T) {
	t.Parallel()
	pub, active := activeWindowJWK("live")
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(futureWindowJWK("early"), active), wbaAnchor)
	if err != nil {
		t.Fatalf("ActiveEd25519Key: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("not-yet-valid key ahead of the active one must be skipped")
	}
}

func TestActiveEd25519Key_SkipsOffsetLessBoundThenSelectsActive(t *testing.T) {
	t.Parallel()
	pub, active := activeWindowJWK("live")
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(naiveBoundsJWK("naive"), active), wbaAnchor)
	if err != nil {
		t.Fatalf("ActiveEd25519Key: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("a key with offset-less window bounds must be skipped as inactive")
	}
}

func TestActiveEd25519Key_OffsetLessBoundOnlyNoneQualifies(t *testing.T) {
	t.Parallel()
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(naiveBoundsJWK("naive")), wbaAnchor)
	if got != nil {
		t.Fatal("expected a nil key when the only member has offset-less bounds")
	}
	if !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired, got %v", err)
	}
}

func TestActiveEd25519Key_SkipsMalformedAndContinues(t *testing.T) {
	t.Parallel()
	good31 := base64.RawURLEncoding.EncodeToString(make([]byte, 31)) // decodes to 31 bytes
	cases := []struct {
		name   string
		mutate func(*rampv1.JsonWebKey)
	}{
		{"non-OKP kty", func(k *rampv1.JsonWebKey) { k.Kty = "RSA" }},
		{"wrong crv", func(k *rampv1.JsonWebKey) { k.Crv = "P-256" }},
		{"undecodable x", func(k *rampv1.JsonWebKey) { k.X = "!!!!" }},
		{"wrong-length x", func(k *rampv1.JsonWebKey) { k.X = good31 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, bad := activeWindowJWK("bad")
			tc.mutate(bad)
			pub, good := activeWindowJWK("good")
			got, err := resolvers.ActiveEd25519Key(wbaDirectory(bad, good), wbaAnchor)
			if err != nil {
				t.Fatalf("ActiveEd25519Key: %v", err)
			}
			if !got.Equal(pub) {
				t.Fatalf("malformed active key (%s) must be skipped; the next valid key wins", tc.name)
			}
		})
	}
}

func tenExpiredFillers() []*rampv1.JsonWebKey {
	fillers := make([]*rampv1.JsonWebKey, 0, 10)
	for i := range 10 {
		fillers = append(fillers, expiredWindowJWK(string(rune('A'+i))))
	}
	return fillers
}

func TestActiveEd25519Key_UnboundedByDefaultReachesHighIndex(t *testing.T) {
	t.Parallel()
	// Ten inactive fillers then a valid active key at position 11 (0-indexed 10).
	// The former default cap of 10 would have hidden it; the UNBOUNDED default now
	// reaches it — the DoS-by-directory-padding footgun is gone.
	pub, target := activeWindowJWK("target")
	dir := wbaDirectory(append(tenExpiredFillers(), target)...)

	got, err := resolvers.ActiveEd25519Key(dir, wbaAnchor)
	if err != nil {
		t.Fatalf("the unbounded default must reach index 10: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("a valid key at index 10 must be selected by the unbounded default")
	}

	// An explicit bound large enough still reaches it.
	got, err = resolvers.ActiveEd25519Key(dir, wbaAnchor, resolvers.ActiveKeyScanOptions{MaxScan: intp(11)})
	if err != nil {
		t.Fatalf("an explicit max_scan of 11 must reach index 10: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("with an explicit max_scan of 11 the index-10 key must be selected")
	}
}

func TestActiveEd25519Key_ExplicitBoundExhaustionReturnsNoneAndLogs(t *testing.T) {
	t.Parallel()
	// An explicit max_scan of 10 is exhausted over the 10 expired fillers before the
	// index-10 key: none is selected AND the exhaustion is logged (a valid key beyond
	// the cap is unreachable) — never silently indistinguishable from a genuine miss.
	_, target := activeWindowJWK("target")
	dir := wbaDirectory(append(tenExpiredFillers(), target)...)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	got, err := resolvers.ActiveEd25519Key(dir, wbaAnchor,
		resolvers.ActiveKeyScanOptions{MaxScan: intp(10), Logger: logger})
	if got != nil {
		t.Fatal("an exhausted explicit bound must return a nil key")
	}
	// The 10 fillers are well-formed candidates (out of window), so the sentinel is
	// ErrKeyExpired, not ErrUnknownKey.
	if !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired on bounded exhaustion, got %v", err)
	}
	if !strings.Contains(buf.String(), "max_scan") {
		t.Fatalf("expected a bounded-exhaustion warning to be logged, got %q", buf.String())
	}
}

func TestActiveEd25519Key_NegativeBoundScansNone(t *testing.T) {
	t.Parallel()
	// A negative max_scan clamps to zero (scan none): no key is examined even though
	// one is active. Parity with py max(0, n) / ts Math.max(0, n).
	_, active := activeWindowJWK("present")
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(active), wbaAnchor,
		resolvers.ActiveKeyScanOptions{MaxScan: intp(-1)})
	if got != nil {
		t.Fatal("a negative max_scan must scan none → nil key")
	}
	// Nothing was examined, so there is no candidate → the ErrUnknownKey sentinel.
	if !errors.Is(err, resolvers.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey when the bound scans no candidate, got %v", err)
	}
}

func TestActiveEd25519Key_MixedCaseKtyCrvAccepted(t *testing.T) {
	t.Parallel()
	// Case-insensitive kty/crv is a DELIBERATE lenient SDK convention (RFC 7517/8037
	// specify exact-case OKP / Ed25519). A window-active key with mixed-case kty/crv
	// is accepted and selected — locked identically across the three SDKs.
	pub, k := activeWindowJWK("mixed")
	k.Kty = "oKp"
	k.Crv = "ed25519"
	got, err := resolvers.ActiveEd25519Key(wbaDirectory(k), wbaAnchor)
	if err != nil {
		t.Fatalf("mixed-case kty/crv must be accepted: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("a window-active key with mixed-case kty/crv must be selected")
	}
}

func TestActiveEd25519Key_NoneQualifies(t *testing.T) {
	t.Parallel()
	// The not-found sentinel splits like WBAKeyResolver.Resolve: no well-formed
	// candidate → ErrUnknownKey; a well-formed candidate that is merely out of window
	// → ErrKeyExpired. A nil directory is guarded (ErrUnknownKey, never a panic).
	for _, tc := range []struct {
		name    string
		dir     *rampv1.WBAFile
		wantErr error
	}{
		{"empty", wbaDirectory(), resolvers.ErrUnknownKey},
		{"nil", nil, resolvers.ErrUnknownKey},
		{"all-inactive", wbaDirectory(expiredWindowJWK("x"), futureWindowJWK("y")), resolvers.ErrKeyExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolvers.ActiveEd25519Key(tc.dir, wbaAnchor)
			if got != nil {
				t.Fatal("expected a nil key when none qualifies")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// ── ActiveEd25519KeyWithExpiry — the key + not_after variant ─────────────────

func TestActiveEd25519KeyWithExpiry_ReturnsKeyAndNotAfter(t *testing.T) {
	t.Parallel()
	pub1, k1 := activeWindowJWK("a1")
	_, k2 := activeWindowJWK("a2")
	got, notAfter, err := resolvers.ActiveEd25519KeyWithExpiry(wbaDirectory(k1, k2), wbaAnchor)
	if err != nil {
		t.Fatalf("ActiveEd25519KeyWithExpiry: %v", err)
	}
	if !got.Equal(pub1) {
		t.Fatal("expected the FIRST active key in document order")
	}
	want := wbaAnchor.Add(time.Hour) // activeWindowJWK's not_after
	if !notAfter.Equal(want) {
		t.Fatalf("not_after = %v, want %v", notAfter, want)
	}
}

func TestActiveEd25519KeyWithExpiry_SkipsInactiveAndReturnsNextNotAfter(t *testing.T) {
	t.Parallel()
	// A retired and a not-yet-valid key are skipped; the returned not_after is the
	// NEXT (selected) active key's — a long window, distinct from the skipped bounds.
	pub, selected := longWindowJWK("live")
	dir := wbaDirectory(expiredWindowJWK("dead"), futureWindowJWK("early"), selected)
	got, notAfter, err := resolvers.ActiveEd25519KeyWithExpiry(dir, wbaAnchor)
	if err != nil {
		t.Fatalf("ActiveEd25519KeyWithExpiry: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("inactive keys ahead of the active one must be skipped")
	}
	want := wbaAnchor.Add(1000 * time.Hour) // longWindowJWK's not_after
	if !notAfter.Equal(want) {
		t.Fatalf("not_after = %v, want %v", notAfter, want)
	}
}

func TestActiveEd25519KeyWithExpiry_NoneQualifies(t *testing.T) {
	t.Parallel()
	// No qualifying key → (nil, zero time, ErrKeyExpired), the not-found sentinel.
	got, notAfter, err := resolvers.ActiveEd25519KeyWithExpiry(
		wbaDirectory(expiredWindowJWK("x"), futureWindowJWK("y")), wbaAnchor)
	if got != nil {
		t.Fatal("expected a nil key when none qualifies")
	}
	if !notAfter.IsZero() {
		t.Fatalf("expected a zero not_after when none qualifies, got %v", notAfter)
	}
	if !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired, got %v", err)
	}
}

func TestActiveEd25519KeyWithExpiry_AgreesWithPlainSelector(t *testing.T) {
	t.Parallel()
	// Regression: both faces select the SAME key. The with-expiry variant only
	// adds not_after; it never changes the selection.
	_, selected := longWindowJWK("live")
	dir := wbaDirectory(expiredWindowJWK("dead"), selected)
	plain, err1 := resolvers.ActiveEd25519Key(dir, wbaAnchor)
	withExp, _, err2 := resolvers.ActiveEd25519KeyWithExpiry(dir, wbaAnchor)
	if err1 != nil || err2 != nil {
		t.Fatalf("selection errored: plain=%v withExpiry=%v", err1, err2)
	}
	if !plain.Equal(withExp) {
		t.Fatal("both faces must agree on the selected key")
	}
}

// ── Revocation-aware faces — ActiveEd25519Key(WithExpiry)Screened ─────────────

func TestActiveEd25519KeyScreened_SkipsRevokedThenSelectsNext(t *testing.T) {
	t.Parallel()
	// A window-active key whose thumbprint is revoked must be skipped even though it
	// is otherwise selectable; the next active, non-revoked key wins. This is the
	// emergency-revocation guard the bare selector deliberately omits.
	pub1, k1 := activeWindowJWK("rev-1")
	pub2, k2 := activeWindowJWK("rev-2")
	tp1 := mustThumbprint(t, pub1)
	got, err := resolvers.ActiveEd25519KeyScreened(wbaDirectory(k1, k2), wbaAnchor,
		func(tp string) bool { return tp == tp1 })
	if err != nil {
		t.Fatalf("ActiveEd25519KeyScreened: %v", err)
	}
	if !got.Equal(pub2) {
		t.Fatal("a revoked window-active key must be skipped for the next active one")
	}
}

func TestActiveEd25519KeyScreened_OnlyKeyRevokedNone(t *testing.T) {
	t.Parallel()
	pub1, k1 := activeWindowJWK("rev-only")
	tp1 := mustThumbprint(t, pub1)
	got, err := resolvers.ActiveEd25519KeyScreened(wbaDirectory(k1), wbaAnchor,
		func(tp string) bool { return tp == tp1 })
	if got != nil {
		t.Fatal("expected a nil key when the only active key is revoked")
	}
	if !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired, got %v", err)
	}
}

func TestActiveEd25519KeyScreened_NilPredicateEqualsBare(t *testing.T) {
	t.Parallel()
	// A nil predicate screens nothing — the screened face degrades exactly to the
	// bare selector (which is why nil is unsafe on a verification path).
	pub1, k1 := activeWindowJWK("nil-pred")
	got, err := resolvers.ActiveEd25519KeyScreened(wbaDirectory(k1), wbaAnchor, nil)
	if err != nil {
		t.Fatalf("ActiveEd25519KeyScreened(nil): %v", err)
	}
	if !got.Equal(pub1) {
		t.Fatal("a nil revoked predicate must select exactly what the bare face does")
	}
}

func TestActiveEd25519KeyWithExpiryScreened_SkipsRevokedReturnsNextNotAfter(t *testing.T) {
	t.Parallel()
	// The revoked first key is skipped; the returned not_after is the NEXT
	// (selected) key's — a long window, distinct from the skipped key's bound.
	pub1, k1 := activeWindowJWK("we-rev")
	pub2, k2 := longWindowJWK("we-live")
	tp1 := mustThumbprint(t, pub1)
	got, notAfter, err := resolvers.ActiveEd25519KeyWithExpiryScreened(
		wbaDirectory(k1, k2), wbaAnchor, func(tp string) bool { return tp == tp1 })
	if err != nil {
		t.Fatalf("ActiveEd25519KeyWithExpiryScreened: %v", err)
	}
	if !got.Equal(pub2) {
		t.Fatal("revoked key ahead of the active one must be skipped")
	}
	if want := wbaAnchor.Add(1000 * time.Hour); !notAfter.Equal(want) {
		t.Fatalf("not_after = %v, want %v", notAfter, want)
	}
}
