package helpers_test

// wbakeyresolver_test.go — TDD red for WBAKeyResolver (sdk/go WBA directory
// resolution, revocation poller, ErrKeyRevoked/ErrKeyExpired,
// host-anchored revocation_url). All 14 tests drive through Resolve(ctx, keyID).
//
// Test-local fixtures (newWBAOrigin, newSigningKey, marshalWBA,
// marshalRevocation, pollClock, pollSignals) are defined at the bottom of this
// file — no shared testutil package.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// wbaAnchor is the reference instant all tests use, chosen well within the
// validity windows emitted by newSigningKey.
var wbaAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// wbaRevocationPath is the conventional path the test origin serves revocations.
const wbaRevocationPath = "/.well-known/ramp-key-revocations.json"

// wbaDirPath is the WBA directory well-known path.
const wbaDirPath = "/.well-known/http-message-signatures-directory"

// ── Test 1 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_Active verifies the happy path: the WBA directory is
// fetched, the key is identified by its RFC 7638 thumbprint, it is within its
// validity window, and Resolve returns the correct ed25519.PublicKey.
func TestWBAKeyResolver_Active(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(jwk))

	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)

	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})
	got, err := r.Resolve(ctx, tp)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Equal(priv.Public()) {
		t.Fatal("resolved key mismatch")
	}
}

// ── Test 2 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_ErrKeyExpired verifies that a key outside its validity
// window returns ErrKeyExpired from Resolve.
func TestWBAKeyResolver_ErrKeyExpired(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-2*time.Hour), wbaAnchor.Add(-time.Hour))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(jwk))

	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)

	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})
	_, err := r.Resolve(ctx, tp)
	if !errors.Is(err, helpers.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired, got %v", err)
	}
}

// ── Test 3 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_ErrUnknownKey verifies that a thumbprint absent from the
// directory returns ErrUnknownKey (the SDK sentinel name, not the app's
// ErrKeyUnknown).
func TestWBAKeyResolver_ErrUnknownKey(t *testing.T) {
	t.Parallel()
	_, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(jwk))

	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})
	_, err := r.Resolve(ctx, "absent-thumbprint")
	if !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

// ── Test 4 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_ErrKeyRevoked verifies that a thumbprint present in the
// revocation snapshot returns ErrKeyRevoked.
func TestWBAKeyResolver_ErrKeyRevoked(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBAWithRevocation(jwk, origin.revocationURL()))
	origin.setRevocation(marshalRevocation(wbaAnchor, tp))

	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})
	_, err := r.Resolve(ctx, tp)
	if !errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatalf("want ErrKeyRevoked, got %v", err)
	}
}

// ── Test 5 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_RotationSelfHeal verifies that when a key is added to the
// directory after the first cache prime, a single sync-refresh finds it.
func TestWBAKeyResolver_RotationSelfHeal(t *testing.T) {
	t.Parallel()
	_, k1 := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	priv2, k2 := newSigningKey("k2", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	tp2 := mustThumbprint(t, priv2.Public().(ed25519.PublicKey))

	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(k1)) // prime: only k1

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		TTL:    time.Hour,
		Now:    func() time.Time { return now },
	})

	// Prime the cache with k1-only (same seed ⇒ same key as k1 above).
	k1priv, _ := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	tp1 := mustThumbprint(t, k1priv.Public().(ed25519.PublicKey))
	if _, err := r.Resolve(ctx, tp1); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Rotate in k2; cache still holds k1-only, so the lookup must self-heal.
	origin.setWBA(marshalWBA(k1, k2))
	got, err := r.Resolve(ctx, tp2)
	if err != nil {
		t.Fatalf("self-heal lookup of rotated-in k2: %v", err)
	}
	if !got.Equal(priv2.Public()) {
		t.Fatal("resolved key mismatch after self-heal")
	}
}

// ── Test 6 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_RevocationRollbackIgnored verifies that a revocation
// snapshot with a strictly older as_of than the one already held is ignored —
// the monotonic guard must not un-revoke a key.
func TestWBAKeyResolver_RevocationRollbackIgnored(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBAWithRevocation(jwk, origin.revocationURL()))
	// Newer snapshot revokes the key.
	origin.setRevocation(marshalRevocation(wbaAnchor, tp))

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		TTL:    time.Hour,
		Now:    func() time.Time { return now },
	})
	if _, err := r.Resolve(ctx, tp); !errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatalf("precondition: want ErrKeyRevoked, got %v", err)
	}
	// Publish a rolled-back (older as_of) snapshot that does not revoke the key.
	origin.setRevocation(marshalRevocation(wbaAnchor.Add(-time.Hour)))
	// Expire the TTL so the directory is re-fetched and revocation is refreshed.
	now = wbaAnchor.Add(2 * time.Hour)
	if _, err := r.Resolve(ctx, tp); !errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatalf("rollback list (older as_of) must not un-revoke; got %v", err)
	}
}

// ── Test 7 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_RevocationForwardProgressApplied verifies that a snapshot
// with a strictly newer as_of that does NOT include the thumbprint un-revokes
// the key — forward progress on the as_of must apply.
func TestWBAKeyResolver_RevocationForwardProgressApplied(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBAWithRevocation(jwk, origin.revocationURL()))
	origin.setRevocation(marshalRevocation(wbaAnchor, tp))

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		TTL:    time.Hour,
		Now:    func() time.Time { return now },
	})
	if _, err := r.Resolve(ctx, tp); !errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatalf("precondition: want ErrKeyRevoked, got %v", err)
	}
	// Strictly-newer snapshot that drops the thumbprint legitimately un-revokes.
	origin.setRevocation(marshalRevocation(wbaAnchor.Add(time.Hour)))
	now = wbaAnchor.Add(2 * time.Hour) // expire TTL
	got, err := r.Resolve(ctx, tp)
	if err != nil {
		t.Fatalf("newer empty snapshot should un-revoke; got %v", err)
	}
	if !got.Equal(priv.Public()) {
		t.Fatal("resolved key mismatch after un-revocation")
	}
}

// ── Test 8 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_FirstPollFarFutureAsOfClamp verifies the RAMP-24 AC: a
// far-future as_of on the first revocation poll is clamped to now+skew so that
// a later, honest revocation snapshot still applies rather than being frozen
// out by the monotonic guard.
func TestWBAKeyResolver_FirstPollFarFutureAsOfClamp(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBAWithRevocation(jwk, origin.revocationURL()))
	// First snapshot: far-future as_of, nothing revoked.
	origin.setRevocation(marshalRevocation(wbaAnchor.Add(10000 * time.Hour)))

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		TTL:    time.Hour,
		Now:    func() time.Time { return now },
	})
	// Prime: far-future as_of must be clamped, not stored at the far-future value.
	if _, err := r.Resolve(ctx, tp); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// Advance past TTL; publish a real revocation snapshot.
	now = wbaAnchor.Add(2 * time.Hour)
	origin.setRevocation(marshalRevocation(wbaAnchor.Add(2*time.Hour), tp))
	if _, err := r.Resolve(ctx, tp); !errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatalf("far-future first as_of must not freeze later revocations; got %v", err)
	}
}

// ── Test 9 ─────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_RemovalIsNotRevocation verifies the invariant that a key
// dropped from the directory resolves to ErrUnknownKey (not ErrKeyRevoked),
// so a composite resolver falls through to its next delegate.
func TestWBAKeyResolver_RemovalIsNotRevocation(t *testing.T) {
	t.Parallel()
	priv1, k1 := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tp1 := mustThumbprint(t, priv1.Public().(ed25519.PublicKey))
	_, k2 := newSigningKey("k2", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(k1))

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		TTL:    time.Hour,
		Now:    func() time.Time { return now },
	})
	if _, err := r.Resolve(ctx, tp1); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// Remove k1; directory now carries only k2.
	origin.setWBA(marshalWBA(k2))
	now = wbaAnchor.Add(2 * time.Hour) // expire TTL → re-fetch k1-less directory
	_, err := r.Resolve(ctx, tp1)
	if !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("removed key must be ErrUnknownKey, got %v", err)
	}
	if errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatal("removal must not be reported as revocation")
	}
}

// ── Test 10 ────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_RevocationURLHostNotAnchored verifies that the poller
// refuses to follow a revocation_url whose host is not the directory host (nor
// a subdomain of it), so the key stays valid and the cross-host target is
// never polled.
func TestWBAKeyResolver_RevocationURLHostNotAnchored(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))

	// An evil origin that would revoke the key if polled.
	evilOrigin := newWBAOrigin(nil)
	defer evilOrigin.close()
	evilOrigin.setRevocation(marshalRevocation(wbaAnchor, tp))

	// Directory host points revocation_url at evilOrigin (different host).
	dirOrigin := newWBAOrigin(nil)
	defer dirOrigin.close()
	dirOrigin.setWBA(marshalWBAWithRevocation(jwk, evilOrigin.revocationURL()))

	ctx := helpers.WithSignatureAgent(context.Background(), dirOrigin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   dirOrigin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})
	got, err := r.Resolve(ctx, tp)
	if err != nil {
		t.Fatalf("cross-host revocation_url must be skipped; key stays valid: %v", err)
	}
	if got == nil {
		t.Fatal("expected the un-revoked key to resolve")
	}
}

// ── Test 11 ────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_Run_PollerAppliesRevocation verifies that the background
// poller (Run) picks up a newly-published revocation without a directory
// re-fetch. The test uses the OnPollArmed/OnPollCycle determinism seams and a
// test-local pollClock to advance time without sleeping.
func TestWBAKeyResolver_Run_PollerAppliesRevocation(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBAWithRevocation(jwk, origin.revocationURL()))
	origin.setRevocation(marshalRevocation(wbaAnchor.Add(-time.Hour))) // nothing revoked yet

	const pollInterval = 10 * time.Second
	clk := newPollClock(wbaAnchor)
	poll := newPollSignals()

	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme:       "http",
		HTTP:         origin.Client(),
		TTL:          100 * time.Hour, // never expires during the test → isolate poller
		PollInterval: pollInterval,
		Now:          clk.Now,
		After:        clk.After,
		OnPollArmed:  poll.armed,
		OnPollCycle:  poll.cycled,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	ctxDir := helpers.WithSignatureAgent(ctx, origin.url)

	// Prime the directory and an empty revocation snapshot.
	if _, err := r.Resolve(ctxDir, tp); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Publish a newer snapshot revoking the key, then cross one poll boundary
	// via the determinism seams: wait for armed, advance past interval, wait
	// for cycle — no sleeps, no wall-clock deadline.
	origin.setRevocation(marshalRevocation(wbaAnchor, tp))
	poll.crossOne(t, clk, 2*pollInterval)

	if _, err := r.Resolve(ctxDir, tp); !errors.Is(err, helpers.ErrKeyRevoked) {
		t.Fatalf("running poller did not apply the revocation; got %v", err)
	}
}

// ── Test 12 ────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_NoSignatureAgent verifies that an empty Signature-Agent
// in ctx (no directory URL) returns ErrUnknownKey.
func TestWBAKeyResolver_NoSignatureAgent(t *testing.T) {
	t.Parallel()
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		Now:    func() time.Time { return wbaAnchor },
	})
	// Context carries no Signature-Agent — SignatureAgentFromContext returns "".
	_, err := r.Resolve(context.Background(), "any-thumbprint")
	if !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey for empty Signature-Agent, got %v", err)
	}
}

// ── Test 13 ────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_TTLCacheHit verifies that within the cache TTL a failing
// origin does not prevent successful resolution (the cached directory is used).
func TestWBAKeyResolver_TTLCacheHit(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(10*time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(jwk))

	now := wbaAnchor
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		TTL:    time.Hour,
		Now:    func() time.Time { return now },
	})

	if _, err := r.Resolve(ctx, tp); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	// Origin now fails; a cache hit must still succeed within TTL.
	origin.setWBAStatus(http.StatusInternalServerError)
	if _, err := r.Resolve(ctx, tp); err != nil {
		t.Fatalf("cached lookup should not hit origin: %v", err)
	}
}

// ── Test 14 ────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_FetchError verifies that a fetch/500 failure returns an
// error wrapping ErrDirectoryUnavailable that is NOT errors.Is(ErrUnknownKey).
//
// This distinction is load-bearing: the broker composite fails closed on any
// non-ErrUnknownKey error; if a well-known outage returned ErrUnknownKey the
// composite would fall through to the next delegate, silently enabling a
// possibly-revoked key.
func TestWBAKeyResolver_FetchError(t *testing.T) {
	t.Parallel()
	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBAStatus(http.StatusInternalServerError) // force 500

	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})
	_, err := r.Resolve(ctx, "any-thumbprint")
	if err == nil {
		t.Fatal("want error from 500 origin, got nil")
	}
	if !errors.Is(err, helpers.ErrDirectoryUnavailable) {
		t.Fatalf("want error wrapping ErrDirectoryUnavailable, got %v", err)
	}
	// CRITICAL: fetch failure MUST NOT be confused with an unknown key; the
	// composite resolver must halt (fail closed), not fall through.
	if errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatal("fetch/parse failure must be errors.Is-DISTINCT from ErrUnknownKey to preserve broker composite fail-closed semantics")
	}
}

// ── Test 15 ────────────────────────────────────────────────────────────────

// TestWBAKeyResolver_Revoked verifies the revocation-set-membership accessor:
// after the snapshot is primed, Revoked reports true for a thumbprint present in
// the revocation list even when the directory never listed it (directory-absent-
// but-revoked), false for a directory-listed key that is not revoked, and false
// for a thumbprint unknown to both. The accessor is INDEPENDENT of directory
// membership — it is the fail-closed hook a composite resolver uses to reject a
// static-bootstrap-only key the broker has revoked.
func TestWBAKeyResolver_Revoked(t *testing.T) {
	t.Parallel()
	presentPriv, presentJWK := newSigningKey("present.v1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tpPresent := mustThumbprint(t, presentPriv.Public().(ed25519.PublicKey))
	absentPriv, _ := newSigningKey("absent-revoked.v1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tpAbsentRevoked := mustThumbprint(t, absentPriv.Public().(ed25519.PublicKey))
	unknownPriv, _ := newSigningKey("unknown.v1", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(1000*time.Hour))
	tpUnknown := mustThumbprint(t, unknownPriv.Public().(ed25519.PublicKey))

	origin := newWBAOrigin(nil)
	defer origin.close()
	// The directory lists only the present key; the revocation snapshot revokes
	// the directory-ABSENT thumbprint.
	origin.setWBA(marshalWBAWithRevocation(presentJWK, origin.revocationURL()))
	origin.setRevocation(marshalRevocation(wbaAnchor, tpAbsentRevoked))

	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
	r := helpers.NewWBAKeyResolver(helpers.WBAKeyResolverOptions{
		Scheme: "http",
		HTTP:   origin.Client(),
		Now:    func() time.Time { return wbaAnchor },
	})

	// Before any fetch the snapshot is unavailable → membership is false.
	if r.Revoked(tpAbsentRevoked) {
		t.Fatal("Revoked before priming must be false (no snapshot)")
	}
	// Prime the snapshot by resolving the directory-present key.
	if _, err := r.Resolve(ctx, tpPresent); err != nil {
		t.Fatalf("prime resolve: %v", err)
	}

	if !r.Revoked(tpAbsentRevoked) {
		t.Fatal("directory-absent-but-revoked thumbprint must report Revoked=true")
	}
	if r.Revoked(tpPresent) {
		t.Fatal("directory-present, not-revoked thumbprint must report Revoked=false")
	}
	if r.Revoked(tpUnknown) {
		t.Fatal("thumbprint unknown to directory and revocation must report Revoked=false")
	}
	if r.Revoked("") {
		t.Fatal("empty keyID must report Revoked=false")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// Test-local fixtures
// ════════════════════════════════════════════════════════════════════════════

// newSigningKey returns a deterministic Ed25519 private key plus its proto JWK,
// valid over [notBefore, notAfter). The key bytes are derived from the seed
// string so the same seed always yields the same key across test runs. Keys
// carry no kid — they are identified by RFC 7638 thumbprint.
func newSigningKey(seed string, notBefore, notAfter time.Time) (ed25519.PrivateKey, *rampv1.JsonWebKey) {
	raw := make([]byte, ed25519.SeedSize)
	copy(raw, []byte(seed))
	priv := ed25519.NewKeyFromSeed(raw)
	pub, _ := priv.Public().(ed25519.PublicKey)
	jwk := &rampv1.JsonWebKey{
		Kty:       "OKP",
		Crv:       "Ed25519",
		Use:       "sig",
		Alg:       "EdDSA",
		X:         base64.RawURLEncoding.EncodeToString(pub),
		NotBefore: notBefore.UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
	}
	return priv, jwk
}

// mustThumbprint returns the RFC 7638 thumbprint of pub, failing the test on
// error.
func mustThumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// marshalWBA serializes a WBAFile (carrying keys) as canonical protojson.
func marshalWBA(keys ...*rampv1.JsonWebKey) []byte {
	f := &rampv1.WBAFile{Keys: keys}
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(f)
	return raw
}

// marshalWBAWithRevocation serializes a WBAFile carrying keys and a
// revocation_url pointing at revURL.
func marshalWBAWithRevocation(jwk *rampv1.JsonWebKey, revURL string) []byte {
	f := &rampv1.WBAFile{
		Keys:          []*rampv1.JsonWebKey{jwk},
		RevocationUrl: &revURL,
	}
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(f)
	return raw
}

// marshalRevocation serializes a KeyRevocationList as canonical protojson.
func marshalRevocation(asOf time.Time, revoked ...string) []byte {
	list := &rampv1.KeyRevocationList{
		AsOf:    timestamppb.New(asOf.UTC()),
		Revoked: revoked,
	}
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(list)
	return raw
}

// ── wbaOrigin ──────────────────────────────────────────────────────────────

// wbaOrigin is a minimal httptest server serving a WBA directory and
// revocation list at their conventional paths.
type wbaOrigin struct {
	*httptest.Server
	url       string
	wbaDoc    atomic.Pointer[[]byte]
	wbaStatus atomic.Int32
	revDoc    atomic.Pointer[[]byte]
}

func newWBAOrigin(_ []byte) *wbaOrigin {
	o := &wbaOrigin{}
	mux := http.NewServeMux()
	mux.HandleFunc(wbaDirPath, o.serveWBA)
	mux.HandleFunc(wbaRevocationPath, o.serveRevocation)
	o.Server = httptest.NewServer(mux)
	o.url = o.Server.URL
	return o
}

func (o *wbaOrigin) close()                 { o.Server.Close() }
func (o *wbaOrigin) setWBA(b []byte)        { o.wbaDoc.Store(&b) }
func (o *wbaOrigin) setRevocation(b []byte) { o.revDoc.Store(&b) }
func (o *wbaOrigin) revocationURL() string  { return o.url + wbaRevocationPath }
func (o *wbaOrigin) setWBAStatus(code int) {
	o.wbaStatus.Store(int32(code)) //nolint:gosec // small status code
}

func (o *wbaOrigin) serveWBA(w http.ResponseWriter, _ *http.Request) {
	if code := o.wbaStatus.Load(); code != 0 {
		w.WriteHeader(int(code))
		return
	}
	p := o.wbaDoc.Load()
	if p == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = w.Write(*p)
}

func (o *wbaOrigin) serveRevocation(w http.ResponseWriter, _ *http.Request) {
	p := o.revDoc.Load()
	if p == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(*p)
}

// ── pollClock ──────────────────────────────────────────────────────────────

// pollClock is a test-local deterministic clock: Now returns the mutable
// current instant; After returns a channel that fires when Advance moves the
// clock to or past the scheduled instant. It provides the same seam as the
// app's DeterministicClock, using the func() time.Time / func(time.Duration)
// <-chan time.Time API the SDK expects.
type pollClock struct {
	mu      sync.Mutex
	now     time.Time
	pending []clockTimer
}

type clockTimer struct {
	fireAt time.Time
	ch     chan time.Time
}

func newPollClock(start time.Time) *pollClock {
	return &pollClock{now: start.UTC()}
}

func (c *pollClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *pollClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if d <= 0 {
		ch <- c.now
		close(ch)
		return ch
	}
	c.pending = append(c.pending, clockTimer{fireAt: c.now.Add(d), ch: ch})
	return ch
}

func (c *pollClock) Advance(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	due := c.now
	remaining := c.pending[:0]
	for _, t := range c.pending {
		if !t.fireAt.After(due) {
			t.ch <- due
			close(t.ch)
			continue
		}
		remaining = append(remaining, t)
	}
	c.pending = remaining
	c.mu.Unlock()
}

// ── pollSignals ────────────────────────────────────────────────────────────

// pollSignals bridges the WBAKeyResolver's OnPollArmed / OnPollCycle
// determinism seams to a deterministic-clock test, letting it cross exactly
// one revocation-poll boundary without sleeping. Wire armed and cycled into
// WBAKeyResolverOptions, then call crossOne.
type pollSignals struct {
	armedCh  chan struct{}
	cycledCh chan struct{}
}

func newPollSignals() *pollSignals {
	return &pollSignals{
		armedCh:  make(chan struct{}, 1),
		cycledCh: make(chan struct{}, 1),
	}
}

func (p *pollSignals) armed()  { nonBlockingSendW(p.armedCh) }
func (p *pollSignals) cycled() { nonBlockingSendW(p.cycledCh) }

// crossOne waits for the poller to arm its tick timer, advances clk by adv to
// fire it, then waits for the resulting refresh to complete. adv MUST exceed
// the jittered poll interval. No sleeps.
func (p *pollSignals) crossOne(t *testing.T, clk *pollClock, adv time.Duration) {
	t.Helper()
	<-p.armedCh
	clk.Advance(adv)
	<-p.cycledCh
}

func nonBlockingSendW(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
