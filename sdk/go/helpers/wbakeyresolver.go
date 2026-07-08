package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// WBA-resolution sentinels. AUTHORITY CONTRACT: the resolver surfaces these
// verdicts RAW and makes no security decision on the caller's behalf. Whether a
// revoked/expired/unavailable verdict is authoritative (halt a composite
// resolver, fail closed) or maskable into ErrUnknownKey (fall through to the
// next delegate, e.g. a lazy-registration path) is the CALLER's decision —
// composite ordering and any masking live in the application.
var (
	// ErrKeyRevoked signals the thumbprint is present in the directory host's
	// current revocation snapshot.
	ErrKeyRevoked = errors.New("helpers: key revoked")
	// ErrKeyExpired signals the key exists but is outside its
	// [not_before, not_after) validity window.
	ErrKeyExpired = errors.New("helpers: key outside validity window")
	// ErrDirectoryUnavailable signals the WBA directory could not be fetched or
	// parsed. It is deliberately errors.Is-DISTINCT from ErrUnknownKey: a
	// fail-closed composite must be able to halt on a directory outage rather
	// than fall through as if the key were merely unknown.
	ErrDirectoryUnavailable = errors.New("helpers: WBA directory unavailable")
)

// WBADirectoryPath is the well-known path a WBA identity directory is served
// at (Web Bot Auth; the identity half of the RAMP-24 split — the commercial
// overlay stays in /.well-known/ramp.json).
const WBADirectoryPath = "/.well-known/http-message-signatures-directory"

// Defaults mirror the platform reference implementation: the directory itself
// rotates slowly (keys carry validity windows), so an hour TTL is fine; the
// revocation snapshot bounds emergency-revocation latency, so it is polled on
// the 300s cadence (±10% jitter).
const (
	defaultWBADirectoryTTL = time.Hour
	defaultWBAPollInterval = 300 * time.Second

	// wbaRevocationAsOfSkew bounds how far into the future a revocation
	// snapshot's as_of may sit relative to the verifier's clock before it is
	// clamped. A compromised or misconfigured origin cannot then stamp a
	// far-future as_of that would freeze every subsequent (legitimately earlier)
	// snapshot under the monotonic guard — the first-poll integrity bug.
	wbaRevocationAsOfSkew = 300 * time.Second
)

// WBAKeyResolverOptions tune a WBAKeyResolver. Zero values are safe defaults.
type WBAKeyResolverOptions struct {
	// HTTP overrides the client used for directory and revocation GETs (nil →
	// http.DefaultClient). SSRF CONTRACT: when the directory URL is derived from
	// request input (the Signature-Agent header), the caller MUST inject a
	// client whose dialer rejects private/link-local targets — the SDK exposes
	// the injection point, the guard itself stays with the application.
	HTTP *http.Client
	// TTL bounds how long a fetched directory is reused (≤0 → 1 hour).
	TTL time.Duration
	// PollInterval is the base revocation-poll cadence for Run (≤0 → 300s).
	PollInterval time.Duration
	// Now overrides the clock for TTL and validity-window comparisons (nil →
	// time.Now). Tests inject.
	Now func() time.Time
	// After overrides the poll-tick timer source (nil → time.After). Tests
	// inject a deterministic clock.
	After func(time.Duration) <-chan time.Time
	// Scheme is applied when the Signature-Agent value carries no scheme
	// (empty → "https"). Tests inject "http" to drive an httptest server.
	Scheme string
	// Logger receives best-effort revocation-refresh diagnostics (nil →
	// slog.Default()).
	Logger *slog.Logger
	// OnPollArmed and OnPollCycle are optional determinism seams for the Run
	// poller (nil in production). OnPollArmed fires each time the poller has
	// registered its next tick timer and is about to block; OnPollCycle fires
	// after each completed refresh. A deterministic-clock test waits for
	// OnPollArmed, advances the clock to fire the tick, then waits for
	// OnPollCycle — proving a poll boundary was crossed without sleeping.
	OnPollArmed func()
	OnPollCycle func()
}

// WBAKeyResolver resolves signing keys from WBA identity directories
// (WBADirectoryPath), matching by RFC 7638 thumbprint (the RFC 9421 keyid) —
// never by kid — and enforcing each key's [not_before, not_after) validity
// window plus the host's revocation snapshot. The directory host comes from the
// verified request's Signature-Agent value, threaded into ctx by the resolved
// verify entrypoints (SignatureAgentFromContext). Directories are cached per
// host with a TTL; revocation snapshots are primed on directory fetch and kept
// fresh by the Run poller. See the sentinel var block for the authority
// contract: revoked/expired/unavailable verdicts surface raw.
type WBAKeyResolver struct {
	http         *http.Client
	ttl          time.Duration
	pollInterval time.Duration
	now          func() time.Time
	after        func(time.Duration) <-chan time.Time
	scheme       string
	logger       *slog.Logger
	onPollArmed  func()
	onPollCycle  func()

	dirMu    sync.Mutex
	dirCache map[string]wbaDirEntry
	dirBase  map[string]string // host → scheme://host base for poller re-fetch

	revMu   sync.RWMutex
	revoked map[string]wbaRevSet
}

type wbaDirEntry struct {
	file *rampv1.WBAFile
	exp  time.Time
}

type wbaRevSet struct {
	thumbprints map[string]struct{}
	asOf        time.Time
}

// NewWBAKeyResolver constructs a WBAKeyResolver with defaults applied.
func NewWBAKeyResolver(opts WBAKeyResolverOptions) *WBAKeyResolver {
	client := opts.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultWBADirectoryTTL
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = defaultWBAPollInterval
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	after := opts.After
	if after == nil {
		after = time.After
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &WBAKeyResolver{
		http:         client,
		ttl:          ttl,
		pollInterval: interval,
		now:          now,
		after:        after,
		scheme:       scheme,
		logger:       logger,
		onPollArmed:  opts.OnPollArmed,
		onPollCycle:  opts.OnPollCycle,
		dirCache:     map[string]wbaDirEntry{},
		dirBase:      map[string]string{},
		revoked:      map[string]wbaRevSet{},
	}
}

// Resolve implements KeyResolver: keyID is an RFC 7638 thumbprint; the
// directory to resolve it against comes from SignatureAgentFromContext. On an
// unknown thumbprint it performs one bounded directory re-fetch (rotation
// self-heal) before giving up. A thumbprint merely ABSENT from the directory
// (e.g. dropped during rotation) yields ErrUnknownKey, never ErrKeyRevoked:
// removal is not revocation — the authoritative revocation channel is the
// revocation list, so a composite resolver falls through on a removed key.
func (r *WBAKeyResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	dir := SignatureAgentFromContext(ctx)
	if dir == "" || keyID == "" {
		return nil, fmt.Errorf("%w: no signature-agent directory for keyid=%q", ErrUnknownKey, keyID)
	}
	base, host, err := r.directoryBase(dir)
	if err != nil {
		// A malformed Signature-Agent cannot name a directory: the key is
		// unresolvable here, not "the directory is down" — fall-through verdict.
		return nil, fmt.Errorf("%w: unparseable signature-agent %q: %w", ErrUnknownKey, dir, err)
	}
	f, err := r.wbaFile(ctx, base, host)
	if err != nil {
		return nil, err
	}
	key, ok := wbaKeyByThumbprint(f, keyID)
	if !ok {
		if f, err = r.syncRefresh(ctx, base, host); err != nil {
			return nil, err
		}
		if key, ok = wbaKeyByThumbprint(f, keyID); !ok {
			return nil, fmt.Errorf("%w: keyid=%q host=%q", ErrUnknownKey, keyID, host)
		}
	}
	if r.isRevoked(host, keyID) {
		return nil, fmt.Errorf("%w: keyid=%q", ErrKeyRevoked, keyID)
	}
	if !wbaKeyActiveAt(key, r.now()) {
		return nil, fmt.Errorf("%w: keyid=%q", ErrKeyExpired, keyID)
	}
	return wbaPublicKey(key)
}

// Run drives the revocation poller until ctx is cancelled. Each tick refreshes
// every known host's revocation snapshot on a ±10%-jittered PollInterval. The
// caller owns the goroutine: `go r.Run(ctx)`; cancelling ctx is the stop.
func (r *WBAKeyResolver) Run(ctx context.Context) {
	for {
		timer := r.after(r.jitteredInterval())
		wbaNotify(r.onPollArmed)
		select {
		case <-ctx.Done():
			return
		case <-timer:
			r.refreshAllRevocations(ctx)
			wbaNotify(r.onPollCycle)
		}
	}
}

// wbaNotify invokes a determinism-seam hook when set (nil in production).
func wbaNotify(hook func()) {
	if hook != nil {
		hook()
	}
}

// directoryBase normalizes a Signature-Agent value (bare host, host:port, or
// full URL) into a scheme://host base and its host key.
func (r *WBAKeyResolver) directoryBase(ref string) (base, host string, err error) {
	if !strings.Contains(ref, "://") {
		ref = r.scheme + "://" + ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("no host in %q", ref)
	}
	return u.Scheme + "://" + u.Host, u.Host, nil
}

// wbaFile returns host's cached directory when fresh, else fetches, stores, and
// primes its revocation snapshot. The per-call fetch is serialized under dirMu's
// release via syncRefresh; a stale entry never blocks a fresh reader.
func (r *WBAKeyResolver) wbaFile(ctx context.Context, base, host string) (*rampv1.WBAFile, error) {
	r.dirMu.Lock()
	if e, ok := r.dirCache[host]; ok && r.now().Before(e.exp) {
		r.dirMu.Unlock()
		return e.file, nil
	}
	r.dirMu.Unlock()
	return r.syncRefresh(ctx, base, host)
}

// syncRefresh force-fetches host's WBA directory, bypassing the TTL cache, and
// refreshes its revocation snapshot.
func (r *WBAKeyResolver) syncRefresh(ctx context.Context, base, host string) (*rampv1.WBAFile, error) {
	f, err := r.fetchDirectory(ctx, base)
	if err != nil {
		return nil, err
	}
	r.dirMu.Lock()
	r.dirCache[host] = wbaDirEntry{file: f, exp: r.now().Add(r.ttl)}
	r.dirBase[host] = base
	r.dirMu.Unlock()
	r.refreshRevocationFor(ctx, host, f)
	return f, nil
}

// fetchDirectory GETs and decodes the WBA directory at base. Any transport,
// status, or decode failure wraps ErrDirectoryUnavailable — see the sentinel
// contract: a directory outage must stay distinguishable from an unknown key.
func (r *WBAKeyResolver) fetchDirectory(ctx context.Context, base string) (*rampv1.WBAFile, error) {
	raw, err := r.getDoc(ctx, base+WBADirectoryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryUnavailable, err)
	}
	var f rampv1.WBAFile
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrDirectoryUnavailable, err)
	}
	return &f, nil
}

// getDoc GETs a small well-known document, bounding the body read.
func (r *WBAKeyResolver) getDoc(ctx context.Context, docURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	const maxDocBytes = 1 << 20 // 1 MiB — well-known documents are small
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return raw, nil
}

func (r *WBAKeyResolver) isRevoked(host, thumbprint string) bool {
	r.revMu.RLock()
	defer r.revMu.RUnlock()
	set, ok := r.revoked[host]
	if !ok {
		return false
	}
	_, revoked := set.thumbprints[thumbprint]
	return revoked
}

// Revoked reports whether keyID (an RFC 7638 thumbprint) is present in ANY
// host's fetched revocation snapshot, INDEPENDENT of whether that thumbprint
// appears in the corresponding WBA directory. Resolve gates a key only when the
// directory lists it (removal is not revocation); a key resolved from a source
// OTHER than the directory — e.g. a static bootstrap file — is invisible to that
// path, so a composite resolver can still admit a broker-revoked, directory-
// absent thumbprint. Revoked closes that gap: a caller that resolved a key
// elsewhere consults it to fail closed against the revocation channel. It
// returns false when no snapshot has been fetched (the snapshot is unavailable —
// the caller decides whether an unavailable revocation channel is itself
// fail-closed; this accessor reports membership only, never an outage).
func (r *WBAKeyResolver) Revoked(keyID string) bool {
	if keyID == "" {
		return false
	}
	r.revMu.RLock()
	defer r.revMu.RUnlock()
	for _, set := range r.revoked {
		if _, ok := set.thumbprints[keyID]; ok {
			return true
		}
	}
	return false
}

// refreshRevocationFor replaces host's revocation snapshot from f's
// revocation_url. Best-effort: a fetch failure leaves the prior snapshot in
// place and is logged, never propagated (a stale-but-present snapshot is safer
// than dropping revocations on a transient blip).
func (r *WBAKeyResolver) refreshRevocationFor(ctx context.Context, host string, f *rampv1.WBAFile) {
	revURL := f.GetRevocationUrl()
	if revURL == "" {
		return
	}
	// Anchor the revocation_url to the directory host before polling it. A WBA
	// directory that names a revocation_url on a different host would otherwise
	// steer the poller at an arbitrary target every cadence — cross-host polling
	// and SSRF amplification. Only a same-host-or-subdomain revocation_url is
	// fetched; a mismatch is logged and skipped, leaving the prior snapshot.
	if !wbaHostAnchored(host, revURL) {
		r.logger.WarnContext(ctx, "revocation_url host not anchored to directory; skipping poll",
			"host", host, "revocation_url", revURL)
		return
	}
	raw, err := r.getDoc(ctx, revURL)
	if err != nil {
		r.logger.WarnContext(ctx, "revocation refresh failed",
			"host", host, "revocation_url", revURL, "err", err)
		return
	}
	var list rampv1.KeyRevocationList
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &list); err != nil {
		r.logger.WarnContext(ctx, "revocation decode failed",
			"host", host, "revocation_url", revURL, "err", err)
		return
	}
	// Clamp a future as_of to now+skew so a compromised origin cannot seed a
	// far-future baseline that permanently freezes later (legitimately earlier)
	// snapshots under the monotonic guard below — the first-poll integrity bug.
	asOf := list.GetAsOf().AsTime()
	if ceiling := r.now().Add(wbaRevocationAsOfSkew); asOf.After(ceiling) {
		asOf = ceiling
	}
	set := make(map[string]struct{}, len(list.GetRevoked()))
	for _, tp := range list.GetRevoked() {
		set[tp] = struct{}{}
	}
	r.revMu.Lock()
	prev, ok := r.revoked[host]
	// Monotonic guard: a successful fetch whose as_of is not strictly newer than
	// the snapshot already held is a rollback (stale cache, replayed prior
	// snapshot, regressed document) and is ignored — a revoked thumbprint must
	// not be silently un-revoked. The guard fires only once a real snapshot has
	// been seeded; the first seed is always accepted.
	rollback := ok && !asOf.After(prev.asOf)
	if !rollback {
		r.revoked[host] = wbaRevSet{thumbprints: set, asOf: asOf}
	}
	r.revMu.Unlock()
	if rollback {
		r.logger.WarnContext(ctx, "revocation rollback ignored",
			"host", host, "fetched_as_of", asOf, "held_as_of", prev.asOf)
	}
}

func (r *WBAKeyResolver) refreshAllRevocations(ctx context.Context) {
	r.dirMu.Lock()
	entries := make(map[string]*rampv1.WBAFile, len(r.dirCache))
	for host, e := range r.dirCache {
		entries[host] = e.file
	}
	r.dirMu.Unlock()
	for host, f := range entries {
		r.refreshRevocationFor(ctx, host, f)
	}
}

// jitteredInterval returns PollInterval ±10% to avoid synchronized polling.
func (r *WBAKeyResolver) jitteredInterval() time.Duration {
	delta := int64(r.pollInterval) / 10
	if delta <= 0 {
		return r.pollInterval
	}
	//nolint:gosec // G404: poll jitter is not security-sensitive
	jitter := rand.Int64N(2*delta+1) - delta
	return time.Duration(int64(r.pollInterval) + jitter)
}

// wbaKeyByThumbprint returns the key in f whose RFC 7638 thumbprint equals
// thumbprint (the RFC 9421 keyid) and whether it was found. Each key's
// thumbprint is computed locally from its decoded public key; keys with an
// undecodable x are skipped.
func wbaKeyByThumbprint(f *rampv1.WBAFile, thumbprint string) (*rampv1.JsonWebKey, bool) {
	if f == nil || thumbprint == "" {
		return nil, false
	}
	for _, k := range f.GetKeys() {
		pub, err := wbaPublicKey(k)
		if err != nil {
			continue
		}
		tp, err := Thumbprint(pub)
		if err != nil {
			continue
		}
		if tp == thumbprint {
			return k, true
		}
	}
	return nil, false
}

// wbaPublicKey decodes k's Ed25519 public key. Explicit post-unmarshal field
// checks (kty/crv/x length) stand in for schema validation of the wire doc.
func wbaPublicKey(k *rampv1.JsonWebKey) (ed25519.PublicKey, error) {
	if !strings.EqualFold(k.GetKty(), "OKP") || !strings.EqualFold(k.GetCrv(), "Ed25519") {
		return nil, fmt.Errorf("helpers: unsupported key type kty=%q crv=%q", k.GetKty(), k.GetCrv())
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.GetX())
	if err != nil {
		return nil, fmt.Errorf("helpers: decode jwk x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("helpers: jwk x length %d != %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// wbaKeyActiveAt reports whether now falls inside k's [not_before, not_after)
// half-open validity window. A missing or unparseable bound makes the key
// inactive — validity must be explicit.
func wbaKeyActiveAt(k *rampv1.JsonWebKey, now time.Time) bool {
	notBefore, err := time.Parse(time.RFC3339, k.GetNotBefore())
	if err != nil {
		return false
	}
	notAfter, err := time.Parse(time.RFC3339, k.GetNotAfter())
	if err != nil {
		return false
	}
	return !now.Before(notBefore) && now.Before(notAfter)
}

// wbaHostAnchored reports whether candidate's host is anchored to anchor —
// equal to it or a subdomain of it (case-insensitive, full label boundary, so
// "evil-a.com" is NOT a subdomain of "a.com"). candidate may be a full URL.
func wbaHostAnchored(anchor, candidate string) bool {
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		return false
	}
	a := strings.ToLower(strings.TrimSuffix(anchor, "."))
	c := strings.ToLower(strings.TrimSuffix(u.Host, "."))
	if a == "" {
		return false
	}
	return c == a || strings.HasSuffix(c, "."+a)
}
