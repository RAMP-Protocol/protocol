package resolvers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/encoding/protojson"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// WBA-resolution sentinels. AUTHORITY CONTRACT: the resolver surfaces these
// verdicts RAW and makes no security decision on the caller's behalf. Whether a
// revoked/expired/unavailable verdict is authoritative (halt a composite
// resolver, fail closed) or maskable into ErrUnknownKey (fall through to the
// next delegate, e.g. a lazy-registration path) is the CALLER's decision —
// composite ordering and any masking live in the application.
var (
	// ErrUnknownKey re-exports helpers.ErrUnknownKey so the active-key selectors'
	// "no candidate" verdict (empty / nil / all-malformed directory, or a bound that
	// scanned none) is checkable from this package — errors.Is-identical to the
	// sentinel WBAKeyResolver.Resolve surfaces for an unknown thumbprint — without a
	// caller importing helpers directly. It is the DISTINCT counterpart to
	// ErrKeyExpired: no candidate at all, versus a candidate that was out of window.
	ErrUnknownKey = helpers.ErrUnknownKey
	// ErrKeyRevoked signals the thumbprint is present in the directory host's
	// current revocation snapshot.
	ErrKeyRevoked = errors.New("resolvers: key revoked")
	// ErrKeyExpired signals the key exists but is outside its
	// [not_before, not_after) validity window.
	ErrKeyExpired = errors.New("resolvers: key outside validity window")
	// ErrDirectoryUnavailable signals the WBA directory could not be fetched or
	// parsed. It is deliberately errors.Is-DISTINCT from ErrUnknownKey: a
	// fail-closed composite must be able to halt on a directory outage rather
	// than fall through as if the key were merely unknown.
	ErrDirectoryUnavailable = errors.New("resolvers: WBA directory unavailable")
	// ErrRevocationUnevaluated signals that the key resolved, but its directory
	// declares a revocation_url whose snapshot has never been fetched (unreachable
	// or not host-anchored) — so revocation was NEVER EVALUATED, which is distinct
	// from "evaluated and not revoked". Only surfaced when RequireRevocation is
	// set; the default keeps the prior best-effort behavior. It lets a caller that
	// treats revocation as mandatory fail closed instead of trusting an
	// unevaluated key.
	ErrRevocationUnevaluated = errors.New("resolvers: key revocation unevaluated")
)

// WBADirectoryPath is the well-known path a WBA identity directory is served
// at (Web Bot Auth; the identity half of the split — the commercial
// overlay stays in /.well-known/ramp.json).
const WBADirectoryPath = "/.well-known/http-message-signatures-directory"

// WBADirectoryURL builds the full WBA identity-directory URL from a scheme and an
// already-joined host: scheme://host + WBADirectoryPath. An empty scheme defaults
// to https. It is a PURE string function — the host arrives pre-formed (any
// port-join / IPv6 bracketing is the caller's concern, e.g. net.JoinHostPort at
// NewWBADirectoryFetcher), there is no env read, and no scheme-in-host detection.
// It is the cross-language oracle for the wba-url-vectors.json parity corpus that
// sdk/python wba_directory_url and sdk/ts wbaDirectoryURL replay; the base-carrying
// fetch path (fetchWBAFile) keeps appending the shared WBADirectoryPath const
// directly, so it is deliberately left untouched to preserve the single
// fetch+decode path and avoid a double-append.
func WBADirectoryURL(scheme, host string) string {
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + host + WBADirectoryPath
}

// Defaults mirror the platform reference implementation: the directory itself
// rotates slowly (keys carry validity windows), so an hour TTL is fine; the
// revocation snapshot bounds emergency-revocation latency, so it is polled on
// the 300s cadence (±10% jitter).
const (
	defaultWBADirectoryTTL = time.Hour
	defaultWBAPollInterval = 300 * time.Second

	// defaultWBASyncDebounce bounds how often the unknown-thumbprint force-refresh
	// may fire per directory host. The key resolver runs BEFORE the ed25519
	// signature check and the directory host is the caller-supplied
	// Signature-Agent, so an unauthenticated caller can otherwise drive one
	// outbound directory GET per unknown thumbprint (reflection/amplification +
	// self-DoS). The SSRF-guarded dialer blocks private TARGETS, not the fetch
	// RATE to public hosts — this window is the rate bound.
	defaultWBASyncDebounce = 5 * time.Second

	// wbaRevocationAsOfSkew bounds how far into the future a revocation
	// snapshot's as_of may sit relative to the verifier's clock before it is
	// clamped. A compromised or misconfigured origin cannot then stamp a
	// far-future as_of that would freeze every subsequent (legitimately earlier)
	// snapshot under the monotonic guard — the first-poll integrity bug.
	wbaRevocationAsOfSkew = 300 * time.Second

	// defaultWBAHTTPTimeout bounds the built-in guarded client's directory /
	// revocation GETs so a slow origin cannot pin the poller or a Resolve call.
	defaultWBAHTTPTimeout = 10 * time.Second
)

// ssrfBlockedPrefixes is the reserved / non-public address set the WBA SSRF
// guard rejects, built once. It replaces the net.IP.IsPrivate/IsLinkLocalUnicast
// heuristic, which misses CGNAT (100.64.0.0/10), 0.0.0.0/8, the TEST-NETs,
// benchmarking, protocol-assignment, and other reserved ranges that are still
// IsGlobalUnicast()==true. IPv4-mapped and NAT64 forms are unwrapped separately
// (see ssrfBlocked) so an IPv6 literal cannot smuggle a private v4 past a
// v6-form-only check.
var ssrfBlockedPrefixes = mustParsePrefixes(
	// IPv4
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	// IPv6
	"::/96", "::1/128", "100::/64", "2001:db8::/32", "2001::/23",
	"fc00::/7", "fe80::/10", "ff00::/8",
	// 6to4 (embeds a v4 in bits 16-48; block the block wholesale — RFC 3056)
	"2002::/16",
	// NAT64 (also unwrapped in ssrfBlocked so the embedded v4 is re-checked)
	"64:ff9b::/96", "64:ff9b:1::/48",
)

func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c).Masked())
	}
	return out
}

// ssrfBlocked reports whether addr is non-public. It first strips any IPv6 zone
// (netip.Prefix.Contains is false for a zoned address, so a zoned literal like
// fe80::1%eth0 would otherwise skip every prefix — a guard bypass) and unwraps
// v4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) forms, re-checking the
// embedded v4, so an IPv6 literal embedding a private v4 cannot slip past a
// v6-only test.
func ssrfBlocked(addr netip.Addr) bool {
	addr = addr.WithZone("").Unmap() // drop scope id, then v4-mapped ::ffff:a.b.c.d -> a.b.c.d
	if addr.Is6() {
		if v4, ok := nat64EmbeddedV4(addr); ok && ssrfBlocked(v4) {
			return true
		}
	}
	for _, p := range ssrfBlockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// nat64EmbeddedV4 extracts the trailing 32 bits of a 64:ff9b::/96 (well-known
// NAT64 prefix, RFC 6052) address as an IPv4 address so its reserved-ness can be
// re-checked. Only the /96 well-known prefix is handled — the /48 local-use
// prefix is caught directly by the prefix table.
func nat64EmbeddedV4(addr netip.Addr) (netip.Addr, bool) {
	nat64 := netip.MustParsePrefix("64:ff9b::/96")
	if !nat64.Contains(addr) {
		return netip.Addr{}, false
	}
	b := addr.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}

// allowedScheme is the deny-by-default URL-scheme allowlist for the guarded
// transport: only http/https may be dialed, on the initial request AND every
// redirect target. A scheme denylist is unwinnable (ftp, ftps, telnet, gopher,
// file, data, dict, …), so the policy is an allowlist. Case-insensitive per
// RFC 3986. Shared, corpus-tested across the three SDKs.
func allowedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

// maxWBARedirects bounds redirect following on the guarded transport: the guard
// follows at most this many redirect hops and refuses the next. Shared, corpus-
// tested across the three SDKs (redirectChainRefused): the Go CheckRedirect,
// httpx max_redirects, and undici maxRedirections all honor this SAME cap.
const maxWBARedirects = 5

// redirectChainRefused is the shared redirect-depth policy: a chain of hops
// redirects is refused iff it EXCEEDS maxWBARedirects (deny-by-default parity).
// Called with len(via) (the requests already made when a redirect is offered), so
// the guard follows the first maxWBARedirects hops and refuses the next. The
// shared corpus pins this predicate across the three SDKs so no language inherits
// its HTTP library's looser default (~20 hops).
func redirectChainRefused(hops int) bool { return hops > maxWBARedirects }

// anyAddrBlocked reports whether ANY address in addrs is reserved / non-public.
// It is the multi-address fail-closed rule the three SDKs share: a host that
// resolves to a MIXED public/reserved set is refused OUTRIGHT, so a rebinding or
// round-robin DNS answer cannot land a later connect on the reserved member. The
// corpus emitter self-checks against this predicate so the Go dialer and the
// cross-language vectors agree on the whole-set verdict.
func anyAddrBlocked(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if ssrfBlocked(a) {
			return true
		}
	}
	return false
}

// SSRFGuard returns base with an SSRF-guarded dialer installed: it resolves every
// candidate address for the target host, refuses OUTRIGHT if ANY of them is a
// reserved / non-public address (anyAddrBlocked — fail-closed on a mixed set),
// and otherwise dials PINNED to a checked address literal. No re-resolution
// happens at connect, so a rebinding DNS cannot steer the connect onto a reserved
// address after the check. It is the INJECTABLE form of the WBA default client's
// dial-seam guard — drop it into any *http.Client so a fetch of a caller-supplied
// host cannot reach an internal target.
//
// base==nil yields a fresh, minimal transport; a non-nil base is cloned so the
// caller's other transport settings are kept. In BOTH cases the guard forces
// Proxy=nil: a proxied transport dials the PROXY, so the dial-time check would vet
// the proxy's address instead of the true target — a full bypass. The dial-time
// SSRF pin and an egress proxy are therefore mutually exclusive by construction.
// Pair it with SSRFCheckRedirect on the *http.Client to also vet redirect schemes
// and bound redirect depth.
func SSRFGuard(base *http.Transport) *http.Transport {
	if base == nil {
		base = &http.Transport{}
	} else {
		base = base.Clone()
	}
	// A proxied CONNECT would tunnel past the dial-time address check (the dialer
	// would resolve+check the PROXY, not the destination). Force it off so the
	// guard always vets the real target.
	base.Proxy = nil
	base.DialContext = guardedDialContext
	return base
}

// guardedDialContext is the http.Transport.DialContext that closes the SSRF and
// DNS-rebinding windows: it resolves the target host, refuses if ANY resolved
// address is reserved (fail-closed on a mixed set), then dials PINNED to a checked
// address literal so the connection lands on a vetted peer and no second lookup
// can steer it. TLS SNI is unaffected — http.Transport sets the server name from
// the request URL, not from the dialed address.
func guardedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := ssrfResolveChecked(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	var dialErr error
	for _, a := range addrs {
		conn, cerr := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if cerr == nil {
			return conn, nil
		}
		dialErr = cerr
	}
	return nil, dialErr
}

// ssrfResolveChecked resolves host and returns its candidate addresses ONLY if
// every one is public; otherwise it returns a GENERIC refusal. A bare IP literal
// is checked directly (no lookup). The error deliberately neither echoes the
// resolved address nor distinguishes an unresolvable host from a resolved-reserved
// one, so it cannot serve as a pre-auth DNS oracle against internal networks.
func ssrfResolveChecked(ctx context.Context, host string) ([]netip.Addr, error) {
	refuse := fmt.Errorf("resolvers: refusing to dial %q (SSRF guard)", host)
	if addr, perr := netip.ParseAddr(host); perr == nil {
		if ssrfBlocked(addr) {
			return nil, refuse
		}
		return []netip.Addr{addr}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 || anyAddrBlocked(addrs) {
		return nil, refuse
	}
	return addrs, nil
}

// SSRFCheckRedirect is an http.Client.CheckRedirect that bounds redirect depth
// (redirectChainRefused, the shared cap) and re-vets every redirect target's
// scheme against the deny-by-default http/https allowlist (a scheme denylist is
// unwinnable — ftp, file, data, …). Redirect ADDRESS re-vetting is automatic when
// the client's transport is SSRFGuard-wrapped: each redirect makes a fresh guarded
// dial.
func SSRFCheckRedirect(req *http.Request, via []*http.Request) error {
	if redirectChainRefused(len(via)) {
		return fmt.Errorf("resolvers: too many redirects (SSRF guard)")
	}
	if !allowedScheme(req.URL.Scheme) {
		return fmt.Errorf("resolvers: refusing redirect to non-http(s) scheme %q (SSRF guard)", req.URL.Scheme)
	}
	return nil
}

// newGuardedWBAClient is the HTTP client used when the caller injects none. It
// installs the dial-time address guard (SSRFGuard, no proxy) and the redirect
// scheme+depth guard (SSRFCheckRedirect, http+https), so it refuses reserved /
// non-public targets by default. The directory host is derived from a
// caller-supplied Signature-Agent and the fetch runs BEFORE the ed25519 signature
// check, so an unguarded default is a pre-auth SSRF lever against internal
// networks. A deployment that must reach a private directory (tests, on-prem)
// injects its own HTTP client.
func newGuardedWBAClient() *http.Client {
	return &http.Client{
		Timeout:       defaultWBAHTTPTimeout,
		Transport:     SSRFGuard(nil),
		CheckRedirect: SSRFCheckRedirect,
	}
}

// WBAKeyResolverOptions tune a WBAKeyResolver. Zero values are safe defaults.
type WBAKeyResolverOptions struct {
	// HTTP overrides the client used for directory and revocation GETs. When nil,
	// the resolver installs a safe-by-default SSRF-guarded client (see
	// newGuardedWBAClient): the directory host is derived from request input (the
	// Signature-Agent header) and fetched before the ed25519 check, so the default
	// refuses private/link-local/loopback targets. Inject a client only to REACH a
	// private directory (tests, on-prem) or to apply a custom dialer/timeout.
	HTTP *http.Client
	// TTL bounds how long a fetched directory is reused (≤0 → 1 hour).
	TTL time.Duration
	// PollInterval is the base revocation-poll cadence for Run (≤0 → 300s).
	PollInterval time.Duration
	// SyncDebounce bounds how often the unknown-thumbprint force-refresh may fire
	// per directory host (≤0 → 5s). It caps the outbound directory fetches an
	// unauthenticated caller can drive by presenting unknown thumbprints — the
	// resolver runs before the ed25519 check and the host is the caller-supplied
	// Signature-Agent. The TTL-cache refresh path is NOT gated by it; only the
	// self-heal force-fetch on an unknown thumbprint is.
	SyncDebounce time.Duration
	// Now overrides the clock for TTL and validity-window comparisons (nil →
	// time.Now). Tests inject.
	Now func() time.Time
	// After overrides the poll-tick timer source (nil → time.After). Tests
	// inject a deterministic clock.
	After func(time.Duration) <-chan time.Time
	// Scheme is applied when the Signature-Agent value carries no scheme
	// (empty → "https"). Tests inject "http" to drive an httptest server.
	Scheme string
	// RequireRevocation makes Resolve fail closed with ErrRevocationUnevaluated
	// when a key's directory declares a revocation_url but no snapshot has been
	// fetched (unreachable or not host-anchored) — i.e. revocation could not be
	// evaluated. Default false keeps the best-effort behavior (a declared-but-
	// unreachable revocation channel does not block resolution). Set it where a
	// revoked-key must never resolve even if the revocation channel is down.
	RequireRevocation bool
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
	http              *http.Client
	ttl               time.Duration
	pollInterval      time.Duration
	syncDebounce      time.Duration
	now               func() time.Time
	after             func(time.Duration) <-chan time.Time
	scheme            string
	requireRevocation bool
	logger            *slog.Logger
	onPollArmed       func()
	onPollCycle       func()

	dirMu    sync.Mutex
	dirCache map[string]wbaDirEntry
	dirBase  map[string]string // host → scheme://host base for poller re-fetch

	// sf coalesces a concurrent burst of directory fetches for the same host into
	// ONE in-flight GET (thundering-herd guard on the TTL-refresh AND unknown-
	// thumbprint self-heal paths). syncMu/lastSync throttle the unknown-thumbprint
	// force-refresh to one per SyncDebounce window per host (anti-amplification).
	sf       singleflight.Group
	syncMu   sync.Mutex
	lastSync map[string]time.Time

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
		// Safe by default: block SSRF to internal networks. A caller that needs a
		// private directory (tests, on-prem) injects its own client via opts.HTTP.
		client = newGuardedWBAClient()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultWBADirectoryTTL
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = defaultWBAPollInterval
	}
	debounce := opts.SyncDebounce
	if debounce <= 0 {
		debounce = defaultWBASyncDebounce
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
		http:              client,
		ttl:               ttl,
		pollInterval:      interval,
		syncDebounce:      debounce,
		now:               now,
		after:             after,
		scheme:            scheme,
		requireRevocation: opts.RequireRevocation,
		logger:            logger,
		onPollArmed:       opts.OnPollArmed,
		onPollCycle:       opts.OnPollCycle,
		dirCache:          map[string]wbaDirEntry{},
		dirBase:           map[string]string{},
		lastSync:          map[string]time.Time{},
		revoked:           map[string]wbaRevSet{},
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
	dir := helpers.SignatureAgentFromContext(ctx)
	if dir == "" || keyID == "" {
		return nil, fmt.Errorf("%w: no signature-agent directory for keyid=%q", helpers.ErrUnknownKey, keyID)
	}
	base, host, err := r.directoryBase(dir)
	if err != nil {
		// A Signature-Agent that does not name a fetchable directory cannot resolve
		// a key here — this is "not a directory", not "the directory is down", so it
		// stays a fall-through verdict. Deliberately NOT worded as "unparseable":
		// most failures reaching here are policy refusals of a perfectly well-formed
		// value, and calling those a parse error misdirects whoever reads the log.
		return nil, fmt.Errorf("%w: cannot resolve signature-agent %q: %w", helpers.ErrUnknownKey, dir, err)
	}
	f, err := r.wbaFile(ctx, base, host)
	if err != nil {
		return nil, err
	}
	key, ok := wbaKeyByThumbprint(f, keyID)
	if !ok {
		// The force-refresh below bypasses the TTL cache, so it is the lever an
		// unauthenticated caller could pull once per unknown thumbprint. Gate it
		// to one fetch per SyncDebounce window per host: outside the window the
		// thumbprint is reported unknown WITHOUT a fetch. Removal-vs-rotation
		// self-heal still works — the first unknown lookup in each window refetches.
		if !r.beginSync(host) {
			return nil, fmt.Errorf("%w: keyid=%q host=%q (refresh debounced)", helpers.ErrUnknownKey, keyID, host)
		}
		if f, err = r.syncRefresh(ctx, base, host); err != nil {
			return nil, err
		}
		if key, ok = wbaKeyByThumbprint(f, keyID); !ok {
			return nil, fmt.Errorf("%w: keyid=%q host=%q", helpers.ErrUnknownKey, keyID, host)
		}
	}
	if r.isRevoked(host, keyID) {
		return nil, fmt.Errorf("%w: keyid=%q", ErrKeyRevoked, keyID)
	}
	// Fail-closed on unevaluated revocation: the directory advertises a
	// revocation channel but we hold no snapshot for it, so we cannot assert the
	// key is un-revoked. Only enforced when the caller opted into RequireRevocation.
	if r.requireRevocation && f.GetRevocationUrl() != "" && !r.revocationSnapshotPresent(host) {
		return nil, fmt.Errorf("%w: keyid=%q host=%q", ErrRevocationUnevaluated, keyID, host)
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
//
// A key directory must be something this resolver FETCHES, so the scheme has to
// be one this resolver can fetch over. That is enforced ONCE, on the parsed URL,
// rather than per syntactic form: a value may arrive with an authority
// ("data://x", "ftp://x") or as an opaque URI ("data:{…}"), and a guard that saw
// only one of those shapes would let the other through to fail later as a
// transport error — a different verdict class, which a composite resolver reads
// as "directory down" rather than "not a directory".
//
// The scheme that matters is data:, which the WBA directory draft §4.1 permits
// and which embeds a whole key directory in the header. RAMP refuses it: key
// resolution rests on fetching the directory from a location the signer had to
// control, so a signer shipping its own directory inline is asserting its own
// keys. The draft does substitute a boundary there — a certificate chain (x5c
// validated to a CA via the AIA URI) — but this SDK implements no part of that,
// so accepting data: would authenticate nothing.
func (r *WBAKeyResolver) directoryBase(ref string) (base, host string, err error) {
	if !strings.Contains(ref, "://") {
		if err := requireHostForm(ref); err != nil {
			return "", "", err
		}
		ref = r.scheme + "://" + ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		// Framed, not passed through raw. A value that is not a URL at all used to
		// surface whatever url.Parse happened to complain about — for the spec's
		// dictionary form that is `invalid port ":application"`, which names a port
		// nobody wrote and hides that the value was never a directory reference.
		return "", "", fmt.Errorf("is not a directory reference: %w", err)
	}
	// The SAME allowlist the guarded transport applies to every redirect hop,
	// now applied to the initial URL too. Reusing the predicate rather than
	// re-deriving the verdict is the point: its own contract records that a
	// scheme denylist is unwinnable, and the shared corpus already pins which
	// schemes are fetchable. A second, differently-shaped rule here would be a
	// place for the two to disagree.
	if !allowedScheme(u.Scheme) {
		return "", "", fmt.Errorf("%q directory is not fetchable; only http(s) directories are accepted", u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("no host in %q", ref)
	}
	// A reference that survives parsing can still carry a Host no host-port split
	// reproduces — "data:" prefixed becomes "https://data:", whose Host keeps a
	// dangling colon. Such values are not merely unreachable: this Host is the
	// cache key and the Host header for every later fetch, so admitting one puts
	// a malformed key in a shared map.
	if !wellFormedHost(u) {
		return "", "", fmt.Errorf("%q is not a host[:port]", u.Host)
	}
	return u.Scheme + "://" + u.Host, u.Host, nil
}

// wellFormedHost reports whether u.Host is an addressable host[:port] rather than
// merely non-empty. url.Parse is deliberately lenient — it carries a trailing
// colon, or text no name resolver could ever look up, through as a Host instead
// of failing — and this Host becomes the directory cache key and the Host header
// of every later fetch, so leniency here puts junk in a shared map.
//
// Two conditions. The name must be a registered name or an IP literal, which is
// what rejects the sf-dictionary form: "agent2=\"a.example\"" parses to exactly
// that Host, and quotes and equals signs are not host characters. And Host must
// be precisely what re-assembling the parsed name and port produces, which is
// what rejects a dangling colon.
func wellFormedHost(u *url.URL) bool {
	name := u.Hostname()
	if name == "" {
		return false
	}
	reassembled := name
	if strings.Contains(name, ":") {
		// Colons are legal in a host only inside an IPv6 literal, and Hostname()
		// strips the brackets that Host carries.
		if net.ParseIP(name) == nil {
			return false
		}
		reassembled = "[" + name + "]"
	} else if !isRegisteredName(name) {
		return false
	}
	if port := u.Port(); port != "" {
		reassembled += ":" + port
	}
	return u.Host == reassembled
}

// isRegisteredName reports whether name holds only characters a DNS name may
// carry. Internationalized names reach here already punycoded (xn--…), so ASCII
// is the whole alphabet; underscore is admitted because service records and
// container hostnames use it.
func isRegisteredName(name string) bool {
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// requireHostForm decides whether a reference carrying no "://" is a bare host
// (possibly with a port and a path) or an opaque scheme:payload URI. Only the
// former may have a scheme prefixed onto it; prefixing an opaque URI produces a
// pseudo-authority like "https://data:application/json" whose failure reads as a
// malformed host rather than a declined directory.
//
// url.Parse cannot tell the two apart on its own — "identity:8080" and "data:{…}"
// both come back as scheme:opaque — so the decision is made on the text before
// the first "/", which is the only part that could be a port. Getting this wrong
// in either direction is costly: too strict and compose stacks addressing
// "identity:8080" break, too loose and inline directories get through.
//
// The error is not prefixed with the reference: the caller in Resolve already
// echoes it, and repeating it produced a message naming the value twice.
func requireHostForm(ref string) error {
	u, err := url.Parse(ref)
	if err != nil || u.Opaque == "" {
		// Unparseable or no opaque part: not the shape this guard covers. A
		// genuinely malformed value still fails the host check downstream.
		return nil
	}
	// "identity:8080/dir" parses to Opaque "8080/dir"; a path after the port is
	// legal on a bare host reference and must not be read as an opaque payload.
	portText, _, _ := strings.Cut(u.Opaque, "/")
	if _, portErr := strconv.ParseUint(portText, 10, 16); portErr == nil {
		return nil // host:port, optionally with a path
	}
	// Digits that do not fit a port are a bad port, not an inline payload. Saying
	// "inline URI" there would be the same misdiagnosis this guard exists to end,
	// pointed the other way.
	if portText != "" && strings.IndexFunc(portText, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return fmt.Errorf("port %q is out of range", portText)
	}
	return fmt.Errorf("carries an inline %q URI; only fetchable http(s) directories are accepted", u.Scheme)
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

// beginSync reports whether an unknown-thumbprint force-refresh for host may
// proceed now, recording the attempt's timestamp when it does. It admits at most
// one forced refresh per SyncDebounce window per host: an unauthenticated caller
// presenting N unknown thumbprints for one host drives ONE outbound fetch, not N.
// The TTL-cache refresh path (wbaFile) does not call it — a legitimately-expired
// directory always re-fetches.
func (r *WBAKeyResolver) beginSync(host string) bool {
	now := r.now()
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if last, ok := r.lastSync[host]; ok && now.Sub(last) < r.syncDebounce {
		return false
	}
	r.lastSync[host] = now
	return true
}

// syncRefresh force-fetches host's WBA directory, bypassing the TTL cache, and
// refreshes its revocation snapshot. A concurrent burst for the same host
// coalesces to ONE in-flight fetch via singleflight — a thundering herd (many
// callers crossing a TTL boundary, or an unknown-thumbprint burst) issues a
// single GET and shares its result.
func (r *WBAKeyResolver) syncRefresh(ctx context.Context, base, host string) (*rampv1.WBAFile, error) {
	v, err, _ := r.sf.Do(host, func() (any, error) {
		f, ferr := r.fetchDirectory(ctx, base)
		if ferr != nil {
			return nil, ferr
		}
		r.dirMu.Lock()
		r.dirCache[host] = wbaDirEntry{file: f, exp: r.now().Add(r.ttl)}
		r.dirBase[host] = base
		r.dirMu.Unlock()
		r.refreshRevocationFor(ctx, host, f)
		return f, nil
	})
	if err != nil {
		return nil, err
	}
	f, ok := v.(*rampv1.WBAFile)
	if !ok {
		return nil, fmt.Errorf("%w: internal fetch result type", ErrDirectoryUnavailable)
	}
	return f, nil
}

// fetchDirectory GETs and decodes the WBA directory at base. Any transport,
// status, or decode failure wraps ErrDirectoryUnavailable — see the sentinel
// contract: a directory outage must stay distinguishable from an unknown key.
func (r *WBAKeyResolver) fetchDirectory(ctx context.Context, base string) (*rampv1.WBAFile, error) {
	return fetchWBAFile(ctx, r.http, base)
}

// getDoc GETs a small well-known document, bounding the body read.
func (r *WBAKeyResolver) getDoc(ctx context.Context, docURL string) ([]byte, error) {
	return fetchWBADoc(ctx, r.http, docURL)
}

// fetchWBAFile GETs base+WBADirectoryPath through client and protojson-decodes the
// WBAFile, wrapping any transport/status/decode failure in ErrDirectoryUnavailable.
// It is the one fetch+decode path shared by WBAKeyResolver.fetchDirectory and the
// domain-keyed offer-key fetcher (NewWBADirectoryFetcher), so the two never drift.
func fetchWBAFile(ctx context.Context, client *http.Client, base string) (*rampv1.WBAFile, error) {
	raw, err := fetchWBADoc(ctx, client, base+WBADirectoryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryUnavailable, err)
	}
	var f rampv1.WBAFile
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrDirectoryUnavailable, err)
	}
	return &f, nil
}

// fetchWBADoc GETs a small well-known document through client, bounding the body read.
func fetchWBADoc(ctx context.Context, client *http.Client, docURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	resp, err := client.Do(req)
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

// revocationSnapshotPresent reports whether a revocation snapshot has ever been
// fetched for host. This is DISTINCT from "the snapshot is empty": an empty
// snapshot means revocation WAS evaluated and nothing is revoked, whereas an
// absent snapshot means revocation was never evaluated (revocation_url
// unreachable / not host-anchored / not yet polled).
func (r *WBAKeyResolver) revocationSnapshotPresent(host string) bool {
	r.revMu.RLock()
	defer r.revMu.RUnlock()
	_, ok := r.revoked[host]
	return ok
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
		tp, err := helpers.Thumbprint(pub)
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
		return nil, fmt.Errorf("resolvers: unsupported key type kty=%q crv=%q", k.GetKty(), k.GetCrv())
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.GetX())
	if err != nil {
		return nil, fmt.Errorf("resolvers: decode jwk x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("resolvers: jwk x length %d != %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ActiveKeyScanOptions tunes the document-order scan the ActiveEd25519Key* faces
// perform. The zero value — and omitting it entirely — scans the WHOLE directory,
// UNBOUNDED, which is the safe default: a silent cap makes a valid key at a high
// document position permanently unselectable AND indistinguishable from "no active
// key" (a DoS-by-directory-padding footgun), so a bound is now opt-IN, never the
// default.
//
// It follows the file's options-struct convention (cf. WBAKeyResolverOptions),
// replacing the former variadic maxScan ...int that silently honored only its first
// argument. The faces still accept it variadically (opts ...ActiveKeyScanOptions) so
// the common unbounded call omits it entirely; at most ONE options value is honored
// (the first).
type ActiveKeyScanOptions struct {
	// MaxScan optionally bounds how many keys are examined in document order. nil
	// (the zero value) scans EVERY key — unbounded. A non-nil bound caps the scan at
	// max(0, *MaxScan) keys: 0 or negative scans none. When a non-nil positive bound
	// is exhausted without selecting a key AND the directory holds MORE keys than the
	// bound, the exhaustion is LOGGED (a valid key beyond the cap is unreachable), so a
	// bounded miss is never silently indistinguishable from a genuine "no active key".
	MaxScan *int
	// Logger receives the explicit-bound exhaustion warning (nil → slog.Default()).
	// Consulted ONLY on the bounded-exhaustion path; the unbounded default never logs.
	Logger *slog.Logger
}

// ActiveEd25519Key selects an identity's window-active Ed25519 signing key from a WBA
// directory BY DOCUMENT ORDER, complementing WBAKeyResolver (which matches a KNOWN
// thumbprint). It iterates directory.GetKeys() in document order and returns the
// FIRST key that passes ALL of: window-active ([not_before, not_after) half-open
// covers now, both bounds RFC 3339-parseable — a missing/unparseable bound makes the
// key inactive); kty=="OKP" && crv=="Ed25519" (matched CASE-INSENSITIVELY — a
// deliberate lenient SDK convention: RFC 7517/8037 specify the exact-case "OKP" /
// "Ed25519", but all three SDKs accept any case IDENTICALLY so a case-varying
// directory resolves the SAME key everywhere); and a present x that base64url-decodes
// to exactly 32 bytes. Any key failing any check is skipped and iteration continues.
//
// SELECTION IS NOT NORMATIVE: the result is the first window-active key in document
// order, which is this SDK's deterministic tie-break — NOT "the current key". The
// protocol permits several simultaneously-active keys during overlap rotation and
// defines no "first", so callers must not read a normative meaning into the choice.
//
// By default the WHOLE directory is scanned; pass ActiveKeyScanOptions.MaxScan to
// bound it. It returns (nil, ErrUnknownKey) when NO well-formed candidate key exists
// in the scanned range (empty / nil / all-malformed / bound scans none), or
// (nil, ErrKeyExpired) when a well-formed candidate existed but none was selectable
// (all out of window / all revoked). Byte-parity with the Python active_ed25519_key /
// TS activeEd25519Key oracles.
//
// REVOCATION: this selector screens ONLY validity windows and key well-formedness —
// it does NOT consult any revocation channel. A key that was emergency-revoked but
// is still window-active in a (possibly CDN-cached) directory WILL be selected. A
// caller on a VERIFICATION path MUST NOT trust the result until it has screened the
// selected key's RFC 7638 thumbprint against the resolver's revoked-thumbprint set
// (WBAKeyResolver.Revoked / a revocation snapshot); otherwise adopting this selector
// defeats emergency revocation. Prefer ActiveEd25519KeyScreened, which folds that
// screen into selection. This bare form is for non-verification callers only.
func ActiveEd25519Key(directory *rampv1.WBAFile, now time.Time, opts ...ActiveKeyScanOptions) (ed25519.PublicKey, error) {
	pub, _, err := selectActiveEd25519Key(directory, now, nil, opts...)
	return pub, err
}

// ActiveEd25519KeyWithExpiry runs the IDENTICAL document-order selection as
// ActiveEd25519Key but ALSO returns the selected key's not_after (its
// [not_before, not_after) upper bound). A downstream caller — e.g. an offer-key
// cache — clamps its cache TTL to min(now+ttl, not_after) with the returned
// time.Time so a cached key never outlives its validity window; the plain
// ActiveEd25519Key drops it. The not_after is guaranteed parseable because
// selection required it (wbaKeyActiveAt rejects a key whose window bounds do not
// parse). It returns the same (ErrUnknownKey / ErrKeyExpired) not-found sentinels
// ActiveEd25519Key surfaces when no key qualifies. Byte-parity with the Python
// active_ed25519_key_with_expiry / TS activeEd25519KeyWithExpiry oracles.
//
// REVOCATION: like ActiveEd25519Key, this bare form does NOT consult revocation —
// it can return a window-active-but-revoked key. A VERIFICATION path MUST screen
// the result against the revoked-thumbprint set, or use the revocation-aware
// ActiveEd25519KeyWithExpiryScreened instead.
func ActiveEd25519KeyWithExpiry(directory *rampv1.WBAFile, now time.Time, opts ...ActiveKeyScanOptions) (ed25519.PublicKey, time.Time, error) {
	return selectActiveEd25519Key(directory, now, nil, opts...)
}

// ActiveEd25519KeyScreened is ActiveEd25519Key made REVOCATION-AWARE: it runs the
// same document-order window + well-formedness selection but ALSO skips any key
// whose RFC 7638 thumbprint `revoked` reports true, so a window-active-but-revoked
// key is never returned. It is the selector a VERIFICATION path adopts — folding
// the revoked-set screen the bare ActiveEd25519Key leaves to the caller into
// selection itself, so an emergency-revoked key still listed in a CDN-cached
// directory is passed over for the next active, non-revoked key. `revoked` is
// REQUIRED: a nil predicate screens nothing (equivalent to the bare selector and
// unsafe on a verification path). Pass one over the resolver's revoked-thumbprint
// set (e.g. WBAKeyResolver.Revoked) or, for a caller with no revocation channel, an
// explicit func(string) bool { return false } to make the waiver visible. The
// thumbprint is computed with helpers.Thumbprint (RFC 7638) — the SAME primitive
// WBAKeyResolver.Resolve keys on. Returns (nil, ErrUnknownKey) when no well-formed
// candidate existed, else (nil, ErrKeyExpired) when every candidate was out of window
// or revoked.
func ActiveEd25519KeyScreened(directory *rampv1.WBAFile, now time.Time, revoked func(thumbprint string) bool, opts ...ActiveKeyScanOptions) (ed25519.PublicKey, error) {
	pub, _, err := selectActiveEd25519Key(directory, now, revoked, opts...)
	return pub, err
}

// ActiveEd25519KeyWithExpiryScreened is ActiveEd25519KeyWithExpiry made
// REVOCATION-AWARE (see ActiveEd25519KeyScreened): the same document-order
// selection, plus a skip of any key whose RFC 7638 thumbprint `revoked` reports
// true, returned with the selected key's not_after for cache-TTL clamping. This is
// the selector CachedOfferKeyResolver composes so a cached offer-signing key is
// both window-active AND not revoked. `revoked` is REQUIRED (see the screened plain
// face). Returns the same (ErrUnknownKey / ErrKeyExpired) not-found sentinels when no
// examined, non-revoked key qualifies.
func ActiveEd25519KeyWithExpiryScreened(directory *rampv1.WBAFile, now time.Time, revoked func(thumbprint string) bool, opts ...ActiveKeyScanOptions) (ed25519.PublicKey, time.Time, error) {
	return selectActiveEd25519Key(directory, now, revoked, opts...)
}

// selectActiveEd25519Key is the shared selector behind all four active-key faces:
// the FIRST window-active, well-formed OKP/Ed25519, non-revoked key in document
// order (UNBOUNDED by default; ActiveKeyScanOptions.MaxScan caps it), returned with
// its not_after. It parses not_after with the SAME time.Parse(RFC3339) wbaKeyActiveAt
// used, so the faces never disagree on the selected key. `revoked` nil disables
// revocation screening (the bare faces); non-nil skips any key whose RFC 7638
// thumbprint it reports true (the screened faces).
//
// A nil directory yields ErrUnknownKey, never a panic. Well-formedness (kty/crv/x)
// is checked BEFORE the window so the not-found sentinel can distinguish "no
// candidate" (ErrUnknownKey) from "a candidate existed but none was selectable"
// (ErrKeyExpired) — mirroring WBAKeyResolver.Resolve's ErrUnknownKey/ErrKeyExpired
// split. Reordering the two checks does NOT change WHICH key is selected (a selected
// key must pass both regardless of order), so byte-parity with py/ts holds.
func selectActiveEd25519Key(directory *rampv1.WBAFile, now time.Time, revoked func(thumbprint string) bool, opts ...ActiveKeyScanOptions) (ed25519.PublicKey, time.Time, error) {
	var opt ActiveKeyScanOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if directory == nil {
		return nil, time.Time{}, fmt.Errorf("%w: no active key in directory", helpers.ErrUnknownKey)
	}
	keys := directory.GetKeys()
	scan := len(keys) // unbounded default: scan every key
	bounded := opt.MaxScan != nil
	if bounded {
		scan = *opt.MaxScan
		if scan < 0 {
			scan = 0 // negative bound scans none (clamp), matching py max(0,n) / ts Math.max(0,n)
		}
		if scan > len(keys) {
			scan = len(keys)
		}
	}
	sawCandidate := false
	for _, k := range keys[:scan] {
		pub, err := wbaPublicKey(k)
		if err != nil {
			continue // malformed / wrong key type — not a candidate
		}
		sawCandidate = true // a well-formed OKP/Ed25519 key, in or out of window
		if !wbaKeyActiveAt(k, now) {
			continue // a candidate, but outside its validity window
		}
		// Revocation screen (verification-path callers): skip a window-active key
		// whose thumbprint is revoked, so an emergency-revoked key still listed in a
		// CDN-cached directory is never selected. Thumbprint via helpers.Thumbprint
		// (RFC 7638) — the SAME keying WBAKeyResolver.Resolve uses. A key whose
		// thumbprint cannot be computed cannot be proven un-revoked, so it is skipped.
		if revoked != nil {
			tp, err := helpers.Thumbprint(pub)
			if err != nil {
				continue
			}
			if revoked(tp) {
				continue
			}
		}
		// not_after is guaranteed parseable: wbaKeyActiveAt above rejects any key
		// whose window bounds do not parse, so the selected key always has one.
		notAfter, err := time.Parse(time.RFC3339, k.GetNotAfter())
		if err != nil { // unreachable: wbaKeyActiveAt required a parseable bound
			continue
		}
		return pub, notAfter, nil
	}
	// Bounded-scan exhaustion signal: a positive explicit bound was exhausted while
	// the directory held MORE keys than the bound, so a valid key beyond the cap is
	// unreachable. Log it rather than let a bounded miss masquerade as a genuine "no
	// active key" — the DoS-by-padding footgun the unbounded default now avoids. The
	// unbounded default never reaches here with keys left unexamined.
	if bounded && *opt.MaxScan > 0 && *opt.MaxScan < len(keys) {
		activeKeyScanLogger(opt).Warn(
			"active-key scan hit explicit max_scan bound without selecting a key; a valid key beyond the cap is unreachable",
			"max_scan", *opt.MaxScan, "total_keys", len(keys))
	}
	if sawCandidate {
		// A well-formed key existed but none was selectable (all out of window / all
		// revoked): the "expired" sentinel, matching Resolve's out-of-window verdict.
		return nil, time.Time{}, fmt.Errorf("%w: no active key in directory", ErrKeyExpired)
	}
	// No well-formed candidate at all (empty / nil / all-malformed / bound scanned
	// none): the "unknown" sentinel, matching Resolve's no-such-key verdict.
	return nil, time.Time{}, fmt.Errorf("%w: no active key in directory", helpers.ErrUnknownKey)
}

// activeKeyScanLogger resolves the logger for the bounded-exhaustion warning,
// defaulting to slog.Default() when the caller injected none.
func activeKeyScanLogger(opt ActiveKeyScanOptions) *slog.Logger {
	if opt.Logger != nil {
		return opt.Logger
	}
	return slog.Default()
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
