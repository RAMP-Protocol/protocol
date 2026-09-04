package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/endpointrule"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/lrucache"
)

// maxWellKnownDocBytes bounds the well-known / JWKS response body read. A hostile
// or misconfigured origin cannot force an unbounded read into the JSON decoder;
// well-known documents are small. Mirrors the WBA fetch's maxDocBytes cap and the
// Python / TS 1 MiB well-known bound so the three SDKs agree on the ceiling.
const maxWellKnownDocBytes = 1 << 20 // 1 MiB

// ErrNoEndpoint signals that an Exchange's /.well-known/ramp.json was fetched and
// decoded successfully but advertises no endpoint (WellKnownManifest.endpoint,
// proto field 12, absent). It is deliberately distinct from a transport or
// decode failure: the manifest exists, the Exchange simply has not closed the
// "defined-but-inert endpoint" gap. Callers can tell "Exchange unreachable" from
// "Exchange reachable but not self-advertising an endpoint".
var ErrNoEndpoint = errors.New("resolvers: well-known manifest has no endpoint")

// ErrEndpointRefused signals that a manifest WAS read and advertises an endpoint
// this resolver will not hand back: one on a host unrelated to the domain that
// served the manifest, or one carrying userinfo.
//
// Distinct from ErrNoEndpoint and from a transport failure because it is a
// VERDICT — the Exchange answered, and the answer is not usable. A caller that
// classifies retryability reads this as final rather than as something to try
// again in a moment.
var ErrEndpointRefused = errors.New("resolvers: well-known manifest advertises an unusable endpoint")

// ErrManifestVersionRefused re-exports helpers.ErrManifestVersionRefused — the
// verdict CheckWellKnownManifestVersion returns for a /.well-known/ramp.json
// whose WellKnownManifest.ver this reader does not accept — so the endpoint
// resolver's refusal is checkable from this package beside ErrNoEndpoint and
// ErrEndpointRefused without a caller importing helpers directly. One sentinel
// under two names: an injected resolver that wraps either is classified the
// same way by the client tier.
//
// Like ErrEndpointRefused it is a VERDICT — final, not a transport failure to
// retry — and it is never cached. The rule, and why the gate runs before any
// other member is read, are stated once on WellKnownManifest.ver in the proto.
var ErrManifestVersionRefused = helpers.ErrManifestVersionRefused

// wellKnownDoc is the JSON projection the two well-known resolvers decode
// through: one decoder for two document shapes, each face reading only its own
// members. The key face (WellKnownKeyResolver) fetches a plain RFC 7517 JWK Set
// from an operator-chosen URL and reads `keys`. The endpoint face
// (WellKnownEndpointResolver) fetches /.well-known/ramp.json and reads the
// WellKnownManifest projection — the document version (field 1) and the
// self-advertised ExchangeService endpoint (field 12). A JWK Set carries no
// manifest version, which is why the version gate is the endpoint face's alone.
//
// Ver is held raw rather than as a string so a document whose `ver` is not a
// JSON string still decodes: the gate then refuses it as a verdict — the answer
// Python and TS give — instead of the decode failing as a transport error the
// client would retry. See manifestVer.
//
// The embedded jose.JSONWebKeySet promotes the "keys" member, so go-jose (the
// canonical JOSE library) parses each JWK — decoding the OKP/Ed25519 `x` member
// into an ed25519.PublicKey on JSONWebKey.Key — rather than the SDK hand-rolling
// the kty/crv match and the base64url `x` decode.
type wellKnownDoc struct {
	jose.JSONWebKeySet
	Ver      json.RawMessage `json:"ver"`
	Endpoint string          `json:"endpoint"`
}

// manifestVer is the string the version rule reads out of the raw `ver` member.
// A member that is absent, null, or not a JSON string yields "" — the value an
// absent field arrives as — so the rule refuses it as absent. Python and TS make
// the same choice (any non-string is absent), so the three languages return the
// same verdict for the same document.
func manifestVer(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// fetchWellKnownDoc GETs url and decodes the well-known manifest. It is the one
// HTTP+decode path both resolvers share, so the request/status/decode handling
// cannot drift between the key and endpoint faces.
func fetchWellKnownDoc(ctx context.Context, client *http.Client, url string) (*wellKnownDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("resolvers: well-known request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolvers: well-known fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resolvers: well-known status %d", resp.StatusCode)
	}
	// Bound the body read so a hostile origin cannot force an unbounded decode.
	var doc wellKnownDoc
	if decErr := json.NewDecoder(io.LimitReader(resp.Body, maxWellKnownDocBytes)).Decode(&doc); decErr != nil {
		return nil, fmt.Errorf("resolvers: well-known decode: %w", decErr)
	}
	return &doc, nil
}

// maxCachedEndpoints bounds the per-host endpoint cache. The key is an
// Offer.exchange host, so which entries appear is driven by incoming offers — an
// open-ended, caller-influenced key space, and an unbounded map over one is
// somewhere an authenticated caller can make the process grow without limit. A
// real deployment reports to a handful of Exchanges. Mirrors the bound the
// per-origin client pool above this resolver already carries.
const maxCachedEndpoints = 256

// maxManifestFetch bounds the SHARED manifest fetch — the one every coalesced
// waiter is served from, which therefore cannot take any single caller's deadline.
//
// It exists because the alternative is no bound at all: WellKnownOptions.HTTP
// accepts any *http.Client, the constructor doc invites one, and http.DefaultClient
// has no timeout. A manifest is a small document from a host an offer named; a
// fetch still running after this is not going to succeed.
const maxManifestFetch = 30 * time.Second

// WellKnownEndpointResolver resolves an Exchange domain to its self-advertised
// ExchangeService endpoint by fetching https://{host}/.well-known/ramp.json and
// reading WellKnownManifest.endpoint. Unlike WellKnownKeyResolver (one fixed
// URL), it is HOST-KEYED: a Broker resolves an arbitrary, signature-covered
// Offer.exchange host per request, so the cache, TTL freshness, and single-flight
// coalescing are all per host. The pre-seeded registry is a TRUST overlay (the
// Allow hook), never the source of the endpoint — that is the Offer.exchange
// routing invariant: the endpoint always comes from the exchange's own manifest.
//
// Because that host space is caller-influenced, neither per-host structure may
// grow without limit. The cache evicts least-recently-used at a fixed cap;
// coalescing is a singleflight.Group, which drops a host's entry as soon as its
// fetch completes and so holds nothing between calls.
type WellKnownEndpointResolver struct {
	http   *http.Client
	ttl    time.Duration
	now    func() time.Time
	scheme string
	allow  func(host string) bool
	sf     singleflight.Group
	cache  *lrucache.Cache[string, endpointEntry]
}

type endpointEntry struct {
	endpoint string
	exp      time.Time
}

// NewWellKnownEndpointResolver returns a host-keyed resolver. Zero-value options
// are safe defaults (https scheme, 5-minute TTL, real clock, SSRF-GUARDED client).
//
// The endpoint host is REQUEST-DERIVED: a Broker resolves a per-request,
// signature-covered Offer.exchange host and this resolver fetches that host's
// /.well-known/ramp.json. That is the same threat shape as the WBA directory
// fetch — a caller-influenced host reached over the network — so the default
// client is SSRF-guarded (NewGuardedClientFromEnv), NOT the unguarded
// http.DefaultClient. (The fixed-URL WellKnownKeyResolver stays on
// http.DefaultClient: its URL is an operator-chosen constant, not request-derived.)
// A deployment that must reach a private/loopback exchange (tests, on-prem) injects
// its own client via opts.HTTP or opts out via the SKIP_SSRF / ALLOW_INSECURE env flags.
func NewWellKnownEndpointResolver(opts WellKnownOptions) *WellKnownEndpointResolver {
	client := opts.HTTP
	if client == nil {
		client = NewGuardedClientFromEnv()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &WellKnownEndpointResolver{
		http:   client,
		ttl:    ttl,
		now:    now,
		scheme: scheme,
		allow:  opts.Allow,
		cache:  lrucache.New[string, endpointEntry](maxCachedEndpoints),
	}
}

// ResolveEndpoint returns the ExchangeService endpoint host advertises in its
// well-known manifest. A fresh cache entry short-circuits; a miss or TTL expiry
// triggers a single coalesced per-host fetch. A host the Allow overlay rejects
// never reaches the network.
//
// host must be a BARE hostname — no scheme, path, query or userinfo, though a
// port is fine. That is checked here rather than assumed, for the same reason
// vetAdvertisedEndpoint runs here: it is a property of building this URL, not of
// any one caller's plans for it.
func (r *WellKnownEndpointResolver) ResolveEndpoint(ctx context.Context, host string) (string, error) {
	// Checked BEFORE the Allow overlay and before the cache. The fetch URL below is
	// built by concatenation, so a value carrying a path or a query would choose
	// WHAT gets fetched rather than merely where from — and the raw string is the
	// cache key, so admitting one would also put it in a shared map.
	bare, err := helpers.IsBareHost(host)
	if err != nil {
		return "", fmt.Errorf("resolvers: resolve endpoint: %w", err)
	}
	if !bare {
		return "", fmt.Errorf("resolvers: %w: %q is not a bare host", helpers.ErrInvalidHost, host)
	}
	if r.allow != nil && !r.allow(host) {
		return "", fmt.Errorf("%w: host %q not allowed", ErrNoEndpoint, host)
	}
	if ep, ok := r.cached(host); ok {
		return ep, nil
	}
	// A concurrent burst for one host issues ONE fetch and shares its result. The
	// group holds a key only while its call is in flight, so coalescing state
	// cannot accumulate over the caller-influenced host space — including for the
	// hosts whose fetches fail, which is where a hand-rolled per-host mutex map
	// grows fastest.
	//
	// Two contexts, because one caller's deadline must not become everyone's and
	// nobody's deadline must not become the fetch's:
	//
	//   - The SHARED fetch does not inherit the winning caller's cancellation.
	//     Every waiter receives whatever the leader returns, so a leader that walks
	//     away would otherwise fail a burst of callers whose own contexts are still
	//     live, and each would read that as the Exchange being unreachable. It
	//     carries maxManifestFetch instead, so it stays bounded whatever client was
	//     injected — WellKnownOptions.HTTP admits one with no timeout at all.
	//   - Each WAITER selects on its OWN context. singleflight is not
	//     context-aware, so without this the call would honour nobody's deadline:
	//     a caller with 200ms would sit until the shared fetch finished. The fetch
	//     continues for the others; only this caller gives up.
	shared := r.sf.DoChan(host, func() (v any, err error) {
		// Derived INSIDE the closure, which singleflight runs for the leader alone.
		// Built before DoChan instead, every coalesced follower would allocate a
		// timer whose cancel func only the leader's closure ever calls — one live
		// timer per waiter, held until its full expiry. go vet's lostcancel cannot
		// see that, because cancelFetch is called on the path it can trace.
		fetchCtx, cancelFetch := context.WithTimeout(
			context.WithoutCancel(ctx), maxManifestFetch)
		defer cancelFetch()
		// A panic is turned into this call's error, HERE, because nowhere above can
		// do it: when a coalesced call has waiting channels singleflight re-raises
		// the panic on a fresh goroutine — `go panic(e)` followed by `select{}` — so
		// no caller's recover can reach it and the process dies. The two seams that
		// can panic are application-supplied (WellKnownOptions.HTTP and .Now), which
		// makes "one lookup fails" the right blast radius, not "the process exits".
		defer func() {
			if p := recover(); p != nil {
				v, err = "", fmt.Errorf("resolvers: resolve endpoint for %q: panic: %v", host, p)
			}
		}()
		if ep, ok := r.cached(host); ok {
			return ep, nil // another goroutine fetched while we waited
		}
		url := r.scheme + "://" + host + "/.well-known/ramp.json"
		doc, ferr := fetchWellKnownDoc(fetchCtx, r.http, url)
		if ferr != nil {
			return "", ferr
		}
		// The document version gate runs before the endpoint is so much as looked
		// at, and only on this face: the key face reads a JWKS document that
		// carries no manifest version.
		if verr := helpers.CheckWellKnownManifestVersion(manifestVer(doc.Ver)); verr != nil {
			return "", fmt.Errorf("resolvers: %w", verr)
		}
		if doc.Endpoint == "" {
			return "", fmt.Errorf("%w: host=%q", ErrNoEndpoint, host)
		}
		if verr := vetAdvertisedEndpoint(host, doc.Endpoint); verr != nil {
			return "", verr
		}
		r.store(host, doc.Endpoint)
		return doc.Endpoint, nil
	})
	var v any
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("resolvers: resolve endpoint for %q: %w", host, ctx.Err())
	case res := <-shared:
		v, err = res.Val, res.Err
	}
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// vetAdvertisedEndpoint decides whether an endpoint a manifest advertises may be
// handed back at all. It runs HERE, in the resolver, rather than in each caller.
//
// The manifest that named this endpoint is served by the very host the call is
// bound for, so the endpoint is only as trustworthy as that host. An Exchange may
// advertise itself or a subdomain of itself, and nothing else — an endpoint on an
// unrelated host is one this resolver refuses to return, whatever the caller
// intends to do with it. A dial-time address guard has no objection to an
// unrelated PUBLIC host, so nothing below this catches it.
//
// It sits in the resolver because every consumer needs it and none of them can be
// relied on to remember: the check is a property of reading an endpoint out of a
// manifest, not of any one caller's plans for it. A caller may of course check
// again.
//
// Userinfo is refused for a different reason with the same shape. The host
// comparison reads the authority's host and ignores any user:password before it,
// so an endpoint carrying credentials would pass the host check and then have
// net/http stamp an Authorization header the SDK never chose, on a leg that
// already carries the agent's own signature.
func vetAdvertisedEndpoint(host, endpoint string) error {
	if err := endpointrule.Vet(host, endpoint); err != nil {
		return fmt.Errorf("%w: %w", ErrEndpointRefused, err)
	}
	return nil
}

// cached returns host's endpoint when the entry is present and fresh. Freshness
// is this resolver's own concern and sits on top of the shared bound: a stale
// entry is left in place rather than deleted, since it still holds a slot the
// eviction policy can reclaim and the next successful fetch overwrites it.
func (r *WellKnownEndpointResolver) cached(host string) (string, bool) {
	entry, ok := r.cache.Get(host)
	if !ok || r.now().After(entry.exp) {
		return "", false
	}
	return entry.endpoint, true
}

// store records host's endpoint with a fresh TTL.
func (r *WellKnownEndpointResolver) store(host, endpoint string) {
	r.cache.Put(host, endpointEntry{endpoint: endpoint, exp: r.now().Add(r.ttl)})
}
