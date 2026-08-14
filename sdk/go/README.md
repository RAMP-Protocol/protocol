# RAMP SDK — Go

Layered protocol libraries co-located with the contract (ADR-020). The SDK is
consumed off-commit from this repo; it imports the generated L0 wire types
directly with no `replace` directive.

| Layer | Package | What it is |
|---|---|---|
| **L0** | `gen/go/ramp/v1`, `gen/go/vocab/*` | generated wire types (consumed, never rebuilt) |
| **L1** | **`sdk/go/helpers`** | stateless, **IO-free** protocol helpers — RFC 9421/7638 crypto, offer/acceptance verify, static key resolution, validation |
| L2 · I/O | **`sdk/go/resolvers`** | the network-fetching tier: well-known JWKS / WBA directory / `ramp.json` endpoint / offer-key resolvers + the SSRF-guarded HTTP client. Runs on a maintained `net/http` client behind the SSRF guard; composes L1, never the reverse |
| L2 · transport | `sdk/go/core` (transport-neutral: Verifier, {verified,rejected}, `DiscoveryResult` per-URI groups, VerifiedOffer guard, signing RoundTripper, ReplayStore — zero Connect) · `sdk/go/connect` (Connect **client** binding: `NewClient` + `NewBrokerClient` + the agent verbs **`Discover` · `Resolve` · `Execute` · `ReportUsage` · `Dispute` · `Fetch`** + client options + the `CallError` taxonomy + `ErrorDetailFrom`) · `sdk/go/connectserver` (Connect **server** binding: `NewExchangeServiceHandler` + server options + `AsConnectError` + `AttachErrorDetail`/`AttachDetail` + reject→code) | transport-neutral core + Connect client/server bindings (state injected) |
| L3 | separate packages | framework adapters (convert, never replace) — later |

The `L2` tier is split by kind: the **I/O** package (`resolvers`) is the only tier
that dials the network (it holds the maintained HTTP client and the SSRF guard),
while the **transport** packages (`core` / `connect` / `connectserver`) hold no
dialing surface of their own — `connect` composes the I/O tier's guarded
transport and content fetcher rather than opening a second one. An io-leaf guard (`helpers/io_leaf_guard_test.go`) fails the build if any pure
L1 file drags in a dialing surface, so the fetch surface cannot leak back down.

## L1 — `helpers`

Stateless, **no network IO** (no HTTP client, no dial), no secret custody, no state.
The same code the Broker, Exchange, MCP, Edge, and external implementors build on.
(The well-known JWKS, WBA-directory, and `ramp.json` endpoint fetches moved one tier
up into `sdk/go/resolvers`; `helpers` keeps only the pure `KeyResolver` interface and
the static resolver.)

```go
import "github.com/RAMP-Protocol/protocol/sdk/go/helpers"
```

**RFC 9421 request signing / verification** — the `Signer` interface signs the
SDK-built signature base, so a KMS/HSM signer never exposes its key:

```go
signer, _ := helpers.NewEd25519Signer("agent.v1", priv)
_ = helpers.SignRequest(ctx, req, body, signer,
    helpers.SignOptions{Created: created, Expires: expires})

// verify with the key injected (pure) ...
vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{})
// ... or resolve the key via a KeyResolver (static in L1; well-known/WBA in L2 resolvers):
vr, err = helpers.VerifyRequestResolved(ctx, req, body, resolver, helpers.VerifyOptions{})
```

**Offer authenticity** — verify a received offer before selecting on it (the gap
the SDK closes); the signature covers `pricing`, `terms`, and `expires_at`:

```go
err := helpers.VerifyOffer(offer, offer.GetSignature(), exchangePub)
```

**Signed delivery URLs + proof-of-possession** (ADR-013), byte-identical with the
edge worker:

```go
su, _ := helpers.SignURLEd25519(priv, "ex.v1", rawURL, agentThumbprint, expiry)
v, err := helpers.VerifyURLEd25519(su.URL, exchangePub, time.Now())
err = v.CheckProofOfPossession(presentedAgentPubKey) // bound-fetch enforcement
```

**Money** — exact decimal in/out, canonical decimal string on the wire:

```go
rate, _ := helpers.ParseMoney(offer.GetPricing().GetRate()) // shopspring/decimal
wire, _ := helpers.FormatMoney(rate.Mul(decimal.NewFromInt(qty)))
```

**Validation** — wraps protovalidate (the oracle), including cross-field CEL:

```go
if err := helpers.Validate(req); err != nil { /* helpers.ValidationRuleIDs(err) */ }
```

**Agent-binding proof of possession** (ADR-013) — the SIGN face of the header pair
a bound delivery fetch presents. The covered set is exactly `@method` +
`@target-uri`: a GET has no body to digest, and the signed URL is itself the
credential. The key arrives as a `Signer` plus the public half, so custody never
moves into the SDK:

```go
binding, _ := helpers.SignAgentBinding(ctx, signer, agentPub, helpers.PoPOptions{
    URL: signedURL, Created: created, Expires: expires, // keep the window short
})
binding.Apply(req.Header) // X-RAMP-Agent-Key + Signature-Input + Signature
```

**Routing predicates** — the two pure checks that precede a signed call to an
address a network party named (a manifest may point at itself or a subdomain of
itself, and nothing else):

```go
bare, _ := helpers.IsBareHost(offer.GetExchange())      // no scheme/path/query
ok, _ := helpers.HostAnchored(exchangeDomain, endpoint) // label-boundary match
```

**Audience check** — the other direction: a request arrived, does it name THIS
Exchange? The recipient's domain travels in a body field because that is the only
agent-authenticated statement of intended recipient that survives a relay — each
hop signs its own `@target-uri`, so the Exchange never sees an agent signature
over its own URL. The check is pure, so it runs before any lookup:

```go
verdict, err := helpers.CheckAudience(cfg.ExchangeDomain, report.GetExchange())
if err != nil {           // this deployment's identity is unusable -> internal
    return err
}
if verdict != helpers.AudienceAccepted {   // "empty" | "malformed" | "mismatch"
    return reject(verdict.String())        // the request's fault -> invalid argument
}
```

Pass one value, or many where the audience lives per item — a `TransactionRequest`
states it once per item, inside each item's signed offer:

```go
claimed := make([]string, 0, len(req.GetItems()))
for _, it := range req.GetItems() {
    claimed = append(claimed, it.GetOffer().GetExchange())
}
verdict, err := helpers.CheckAudience(cfg.ExchangeDomain, claimed...)
```

The match is EXACT — a subdomain is a different party — which is narrower than
the endpoint rule above, where a manifest MAY advertise a subdomain of itself. The
shape both sides admit is `helpers.IsBareDomain`, carrying the same
`BareDomainPattern` bytes as the protovalidate rule on the wire fields, so a value
this SDK accepts before sending is one the wire accepts on arrival.

**Also:** RFC 7638 `Thumbprint`, ADR-019 `ErrorDetail` constructors +
`AsConnectError`/`ErrorDetailFrom`/`Reason`, `NewIdempotencyKey`, scope helpers,
`RedactURL` (a signed URL carries its credential in the query — never log it raw),
and `RetrievalAuthFailureReasonFromToken` (the delivery edge's refusal vocabulary,
mapped onto the typed enum).

## L2 · I/O — `resolvers`

The network-fetching tier. Everything that dials a third-party-influenceable host
lives here, behind a single SSRF-guarded HTTP client, so the pre-auth-reachable
network surface never enters the pure trust core:

```go
import "github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
```

- **Key resolvers** — `NewWellKnownKeyResolver` (well-known JWKS, TTL cache),
  `NewWBAKeyResolver` (WBA directory, revocation/expiry-aware, with a `Run` poller).
- **Endpoint resolver** — `NewWellKnownEndpointResolver` discovers an Exchange's
  own service endpoint (`WellKnownManifest.endpoint`) from `/.well-known/ramp.json`,
  host-keyed and cached per host. Two sentinels, and the difference decides whether
  a caller should retry: `ErrNoEndpoint` when the manifest was read and advertises
  none, `ErrEndpointRefused` when it advertises one this resolver will not hand back
  — on a host unrelated to the one that served the manifest, or carrying userinfo.
  Both are verdicts, so both are final; anything else is a transport failure and
  worth retrying. The key is an offer-supplied host, so the cache evicts
  least-recently-used at a fixed cap and concurrent lookups for one host coalesce to
  a single fetch.
- **Active-key selection** — `ActiveEd25519Key` / `ActiveEd25519KeyWithExpiry` pick
  an identity's window-active key by document order; the `…Screened` variants fold in
  a revoked-thumbprint screen. `NewCachedOfferKeyResolver` caches the selected offer
  key with an expiry clamped to the key's `not_after`.
- **SSRF-guarded client** — `NewGuardedClientFromEnv` is the single construction path
  every fetch uses; `NewGuardedTransport` composes the same guard over a caller's
  own base transport, so application settings ride UNDER the guard rather than
  replacing it; `SSRFGuard` / `SSRFCheckRedirect` are the injectable dial-time
  address guard and redirect re-vet for callers wiring their own `http.Client`.
- **Content fetch** — `NewContentFetcher` retrieves the bytes a signed delivery URL
  names, presenting a proof of possession through the injected `ProofSigner` seam
  (so this tier holds no key material). Bounded body, bounded error body, media
  type reported rather than sniffed, and a typed `FetchError` class.

**Redirects: the guarded client follows, a signed leg refuses.** Following five
hops is right for a public well-known document — the address is re-pinned and the
scheme re-vetted on each. It is wrong for anything carrying a credential, so the
content fetch and the RPC legs take only the guarded `.Transport` and install
their own refusal: following a redirect either replays a proof bound to the old
URL, or hands a fresh proof of possession of the agent's key to whatever host the
first hop named.

The guard is driven by exactly two orthogonal env flags — `SKIP_SSRF` (drop the
dial-time address guard) and `ALLOW_INSECURE` (permit plaintext http) — both
defaulting to the guarded posture. The transport caps redirect depth at 5, caps
well-known/JWKS bodies at 1 MiB, and fails closed if **any** resolved address of a
host is reserved. The address/scheme decisions are corpus-locked
(`resolvers/testdata/ssrf-*-vectors.json`).

## Guarantees

- **Relocation, not rewrite.** The RFC 9421 / 7638 crypto is byte-identical with
  the service-internal implementations it replaces (ADR-020 §8).
- **Cross-field CEL is pinned** to `conformance/corpus/crossfield.json`, generated
  by the same protovalidate oracle the rest of the conformance suite uses.
- Covered by the repo gate: `go build/vet/test ./...` via `scripts/ci-local.sh`.
