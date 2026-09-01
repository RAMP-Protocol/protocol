# RAMP SDK — Go

Layered protocol libraries co-located with the contract (ADR-020). The SDK is
consumed off-commit from this repo; it imports the generated L0 wire types
directly with no `replace` directive.

| Layer | Package | What it is |
|---|---|---|
| **L0** | `gen/go/ramp/v1`, `gen/go/vocab/*` | generated wire types (consumed, never rebuilt) |
| **L1** | **`sdk/go/helpers`** | stateless, **IO-free** protocol helpers — RFC 9421/7638 crypto, offer/acceptance verify, static key resolution, validation |
| L2 · I/O | **`sdk/go/resolvers`** | the network-fetching tier: well-known JWKS / WBA directory / `ramp.json` endpoint / offer-key resolvers + the SSRF-guarded HTTP client. Runs on a maintained `net/http` client behind the SSRF guard; composes L1, never the reverse |
| L2 · transport | `sdk/go/core` (transport-neutral: Verifier, {verified,rejected}, `DiscoveryResult` per-URI groups, VerifiedOffer guard, signing RoundTripper, ReplayStore — zero Connect) · `sdk/go/connect` (Connect **client** binding: `NewClient` + `NewBrokerClient` + `NewCatalogClient`; the agent verbs **`Discover` · `Resolve` · `Execute` · `ReportUsage` · `Dispute` · `Fetch`** and the publisher verbs **`PushResources` · `RemoveResources` · `RefreshCatalog`** + client options + the `CallError` taxonomy + `ErrorDetailFrom`) · `sdk/go/connectserver` (Connect **server** binding: `NewExchangeServiceHandler` + `NewBrokerServiceHandler` + `NewCatalogServiceHandler` + server options + `AsConnectError` + `AttachErrorDetail`/`AttachDetail` + the reject answer **`RejectCode` · `IsBodyTooLarge` · `WriteReject`**, the one place the 413/429/401 split and the error-envelope body are decided) | transport-neutral core + Connect client/server bindings (state injected) |
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

**License-term pre-check** — the two tiers an Exchange applies to a pushed entry,
runnable by a publisher before signing: the wire rules over the entry as given, then
canonicalisation (RFC 8259 trim, ASCII-only fold, alias resolution through the generated
vocabulary) and registry membership over a copy of its terms. Warning messages are the
exact `PushResourcesResponse.warnings` strings; rule ids share the CEL-id namespace:

```go
verdict := helpers.ValidateResourceEntry(entry)   // never modifies entry
for _, v := range verdict.Violations { log.Println(v.Rule, v.Path, v.Message) }
helpers.NormalizeResourceEntry(entry)             // the form the Exchange stores
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
Exchange? The signature does not already answer that: it proves the sender signed
*the URL it dialled*, and that URL came out of a fetched, cached `ramp.json`, so a
poisoned resolution redirects the request while every signature still verifies.
The body field says whom the sender meant. The check is pure, so it runs before
any lookup:

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

`cfg.ExchangeDomain` is the domain this Exchange publishes as its **identity** —
the value it stamps into the offers it issues — never the host the process listens
on. The two may differ: an Exchange at `exchange.example` may serve its API from
`api.exchange.example`. Configure it from the listening host and every correctly
addressed request is refused, so a *global* mismatch storm means check your own
identity before suspecting callers; the check is pure and cannot detect this for
you.

The match is EXACT — a subdomain is a different party — which is narrower than
the endpoint rule above, where a manifest MAY advertise a subdomain of itself. The
shape both sides admit is `helpers.IsBareDomain`, whose `BareDomainPattern` is byte
for byte the protovalidate pattern the contract's recipient-addressing fields carry,
held there by a conformance guard. Reach for it wherever you vet a domain that
arrived in a message; note that the client's own send path still vets with the wider
`IsBareHost`, so passing that one is not yet evidence the wire will accept a value.

**Registration schema** — an Exchange MAY publish a JSON Schema for the
`registration_data` it expects. Both ends of a registration validate against it, so
the rules live here once: 2020-12 only, same-document `$ref` only and no reference
cycles, 16KB, 32 containers, 10,000 evaluations of work, and a `pattern` alphabet all
three SDK languages express identically. `raw` is the schema's bytes **as served** in
`ramp.json` — the size cap is defined over those:

```go
schema, verdict := helpers.CompileRegistrationSchema(raw)
if verdict != helpers.SchemaAccepted {
    // "wrong_dialect" | "remote_ref" | "too_large" | "too_deep" | "unsafe_pattern" | ...
}
```

The two callers read a non-accepted verdict differently, and getting it backwards is
the easy mistake. A **client** pre-checking a payload skips the check and sends
anyway — the Exchange's enforcement decides, and a local check that cannot run must
not become a local veto against your own user. An **Exchange** compiling its OWN
configured schema treats anything but `SchemaAccepted` or `SchemaNotPublished` as a
misconfigured deployment, and must not advertise a schema it is not enforcing.

**Do not discard the verdict.** A nil `*RegistrationSchema` reports no failures,
because "no schema" means "nothing to enforce" — which is right for
`SchemaNotPublished` and right for a client that could not check locally. It is also
what you hold after every refusal, so an Exchange that drops the verdict enforces
nothing and cannot tell. The verdict is the only thing that separates the two cases:

```go
fieldErrors := schema.Validate(req.GetRegistrationData().AsMap())
if len(fieldErrors) > 0 {
    return helpers.RegistrationFailureDetail(domain, "registration_data does not conform",
        rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
        fieldErrors...)
}
```

Each entry is an RFC 6901 pointer relative to `registration_data` (`""` addresses the
whole object) plus the violated constraint. The text states the constraint and
**never the submitted value** — registration data is an operator's business data and a
refusal travels back over the wire, so the validating library's own messages, which
quote the failing value, are deliberately not used. The list is deduplicated by
pointer and keyword and sorted before the 64-item cap, so the same entries survive in
every language.

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
- **The host rule does not depend on how the consumer is configured.** `net/url`'s
  host-colon strictness is the `urlstrictcolons` GODEBUG, and a GODEBUG is the
  consumer's to set: under `urlstrictcolons=0` — from the environment or a
  `//go:debug` line — `url.Parse` accepts `exchange.example::443` and six near
  relatives the committed vectors record refused. `helpers.parseRef` therefore
  refuses a second colon after the host itself, and the guard asserts that through
  the predicate rather than through `url.Parse`, so it means the same thing under
  either setting. (The setting's *default* is not the reachable path: it derives from
  the main module's `go` directive, and a main module cannot declare below this
  module's 1.26 — the build is refused first.)
