# RAMP Design History

RAMP v1.0 is presented as a single, cleanly designed protocol, but several of its
shapes are the result of deliberate reversals during design. This document
records the *reasoning* behind the decisions that most shaped the wire format, so
that the absence of the alternatives is understood as intentional rather than
accidental. It is not a changelog — the per-revision wire-format detail lives in
git history.

## Request and hop authentication: RFC 9421, hop-by-hop

Early drafts carried authentication inside the protobuf messages: per-message
signature fields on requests, on each intermediary hop, and on catalog pushes. We
moved all request authentication to RFC 9421 HTTP Message Signatures
(`alg=ed25519`) and removed those fields. Two reasons drove this. First, signing
the HTTP request rather than a serialized body means the signature covers exactly
what the transport delivers — method, path, headers, content digest — and is
verifiable by standard middleware and edge functions without RAMP-specific
parsing. Second, multi-hop chains (Agent → Broker → … → Exchange) are the
expected common case, not an exception. RFC 9421 lets each hop add its own
`Signature` / `Signature-Input` entry independently, so a verifier checks each
hop against the key it fetches from that hop's `/.well-known/ramp.json` — there is
no nested in-message co-signing scheme to define or version. Content that must
outlive a single HTTP exchange — offers, attestations — keeps its signature as
JWS (RFC 7515, `alg=EdDSA`), because those objects are stored, forwarded, and
re-verified out of band.

Multi-hop forwarding rides on the same primitive rather than an in-message hop
list. A forwarded request carries a stack of RFC 9421 signatures — one per party
(the agent, then each broker), each covering the request and the previous hop's
signature — so the ordered set of signatures is the forwarding chain,
tamper-evident and order-bound, with no nested co-signing scheme or hop array to
define and version. `RequestConstraints.max_hops` and
`WellKnownManifest.max_intermediary_hops` let the agent and the Exchange,
respectively, publish a chain-depth tolerance, enforced by counting signatures.
Responses do not retrace the chain: the terminal Exchange returns directly to the
originating agent, because the signed `retrieval_endpoint` is already bound to the
agent's identity (`agent_identity_hash`) and needs no return-path relay.

## "Marketplace" → "Exchange"

The selling intermediary was originally called a *marketplace*. We renamed it to
*Exchange* throughout — service name, field names, enum values, and well-known
filenames. "Marketplace" overloaded a term that, in the surrounding ad-tech and
content-licensing world, implies a consumer-facing storefront and a particular
business model. RAMP's intermediary is closer to a financial or advertising
*exchange*: a neutral venue that matches buyers (agents and brokers) to priced
inventory, clears a transaction, and produces an auditable settlement record. The
narrower word sets the right expectation for implementers and avoids colliding
with publishers' existing "marketplace" products. With no external consumers at
the time, the rename was taken as a clean break rather than carried as an alias.

## One unified `WellKnownManifest`, not per-role manifests

Discovery initially used a different well-known document per role — a provider
manifest, an exchange manifest at `ramp-exchange.json`, an agent key file at
`ramp-agent.json`, a verifier file at `ramp-verifier.json`, plus a separate
`/marketplace/v1/keys` key endpoint. We collapsed all of them into a single
`WellKnownManifest` served at `/.well-known/ramp.json` by every participant,
role-tagged by a `role` enum. Every RAMP party already needs the same core thing
at the same path: a domain, its public keys, and a contact. Maintaining four
near-identical schemas and four fetch paths multiplied the discovery surface and
the failure modes — which file do you fetch for a party that is both a publisher
and an exchange? — without buying anything. A single document with
role-conditional fields means one fetch, one cache entry, one schema to evolve.
Verifiers, which had their own file, fold into whichever role their operating
domain holds; there is no separate verifier role.

## Inline keys instead of key-URI pointers

Relatedly, keys moved from a `keys_uri` / `jwks_uri` pointer pattern to inline
RFC 7517 JWK objects (`WellKnownManifest.public_keys`) carrying explicit
`not_before` / `not_after` bounds, with an optional `invalidation_url` for
emergency revocation. Inlining removes a second network fetch from every
verification path, and a second thing that can go stale or 404. The time bounds
let a verifier reason about key validity entirely from the one document it
already fetched, while the separate, short-TTL invalidation list keeps emergency
revocation fast without making the manifest itself uncacheable.

## CoMP as an extension; attestations instead of quality scores

Two earlier couplings were undone. The core protocol no longer imports IAB CoMP;
CoMP's Package/Function objects live in a `ramp-comp-v1` extension profile, and
IAB metadata rides optionally in `ext`. Tying every RAMP message to the full CoMP
object graph forced implementers who needed only pricing and transactions to
carry a large ad-tech schema; making it an extension keeps the core small and
lets domain semantics layer in through profiles (news, academic, legal, pharma,
medical imaging, C2PA). Separately, a free-form `ResourceQuality` score was
replaced by signed `ResourceAttestation` claims. "Quality" as an unsigned number
invited gaming and meant little across exchanges, whereas a cryptographically
signed claim from a named verifier is verifiable, attributable, and disputable
through the same dispute chain as the rest of the protocol.

## Universal Licensing Core

Licensing collapsed from several parallel, partly-overlapping shapes into one
`LicenseTerm` that carries `License`, `Restriction`, `Quota`, `Obligation`, and
`Pricing`, and appears with the *same shape* at both ends of the protocol —
`ResourceEntry.terms` at ingestion and `Offer.terms` at emission. A resource
carries zero or more terms; each term is one self-contained commercial/access
arrangement, and discovery projects one offer per term. The earlier
`AccessRestrictions` type, the `Offer.restrictions` projection, and `revshare`
pricing were removed, and `PricingModel` was narrowed to the charging
*structure* (`FREE` / `PER_UNIT` / `FLAT`) with the open-ended metering basis
("per what") moved to the `Pricing.unit` vocabulary axis. One model at both ends
means the bytes a publisher pushes are the bytes the agent verifies under the
offer signature, with no lossy ingestion→emission transform to reconcile.

Two shaping decisions are deliberate and worth recording because their
alternatives are conspicuously absent:

- **The licensing core is uniformly closed — no `ext` seam anywhere, including
  `Pricing`.** `License` / `Restriction` / `Quota` / `Obligation` /
  `LicenseTerm` / `Pricing` have no `ext` / `ext_critical` fields. Licensing
  semantics are the part of the contract that must mean the same thing to every
  participant and survive disputes; an open extension seam there would let any
  party introduce terms others cannot evaluate, which is exactly the ambiguity a
  license is supposed to remove. `Pricing` briefly carried an `ext` Struct
  (inherited from the CoMP/COSE lineage) and it was removed: an untyped blob in a
  signed, cross-exchange-comparable object quietly defeats the comparability that
  `unit_cost` exists to provide, and re-opens the unbounded-payload surface the
  vocabulary axes were closed to avoid. New dimensions — commercial or
  licensing — therefore arrive as typed fields or a vocabulary axis (where the
  value set is genuinely open), through a deliberate core change, not as
  per-deployment `ext` blobs. The general protocol `ext` / `ext_critical`
  mechanism still exists on transport/discovery messages (`Offer`, queries,
  disputes) where contextual, ignorable metadata is appropriate; it just has no
  place inside the license itself.

- **Restrictions are agent-selected, not Exchange-enforced.** Restrictions ride
  on the offer; the agent self-selects the term it can honour and bears
  compliance, with enforcement downstream at accept → report → reconcile. An
  Exchange or Broker MAY pre-filter offers as a convenience using attributes the
  requester volunteers, but that is advisory, never an enforcement gate. Putting
  the responsibility on the agent keeps the Exchange a neutral venue and avoids
  baking each requester's self-declared attributes into a trust boundary.

The full message-level specification and the membership/validation rules live in
ADR-014 (Universal Licensing Core) in the deployment repository; this entry
records only the wire-shaping reasoning.

## `license_id` → `billing_ref`: identity is the signature, not a field

`Requester` once carried a `license_id`, and the name implied that the value was
what entitled the requester to access — that holding the right `license_id`
granted the right resources. We renamed it `billing_ref` and recast it as an
opaque handle into the operator's billing system, nothing more. The rename
follows from a clean separation that the rest of the protocol already assumes:
*identity* is the RFC 9421 request signature (a verifier knows who is calling
because the request is signed by their key), and *entitlement* is scopes plus
delegation (what that identity is allowed to reach). A billing reference is
neither — it is a bookkeeping pointer the Exchange uses to attribute charges, and
treating it as an entitlement would have created a second, weaker authorization
path that a leaked or guessed string could ride. Calling the field `billing_ref`
makes its role unmistakable and removes the temptation to gate access on it.

## DenialReason consolidation

The denial enum carried separate `INVALID_LICENSE` and `EXPIRED_LICENSE`
reasons, and a `DELEGATION_EXPIRED` reason. Once `license_id` became
`billing_ref`, a denial that turns on the billing handle is not about a license
being malformed or expired — it is about the billing reference not being live.
Both former reasons collapse into a single `DENIAL_REASON_BILLING_REF_INACTIVE`:
from the requester's side the remedy is the same (their billing relationship is
not currently usable), and splitting the cause leaked the Exchange's internal
billing state without giving the caller a different action to take. Separately,
`DELEGATION_EXPIRED` was broadened to `DENIAL_REASON_DELEGATION_INVALID`, because
expiry is only one of several ways a delegation token can fail to authorize
(revoked, malformed, holder-binding mismatch, scope too narrow), and a single
reason avoids implying that re-issuing for time alone will fix it. The enum is
contiguous, with no gaps or reused numbers left by the removals.

## Delegation-claims profile: opaque token, bound holder

Delegation tokens stay opaque on the wire — RAMP does not parse or re-encode the
token, and `token_format` only names which verifier to run. But leaving the
*meaning* of a token entirely to each issuer made delegations non-portable: an
Exchange could verify a signature without agreeing on what the contained claims
asserted. We added a small registered claim/fact vocabulary that maps the same
named concepts across both supported formats (JWT registered claims ↔ Biscuit
facts), so a delegation expresses scope, expiry, and spend caps in terms every
RAMP verifier understands regardless of token format. Everything in the
vocabulary is optional with one exception: the subject/holder binding is
mandatory. The key that signs the RFC 9421 request MUST equal the holder key
named in the token. That single requirement is what stops a leaked token from
being bearer-usable — possession alone proves nothing, because the thief cannot
produce a request signature under the bound key. The vocabulary is
vendor-extensible through a `vendor:` namespace for issuer-specific facts, while
`ramp_`-prefixed names are reserved for future registered claims so a vendor
extension can never collide with one. Constraints are fail-closed by default: an
unrecognized or unverifiable binding constraint denies the request rather than
being skipped, unless the constraint is explicitly marked advisory — the same
binding-by-default posture the licensing restrictions take.

## Biscuit v3; JWT verification deferred

> **Superseded by "JWT (holder-of-key) is the default delegation token; Biscuit
> is optional" below.** This section records the earlier decision (Biscuit v3 as
> the v1 conformance format, JWT verification deferred). It was later reversed:
> JWT holder-of-key is now the default and Biscuit v3 is the optional profile.
> Retained for history; see the later section for the current model.

At the time of this (now-reversed) decision, the default delegation
`token_format` was moved from `biscuit-v2` to `"biscuit-v3"`, tracking the
Biscuit specification's own v3 revision, and Biscuit v3 was the format RAMP
implementations were expected to verify at v1. JWT was wire-permitted —
`token_format` accepted it and the claim vocabulary mapped onto JWT registered
claims — but its full verification path (proof-of-possession via `cnf`/DPoP, and
OIDC issuer discovery through to JWKS fetch) was deferred past v1. (This was
later reversed: see the current model below — **JWT holder-of-key is the
default**, and `biscuit-v3` is the optional alternative profile, never the
default.)

## One normative scope-matching algorithm

Scopes appear in two places — on the requester/delegation side (what an actor may
reach) and on `LicenseTerm.scopes` (what a term covers) — and earlier drafts left
the matching semantics implicit, which invited each implementation to choose its
own prefix or glob rules. v1 fixes one normative algorithm used identically
everywhere. A scope is segment-wise, `":"`-separated. A grant covers a
requirement only if, segment by segment, each granted segment either equals the
required segment or is `"*"`; a terminal `"*"` matches all remaining required
segments. There is no implicit prefix match — `a:b` does not cover `a:b:c` unless
it ends in `*` — and a grant narrower than the requirement never covers it.
Pinning the algorithm protocol-wide means a requester's scopes and a term's
scopes are compared by the same rule, so an actor either provably covers a term
or provably does not, with no venue-specific interpretation in between. The
Biscuit Datalog authorizer is treated as one conformant implementation of this
algorithm, not a separate semantics: it MUST produce identical results to the
normative rule.

## Revenue share stays off-protocol

CoMP's `License` carries a `revshare` rate next to `price`, and RAMP's
`PricingModel` was reduced to three charging structures (`FREE`, `PER_UNIT`,
`FLAT`), so the conspicuous question is whether RAMP should add a
`REVENUE_SHARE` model for parity. It does not, and the asymmetry is intentional.
A `PricingModel` is the structure an Exchange can quote, sign, and compare at
transaction time, each with a concrete `unit_cost`. A revenue share has no such
price: the rate and its reconciliation are an agreement struck off-protocol
between agent and publisher. Modelling it as an enum value would be either a
bare label with no rate (the agent still has to go ask "what share?") or, if a
rate field were added, would pull the commercial terms of that off-protocol
agreement into the signed, cross-exchange-comparable `Pricing` — the very thing
closing `Pricing` this cycle was meant to prevent, since it destroys price
comparability and asks the protocol to carry terms it never enforces.

The arrangement is already expressible with existing primitives, and identically
to a subscription: a `Pricing{model: FREE}` term gated by an agreement scope
(e.g. `revshare:publisher-x`) plus a `ReportingObligation`. The agent that
signed the deal holds a delegation carrying the matching scope, accesses at zero
marginal cost, and reports usage; revenue is settled off-protocol from those
reports. "Pay per crawl or take the revenue-share deal" is then just two
`LicenseTerm`s on one resource, and the agent self-selects. CoMP parity is kept
by mapping rather than duplication: a CoMP `revshare` rate rides through verbatim
in the `ramp-comp-v1` ext (`comp.license[].revshare`), full fidelity for
CoMP-aware parties and ignored by everyone else, while RAMP core stays
minimal and its signed offers stay price-comparable.

## JWT (holder-of-key) is the default delegation token; Biscuit is optional

> **Biscuit removed pre-v1; superseded by JWT.** This section records the
> transition from Biscuit-default to JWT-default. The optional `biscuit-v3`
> profile it leaves in place was itself dropped before v1 shipped: JWT is now the
> sole delegation `token_format`, and the entitlement *mechanism* (a
> holder-bound capability token on a covered header) is unchanged — only the
> Biscuit format is gone. Read the "still optional" language below as historical.

The delegation token started as a Biscuit (`token_format` defaulted to
`"biscuit-v3"`), chosen for offline attenuation. Modelling the holder-binding
guarantee end to end surfaced that the property RAMP actually depends on — "a
leaked token is not bearer-usable" — is proof-of-possession, not anything
specific to Biscuit: it is the request-signing key matching a key named in the
token, verified offline. A chain of `cnf`-bound JWTs delivers exactly that — the
authority JWT (issuer-signed) names the principal's key in `cnf`; the principal
issues a child JWT naming the agent's key and narrowing scope; the agent proves
possession with its RFC 9421 request signature; the verifier walks the chain
offline under the issuer's key alone (intermediate keys ride in the JOSE header
`jwk`). The chain-linkage invariant (each token signed by the key its parent
named) gives the same theft- and escalation-resistance as Biscuit's block chain.

What Biscuit adds beyond this — in-token Datalog and deep in-place attenuation by
mutually-distrusting intermediaries — RAMP does not use: the check set is fixed
(scope coverage, expiry, caps, holder binding) and delegation chains are shallow.
So `token_format` now defaults to `"jwt"`, and JWT is the one delegation
technology a conformant implementation must support. `"biscuit-v3"` stays a
permitted optional profile for deployments that genuinely want deep offline
attenuation. The win is adoption: JWT is ubiquitous, so RAMP asks implementers to
take on no genuinely new token technology by default.

## Failure as a typed contract: `ErrorDetail`, not strings

The success side of the protocol was a single validated contract — typed
messages, protovalidate CEL at the boundary — while the failure side was not. The
same failure was named in incompatible ways across implementations: a hand-rolled
Go `Kind` enum in the Exchange (with a seven-mode entitlement family that all
collapsed to `UNAUTHENTICATED` on the wire, distinguishable only by a server-side
tag), a separate `Kind` enum in the Broker, free-text reason strings on the
catalog path, a database denial enum whose values did not match the proto's own
`DenialReason`, and a lowercase token union in the edge worker. A client could
not read a failure as one validated, machine-readable value; the reason for a
failure was expressed differently in Go, TypeScript, and Python, and the error
shapes lived in code rather than in the contract.

We made failure a single contract. The transport carries a coarse canonical code
(gRPC / Connect `Code`) as the error *class*; a typed `ErrorDetail` message,
attached to the transport error's details the same way protovalidate attaches its
violations, carries the precise machine-readable *reason* (a typed enum) plus
structured context. Clients branch on the typed reason, never on a human string.
The per-domain reason enums (`TransactionDenial` reusing `DenialReason`,
`CatalogRejection`, `RegistrationFailure`, `DisputeFailure`,
`DomainVerificationFailure`, `RetrievalAuthFailure`, `UsageReportRejection`) are
the single source of truth that the hand-rolled vocabularies collapse onto: the
database stores the proto reason, the per-service Go error types shrink to mapping
a domain failure to a transport code only, and the edge token union becomes a
generated enum.

We chose closed, typed enums over the open `reason` string of
`google.rpc.ErrorInfo`. Google uses a string because its API surface is enormous
and federated; ours is a handful of RPCs we fully control, and the entire goal is
compile-time conformance across Go, TypeScript, and Python — which a closed enum
delivers and a string would surrender. `ErrorDetail` still carries an
ErrorInfo-compatible `domain` + `metadata` for generic tooling, but the
authoritative reason is the enum. We kept the wrapper (`ErrorDetail` with a
`oneof`) rather than attaching bare detail messages to the transport error,
because one carrier message means uniform client code: there is exactly one type
to look for.

## A failed action is not a success body

The corollary decision is where a failure lives. The rule is the gRPC / AIP-193
one: a method that could not perform the requested *action* returns a non-OK code
plus an `ErrorDetail`; a *query* that ran successfully returns its answer in the
body, and "no results" is a successful answer, not an error. So discovery keeps
its in-body `OfferGroup.absence_reason` (the query succeeded; there were simply no
offers), and a denied *single* transaction, a rejected usage report, a refused
dispute filing, and a failed domain verification all became transport errors
carrying the typed reason — the in-body `bool accepted` / `verified` flags and
`rejection_reason` / `failure_reason` strings were removed. Batch transactions are
the deliberate exception: a batch is a successful call whose per-item
`TransactionResultItem` may carry a denial reason in-body, exactly like discovery
absence, because the partial results *are* the successful answer. The effect is
that success bodies now carry only the payload-when-it-worked.

## One response envelope; correlation by header

With the failure fields gone, the response messages were standardized. Every RPC
request and response now carries `ver` at field 1 — version belongs on every
message, consistently positioned — and the external-contract messages all carry
`ext` / `ext_critical` so any of them is forward-extensible. This includes the
resource-bearing catalog messages `PushResourcesRequest`/`PushResourcesResponse`:
a publisher pushes protocol-specific extension fields (e.g. CoMP members not
already projected from the licensing data) through `ext`/`ext_critical` so they
surface on the resulting offer. The purely-administrative catalog messages
(`RemoveResources*`, `RefreshCatalog*`) carry `ver` only — they move no resource
payload, so extension slots there would be noise.

Correlation, by contrast, was removed from the proto entirely. Earlier drafts
carried a `request_id` ("originating RAMP request id, for traceability") on
several requests and echoed it on responses — but it was dead weight: the
implementations never read or wrote it. Correlation already flows the way
signatures do, over the transport — an `X-Request-ID` header, minted or
propagated by shared middleware in the broker, exchange, and edge, and bound to a
request-scoped logger. By the same reasoning that moved signatures to RFC 9421 (a
value the proxies, edge functions, and tracing systems read without parsing
protobuf belongs on the transport), a correlation id has no place in the message
body. So every `request_id` field was deleted; per-hop and cross-system
correlation ride on `X-Request-ID` — and, when distributed tracing is added, the
W3C Trace Context `traceparent` / `tracestate` headers, which are the ecosystem
standard rather than anything RAMP would hand-roll. The proto keeps only the
identifiers that are *acted on* or *persisted*: the settlement and evidence keys
(`transaction_id`, `billing_id`, `report_id`, `dispute_id`) the Exchange assigns
and the reconciliation chain joins on.

## Idempotency is an explicit `idempotency_key`, not an overloaded `id`

Idempotency is the mirror image of correlation, and the contrast is the point. A
correlation id is ephemeral observability and lives in a header; an idempotency
key is persisted, settlement-bound state the server *acts on* — the Exchange
dedupes on it, stores it under a `UNIQUE` constraint, and threads it into the
billing adapter so a replayed request cannot double-charge. By the rule that
governs the whole wire format — what must outlive the HTTP exchange and survive a
dispute stays a typed field — the idempotency key belongs in the message body,
not a header. (This is where RAMP diverges from Stripe's header-based key: RAMP's
key is part of the signed, persisted, reconciled record, not a transport hint.)

The mutating requests had been carrying this as a generically-named `id` — with
`TransactionRequest.id` the only one a server actually deduped on, and
`UsageReport.id` an unwired intention. We renamed it to `idempotency_key` and made
it required on the state-mutating RPCs (`ExecuteTransaction`, `ReportUsage`,
`DisputeTransaction`), so the contract names the guarantee for what it is: the
server MUST return the original result on replay rather than re-executing. The
request needs no separate own-id, because the durable identity of what it creates
is the Exchange-assigned id in the response (`transaction_id`, `report_id`,
`dispute_id`). Queries take no key — neither `DiscoverResources` nor the Broker's
`Resolve`, which is pure discovery (it returns offers, executes no transaction,
so retrying is naturally safe) — and the naturally-idempotent catalog
upsert/delete and onboarding calls are left out deliberately — a key there would
be ceremony, not a guarantee. The field is
declared in the contract ahead of full enforcement: the Exchange dedupes
`ExecuteTransaction` today, and the remaining RPCs adopt the same check as the
implementation catches up to the contract — the proto leads, the services follow.

## Docs are rendered from the proto descriptor, not hand-written or regex-parsed

The documentation site derives everything it says about the contract from the
**compiler's descriptor**, in one TypeScript pipeline — no hand-typed tables, no
`.proto` text parsing, no reimplemented utilities.

**Why the descriptor.** Protobuf is self-describing: `buf build -o gen/descriptor.binpb`
emits a `FileDescriptorSet` — the schema as data — carrying every message, field,
enum, service, the custom options (`buf.validate` CEL, `(ramp.v1.vocab)`), and, with
source info, the comments (`SourceCodeInfo`). It is the same artifact every code
generator consumes, and it is complete and language-neutral. Crucially it is NOT the
generated `gen/ts` runtime (which lacks protovalidate and strips comments) — we read
the descriptor as data via `@bufbuild/protobuf` as a codec, so `gen/ts`'s
incompleteness never enters the docs pipeline.

**The pipeline.**
- `gen/descriptor.binpb` is a committed, drift-gated generated artifact (Amplify reads
  the file; no `buf` at docs-build time).
- One TS module reads it (`@bufbuild/protobuf`) and exposes enums/values with comments
  (path-matched from `SourceCodeInfo`) and the vocab options.
- A remark plugin injects enum/vocab tables as **mdast** and autolinks proto-symbol
  references across prose *and* the generated table cells in a single pass, using
  `github-slugger` (exactly Starlight's heading-id slugger) for anchors.
  `starlight-links-validator` validates the result. Rendering and linking are one
  pipeline, so a symbol named in a proto comment is rendered AND linked automatically.

**Descriptions live in the proto.** An enum value's description is its proto comment —
the single source — rendered to the table. To change a description, edit the proto.

**Superseded approach (removed).** The earlier Go tooling — `cmd/symbolsjson`
(descriptor walk + regex enum-comment parse + a hand-rolled `slugify`) and
`cmd/vocabjson` (emitting a vocab JSON view from `gen/go/vocab`) — was a wrong-tradeoff
detour: it optimized for "Go-only, reuse the vocab Go packages" and so reimplemented a
slugger that already exists (`github-slugger`), parsed a compiled format with regex
instead of reading the descriptor, and rendered tables as opaque Astro components the
autolink pass could not see into. All of it is deleted. `protoc-gen-rampvocab` and
`gen/go/vocab` stay — they are a real Go-SDK surface the conformance suite uses
(`pricingunits.IsRegistered`).

## SDK layering: a dependency-free trust core, a vetted-client I/O tier

The three SDKs (`sdk/go`, `sdk/ts`, `sdk/python`) are split into a **pure trust
core** and a separate **I/O tier**, and the two obey opposite dependency rules. The
core — the RFC 9421 / 7638 crypto, JCS canonicalization, offer/acceptance verify, and
the transport-neutral `core` composition — imposes **nothing** beyond the platform
standard library, a vetted crypto primitive, and a vetted JCS/canonicalization
library. It takes no HTTP client and does not dial the network: `sdk/go/helpers`
never constructs an `http.Client`, `sdk/ts/core` imports neither `undici` nor a
framework, and `ramp_sdk.core` imports no `httpx`. The I/O tier — `sdk/{go,ts,python}/resolvers`
— is the *only* place a network fetch lives (well-known JWKS, WBA directory,
`ramp.json` endpoint, offer-key resolution), and there the rule inverts: it runs on a
**maintained HTTP client** (Go `net/http`, TS `undici`, Python `httpx`) rather than a
hand-rolled transport, because the client owns the response state machine (status,
redirects, 1xx, decompression) and the SDK should own only the SSRF check it injects
as a connection-level hook.

The reasoning is a threat boundary, not an aesthetic one. The host a resolver fetches
is caller-supplied and reached **before** any signature is checked, so the fetch
surface is pre-auth-reachable network I/O — exactly the surface an attacker probes for
SSRF. Keeping every dial in one tier, behind one SSRF-guarded client, means the pure
verification code an edge worker or a broker links can never be tricked into dialing:
there is no client in it to trick. The split is enforced structurally by an **io-leaf
guard** in each SDK that fails the build if a core/pure file names a dialing surface
(`http.Client`, `net.Dial`, an `httpx`/`undici` import), so the maintained-client
dependency cannot leak back down into the trust core.

This is the resolution of an earlier terminology overload. The `core` package was once
described as "L2 CORE [that] must impose NOTHING … NO httpx", while the resolvers tier
— which legitimately *does* use `httpx`/`undici`/`net/http` — was *also* called "L2".
Read literally the two statements contradict; the fix is to name the split by kind
rather than by a single "L2" number: the **trust core** (pure, dependency-minimal, no
dial) and the **I/O resolvers tier** (vetted maintained client, SSRF-guarded) are
distinct tiers with opposite dependency policies, and "no httpx" is a property of the
core alone, never of the whole SDK above L1.

## SSRF-guarded fetch: two flags, a corpus-locked transport

Every third-party-influenceable fetch across all three SDKs runs through **one**
env-driven guarded client (`NewGuardedClientFromEnv` in Go, `guarded_client` in
Python, `guardedFetchFromEnv` in TS), whose behavior is governed by exactly two
orthogonal environment flags and nothing else — no deployment allow-list, no config
file, no per-stack policy. `SKIP_SSRF` toggles the dial-time **address** guard (default
off: reserved / non-public addresses are refused); `ALLOW_INSECURE` toggles the
**scheme** guard (default off: https only). An operator opts out of a guard by setting
its flag; the production default is both guards on.

The transport policy is fixed and identical in all three languages: redirect depth is
capped at **5** hops, well-known/JWKS response bodies are capped at **1 MiB**, and a
host resolving to multiple addresses **fails closed if any** resolved address is
reserved (never "the first address looked fine"). Python additionally imposes an
overall wall-clock deadline on one guarded GET, because `httpx`'s timeout is per-phase
and a hostile `getaddrinfo` could otherwise stall past every per-phase budget. The two
parts of the guard that are expressible as data — reserved-address classification and
the deny-by-default scheme allowlist — are **corpus-locked** to shared vectors
(`sdk/go/resolvers/testdata/ssrf-address-vectors.json`, `ssrf-scheme-vectors.json`,
`ssrf-hostset-vectors.json`, `ssrf-redirect-vectors.json`) that all three SDKs replay;
the residual wiring (that the guard is actually applied on each redirect hop and that a
non-2xx surfaces as a status rather than a crash) is covered behaviorally per language.

## Active-key selection: deterministic, non-normative, unbounded by default

The WBA directory can carry several simultaneously window-active signing keys during an
overlap rotation, and the protocol defines no "current" key among them. The SDK offers
a document-order selector (`ActiveEd25519Key` and its `…WithExpiry` / `…Screened`
variants) that returns the **first window-active key in document order** — a purely
deterministic tie-break, explicitly **not** a claim about which key is canonical.
Callers must not read normative meaning into the choice. Three conventions are
deliberate and shared byte-for-byte across the SDKs: the scan is **unbounded by
default** (a silent cap would make a valid key at a high document position permanently
unselectable *and* indistinguishable from "no active key" — a directory-padding
footgun — so a bound is opt-in via `MaxScan`, and an exhausted explicit bound is
**logged**); the `kty`/`crv` match ("OKP" / "Ed25519") is **case-insensitive** even
though RFC 7517/8037 specify exact case, so a case-varying directory resolves the same
key everywhere; and the bare selector screens *only* validity windows, so a
verification-path caller must use the revocation-aware `…Screened` form (or screen the
selected thumbprint themselves) — an emergency-revoked but still window-active key
would otherwise be selected.

## `ErrorDetail` is decoded cross-language, not just emitted

The typed `ErrorDetail` failure contract (see "Failure as a typed contract" above) is
now **read** in every SDK, not only produced by the Go server. The Go server binding
attaches a typed detail to a Connect error (`AttachErrorDetail` / `AttachDetail`), and
Python and TS ship symmetric **decoders** (`parse_error_detail` / `error_detail_from`;
`parseErrorDetail` / `errorDetailFrom`) so a TS or Python client branches on the typed
reason enum a Go exchange emitted, never on a human string. Emit and decode are pinned
to one shared oracle corpus (`error-detail-vectors.json`) replayed by all three
languages, so the typed-failure contract is verified end-to-end across the language
boundary rather than trusted to match by inspection.
