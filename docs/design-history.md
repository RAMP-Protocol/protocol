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

## Canonical signing: JCS over proto-JSON, not deterministic protobuf

The two signed RAMP payloads that cover a protobuf message — `Offer.signature` and
the agent's `AgentAcceptance.signature` — originally covered deterministic protobuf
*binary*: marshal the message with deterministic field order, sign those bytes. We
reversed that and moved both onto RFC 8785 JCS over canonical proto-JSON,
`JCS(protojson(msg with the signature fields cleared))`, under one pinned
proto-JSON option set (snake_case field names, enums as name strings, unpopulated
fields omitted). (`ResourceAttestation.signature` also outlives an HTTP exchange but
is out of scope here: it signs a hand-built JSON object — `{verifier, keyid,
attested_at, uri, claims}` — under its own rule, never a rendering of its proto
message.)

Deterministic protobuf marshaling is not actually canonical. Protobuf's own
documentation disclaims byte stability across languages, across library versions,
and in the presence of unknown fields — it is a best-effort local property, not a
wire-format guarantee. That makes it unusable as the basis of a signature two
independent implementations must agree on, which is precisely the RAMP case: an
agent SDK signs, a broker relays, an Exchange verifies, and none of them need share
a language. It also forces every verifier — including an edge worker or a browser
client — to link a protobuf binary codec just to check a signature. JCS over
proto-JSON has neither problem: it is a published canonicalization of JSON, and any
language can reproduce the signed bytes from the JSON rendering alone. The
Go-emitted golden vector is the arbiter, and the TS and Python SDKs replay it
byte-for-byte.

The form then changed a **second** time, within JCS. The first cut rendered
proto-JSON with its default camelCase `json_name` keys; we re-pinned it to
snake_case proto field names (`UseProtoNames=true`) so the wire, the conformance
corpus, the generated Pydantic/Zod clients, and the signed form all share one
naming — protojson accepts both spellings on input, so the duality was silently
hiding client divergence rather than absorbing it. That re-pin **re-signed the
golden vectors**: signatures produced over the camelCase-JCS form no longer verify,
and all three SDKs had to move in the same commit.

One clause of that pinned option set carries more weight than it looks.
`EmitUnpopulated=false` means an empty field is *absent* from the JSON, not present
with an empty value — so the canonical bytes for an empty string field are never the
bytes for a populated one. Go inherits that from `protojson` for free. A port that
assembles the JSON object by hand does not, and has to enumerate the omission for
every field or it signs bytes Go never produces. The acceptance payload is the one
place the Python and TS ports hand-build the object — Go renders the
`AgentAcceptancePayload` message through the same protojson canonicalizer as the
offer — and it is exactly where the divergence
appeared: Python and TS dropped an empty `requester_domain` but emitted an empty
`requester_id`, which is wire-valid because `Requester.id` carries no `min_len`. Such
a mismatch fails closed, but it falsifies the byte-equivalence the canonical-bytes
accessors promise, so the shared corpus now carries a vector that holds every port to
the omission.

The two reversals left a consequence worth naming, because it is the reason the
canonical bytes are a first-class SDK export rather than an internal detail. A
canonical form that has already changed twice can change again, and a verifier that
re-derives the bytes at verification time has silently pinned an *already-signed*
payload to whatever canonicalization the SDK implements *later* — the failure would
surface as "the signature does not verify", indistinguishable from "it was never
signed". So all three SDKs expose the exact signed bytes as a public accessor
(`CanonicalOfferBytes` / `CanonicalAcceptanceBytes` in Go, `canonical_offer_payload`
/ `jcs_acceptance_payload` in Python, `canonicalOfferPayload` / `acceptancePayload`
in TS). A party keeping evidence stores those bytes and re-verifies against them
verbatim, rather than trusting a future canonicalizer to reproduce the past.

Storing them is necessary, not sufficient. A signature that verifies over stored bytes
proves only that the holder of that key signed *those bytes*; it says nothing about
which transaction they belong to. Whoever reads the evidence must also parse the stored
bytes and match their content — offer id, requester, idempotency key — against the
transaction under dispute. Skip that and any valid triple minted under the same key
passes as evidence for any transaction.

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

> **Superseded — the renamed field was later removed outright:**
> after the Broker cost guard moved to the authenticated agent identity,
> nothing read `Requester.billing_ref`, and the caller-written
> label collided by name with the authoritative account handle minted at
> `Register`. The field was deleted outright — pre-v1, removed field numbers
> return to the free pool rather than being `reserved`. The reasoning below
> still stands — it is the same separation (identity = signature,
> entitlement = scopes/delegation) taken one step further: billing needs no
> request field at all.

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

Every third-party-influenceable fetch across all three SDKs runs through a guarded
client governed by exactly two orthogonal environment flags and nothing else — no
deployment allow-list, no config file, no per-stack policy. `SKIP_SSRF` toggles the
dial-time **address** guard (default off: reserved / non-public addresses are
refused); `ALLOW_INSECURE` toggles the **scheme** guard (default off: https only).
An operator opts out of a guard by setting its flag; the production default is both
guards on.

Most fetches take that policy from the shared factory — `NewGuardedClientFromEnv`
in Go, `guarded_client` in Python, `guardedFetchFromEnv` in TS. The **WBA directory
fetch is the exception, and is deliberately stricter**: its host arrives in an
unauthenticated header and the GET runs *before* the signature is checked, so its
address guard is **not** opt-outable — `SKIP_SSRF` does not reach it. It honours
`ALLOW_INSECURE` for the scheme like everything else. A caller injecting its own
client into the resolver replaces that transport entirely and owns both policies
from then on, which is how the SDK's own tests reach loopback origins.

That asymmetry was not the original state, and the gap ran the other way. The
directory client was written before the scheme guard existed, and the change that
introduced the guard shared the address classifier with this resolver while leaving
the scheme policy behind — so for a period this section described a posture the most
exposed fetch in the SDK did not have. The lesson generalises: a guard introduced
after its callers has to be walked back through them, and a sentence beginning
"every fetch" is the easiest kind of claim to leave standing once it stops being
true.

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

## Discovery answers are grouped per URI, not flattened

A discovery call is per-URI: an agent asks about several resources at once, and both
`DiscoverResources` and the Broker's `Resolve` answer with one `OfferGroup` per
requested URI, each either carrying offers or carrying a typed `OfferAbsenceReason`
explaining why it carries none. The SDK returns that shape rather than a flat list,
with the fail-closed `{verified, rejected}` split preserved **inside** each group and
produced by the one `Verifier` — never a second verification path.

Flattening loses two things, and the second is unrecoverable. It drops the
attribution — which offer answers which URI — and it erases a REFUSED URI entirely,
because an empty group has no offer to carry its identity back. That matters because
the absence vocabulary is a set of different actions: `NOT_IN_CATALOG` means give up,
`SCOPE_INSUFFICIENT` means acquire an entitlement and retry, `CONTENT_BLOCKED` means
never retry. Flattened, all three read as "found nothing", which is the trial-and-error
the field exists to prevent.

Two consequences worth stating. The absence reasons are carried as POINTERS, because a
responder may legitimately withhold a reason where the existence of a resource must
itself stay hidden — so "absent" and "unspecified" have to stay distinguishable, and a
generated getter collapses them. And `ResourceResponse` carries a grouped list *and* a
flat one, with the flat one a single-URI convenience mirror; the two are read as
alternatives, never concatenated, because a responder that populates both would
otherwise have every offer counted twice.

## A signed leg refuses redirects; the guarded fetch follows them

The SSRF-guarded HTTP client follows up to five redirects, re-pinning the address and
re-vetting the scheme at each hop. That is correct for what it was built for: fetching
public well-known documents and key directories, where there is nothing to leak.

It is wrong for any request carrying a credential. A usage report, a dispute and a
delivery fetch all take only the guarded `.Transport` and install their own refusal.
For the RPC legs, following a redirect would re-sign the caller's request for a target
the peer chose — after the endpoint check had already passed, which is precisely the
window that check exists to close. For the delivery fetch it is worse: the proof of
possession covers `@target-uri`, so replaying it at a new location fails the edge's own
check, and re-signing per hop would hand a fresh proof of possession of the agent's key
to whatever host the first hop named. Redirect support on those legs would need per-hop
re-signing plus host anchoring, and is deliberately not attempted.

The transport error is rebuilt before it surfaces, because the HTTP client wraps every
failure in a value carrying the full URL it was dialing — query included. On a refused
redirect that is a credential belonging to a URL the *first hop* chose, so the wrapper
leaks even when the SDK's own message is already redacted.

## A usage report's destination comes off the message, not from configuration

A usage report must reach the Exchange that ISSUED the offer, and that Exchange's
address is read from its own `/.well-known/ramp.json` — never from configuration. A
signature covers the `exchange` DOMAIN; it says nothing about where that domain's
endpoint lives or where its DNS points.

The SDK takes the domain off `UsageReport.exchange` rather than as an argument, and
offers no option to supply an endpoint. Leaving no configuration slot for it is what
makes the rule structural instead of a convention someone can quietly reverse: there is
no parameter a configured origin could be passed as. (`Dispute` is the exception, and
only because `DisputeRequest` carries no `exchange` field to read — it takes the domain
as an argument and runs the identical checks.)

Five checks precede the send, in order: refuse anything that is not a plain hostname,
because the value is concatenated into a URL and a smuggled path would choose what gets
fetched; resolve the endpoint from that host's own manifest, cached per host; require
the endpoint to be that host or a subdomain of it, since the manifest is only as
trustworthy as the host serving it and a dial-time address guard has no objection to an
unrelated PUBLIC host; dial through the SSRF guard, applied to the report itself and
not only to the manifest fetch; and refuse redirects. The per-origin client pool that
follows is bounded and evicts least-recently-used, because which Exchanges appear is
driven by incoming offers — an open-ended, caller-influenced key space.
