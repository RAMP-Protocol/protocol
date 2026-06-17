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
reason avoids implying that re-issuing for time alone will fix it. The enum is a
contiguous 0–11 with no gaps left by the removals.

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

The default delegation `token_format` moved from `biscuit-v2` to `"biscuit-v3"`,
tracking the Biscuit specification's own v3 revision, and Biscuit v3 is the
format RAMP implementations are expected to verify at v1. JWT remains
wire-permitted — `token_format` accepts it and the claim vocabulary maps onto JWT
registered claims — but its full verification path (proof-of-possession via
`cnf`/DPoP, and OIDC issuer discovery through to JWKS fetch) is deferred past v1.
Permitting the format now without mandating the heavier verification machinery
lets deployments that already speak JWT carry tokens on the wire, while keeping
the v1 conformance surface to the one format (Biscuit v3) whose offline,
self-contained verification matches RAMP's no-extra-fetch posture.

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
