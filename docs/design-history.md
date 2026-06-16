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

Three small v1.0 fields finish this story. `IntermediaryHop.signature_label`
binds a hop to the specific RFC 9421 signature label it added, so a verifier
matches a hop to its signature directly instead of inferring by ordinal position
or domain. `RequestConstraints.max_hops` and
`WellKnownManifest.max_intermediary_hops` let the agent and the Exchange,
respectively, publish a chain-depth tolerance. Responses do not retrace the
chain: the terminal Exchange returns directly to the originating agent, because
the signed `retrieval_endpoint` is already bound to the agent's identity
(`agent_identity_hash`) and needs no return-path relay.

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
