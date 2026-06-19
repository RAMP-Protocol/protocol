# RAMP Protocol Changelog

## Unreleased

**CoMP re-baseline to canonical V1 (breaking).** `proto/comp/v1/comp.proto` is
re-aligned to be a 1:1 mirror of IAB Tech Lab Content Monetization Protocols
**CoMP V1** (finalized 2026-04-28,
[`CoMP-1.0.md`](https://github.com/IABTechLab/CoMP/blob/main/CoMP-1.0.md)). Our
prior snapshot mirrored a pre-final draft. Changes:

- **Removed** the `License` message, the `LicenseUse` enum, and `Package.license`
  — canonical V1 has no separate `License` object.
- **Folded licensing into `Scope`**: added `ause` (new `AllowedUse` enum),
  `pricetype` (new `PriceType` enum), `pricetier`, `unitprice`, `cur`
  (default `"USD"`), `country` (`repeated int32`, ISO-3166 numeric), and
  `licensedur` (days).
- **Added** `Package.reporturl` (usage-reporting URL).
- **Added** per-media taxonomy fields `cattax` (default 9), `cat`
  (`repeated int32`), and `language` (`repeated int32`, ISO-639-1) to `Text`,
  `Video`, `Image`, and `Audio`.
- **Removed** the RAMP-invented fields that were not part of canonical CoMP:
  `Text.authority`, `Text.originality`, `Image.alt`, `Image.caption`,
  `Video/Image/Audio.c2pa`, and `Retrieval.ratelmt`.
- **Added** `RETRIEVAL_AUTH_OTHER = 4` to the retrieval auth enum.

The request-side model (`AISystem`/`AISystemUse`, `Function`, `SubFunction`,
`AuthMethod`, `ScopeType`, `ContentType`) is unchanged. This is an accepted
breaking change pre-v1 freeze of the CoMP profile; `buf breaking` reports the
deltas as expected.

## v1.0.0 — Initial release

First public release of the RAMP Protocol (Resource Access Metering Protocol):
the wire format (protobuf under `proto/`), the generated Go and TypeScript SDKs
(under `gen/`), and the specification site (under `website/`). RAMP extends IAB
Tech Lab CoMP v1.0 and RSL 1.0 with resource discovery, transaction execution,
post-usage reporting, dispute resolution, and provider domain verification —
enough for an autonomous agent to negotiate licensed access to a publisher's
resources through an Exchange and produce a cryptographically auditable record of
the transaction.

Highlights: a single `ExchangeService` (`DiscoverResources`,
`ExecuteTransaction`, `ReportUsage`, `DisputeTransaction`, and domain
verification) with Brokers and agents as interchangeable clients; unit-agnostic
metering; Ed25519 at every trust boundary, with RFC 9421 HTTP Message Signatures
for request and hop authentication and JWS (RFC 7515) for offer and attestation
signatures; a unified `/.well-known/ramp.json` (`WellKnownManifest`) served by
every role with inline RFC 7517 JWKs and explicit key-validity bounds;
cryptographic content attestations with a structured dispute chain; multi-hop
intermediary chains with agent- and exchange-published depth caps; and extension
profiles for domain-specific behavior (news, academic, legal, C2PA, CoMP, pharma,
medical imaging).

**Universal Licensing Core.** A resource carries `repeated LicenseTerm terms`
— the same shape at ingestion (`ResourceEntry.terms`) and emission
(`Offer.terms`) — replacing the hard-coded default pricing and the removed
`AccessRestrictions` / `Offer.restrictions`. A `LicenseTerm` bundles `License`
(`uri`, `id`, `name`, `immutable`), `TermSemantics` (`ENUMERATED` vs
`REFERENCE_ONLY`), `Restriction`s (function / geography / user-type axes),
`Quota`s, `Obligation`s (`scope_license`, `detail`), `Pricing` (required on
every term), Biscuit `scopes`, and `part_label`. `PricingModel` is the closed
charging structure (`FREE`, `PER_UNIT`, `FLAT`); the metering basis moved to
the open `Pricing.unit` vocabulary; `Pricing.metering` was added and
`revshare` / `REVENUE_SHARE` removed (settlement is off-protocol). Every
required enum carries `_UNSPECIFIED = 0` and is rejected if unset
(`PricingMetering` is the deliberate exception — `ONLINE = 0` is its real
default). The Offer JWS signs the entire canonical Offer, so `terms` and
`pricing` are tamper-evident.

**Proto-native vocabulary.** Every open vocabulary axis is defined in the proto
and tooled by buf — no side-car JSON registry. The `(ramp.v1.vocab)` field
option (`FieldOptions` extension 50001) carries the registered bare tokens on
`Pricing.unit` and `Quota.metric`; the `(ramp.v1.vocab_enum)` enum-value option
(`EnumValueOptions` extension 50002, both in `ramp/v1/vocab.proto`) carries the
function / geography / user-type tokens on the `RESTRICTION_KIND_FUNCTION` /
`RESTRICTION_KIND_GEOGRAPHY` / `RESTRICTION_KIND_USER_TYPE` enum values. The
`protoc-gen-rampvocab` buf plugin reads both options structurally and emits
typed Go constants, `All`, and `IsRegistered` per axis under `gen/go/vocab/`
(`pricingunits`, `quotametrics`, `functiontokens`, `geographytokens`,
`usertypes`). Geography registers only the non-ISO specials (`*`, `EU`, `EEA`);
ISO 3166-1 alpha-2 codes are structural. `protovalidate` carries the structural
field CELs (`Pricing.unit`, `Quota.metric`) and message-level CEL on `Pricing`
(`PER_UNIT ⇒ unit`, `FREE ⇒ rate 0`). Adding a token edits the option list only
— no message-shape change.

**Billing reference, not entitlement.** `Requester.license_id` was renamed
`billing_ref` and recast as an opaque handle into the operator's billing system.
It is not an authorization token: identity is the RFC 9421 request signature and
entitlement is scopes plus `Delegation`, so access is never gated on
`billing_ref`.

**DenialReason consolidation.** `INVALID_LICENSE` and `EXPIRED_LICENSE` collapse
into a single `DENIAL_REASON_BILLING_REF_INACTIVE`, and `DELEGATION_EXPIRED`
broadens to `DENIAL_REASON_DELEGATION_INVALID` (expiry is one of several ways a
token fails to authorize). The enum is contiguous 0–11.

**Delegation-claims profile.** The delegation token stays opaque on the wire;
`token_format` only selects the verifier. RAMP defines a small registered
claim/fact vocabulary mapping the same named concepts across JWT registered
claims and Biscuit facts, so scope / expiry / spend caps mean the same thing to
every verifier regardless of format. All vocabulary entries are optional except
the mandatory subject/holder binding: the key that signs the RFC 9421 request
MUST equal the token's holder key, which is what makes a leaked token not
bearer-usable. Issuer-specific facts use a `vendor:` namespace; `ramp_`-prefixed
names are reserved. Binding constraints are fail-closed (binding by default)
unless explicitly marked advisory.

**JWT-default delegation (holder-of-key).** `token_format` defaults to `"jwt"`:
the delegation token is a holder-bound JWT, with the grant tied to a key via the
RFC 7800 `cnf` claim (`cnf.jkt` = RFC 7638 thumbprint) and possession proven by
the RFC 9421 request signature. Delegation is a chain of `cnf`-linked JWTs
(each child signed by the key its parent named, scope ⊆ parent), verified offline
under the issuer's key alone. `"biscuit-v3"` remains a permitted **optional**
alternative for deployments wanting deep multi-hop in-place attenuation. This
makes JWT — already ubiquitous — the one delegation technology implementers must
support; Biscuit is opt-in.

**Scope matching.** One normative algorithm applies protocol-wide: scopes are
`":"`-separated segments; a grant covers a requirement only if each granted
segment equals the required segment or is `"*"`, with a terminal `"*"` matching
all remaining segments. There is no implicit prefix match and a grant narrower
than the requirement does not cover it. The same rule applies to
requester/`Delegation` scopes and to `LicenseTerm.scopes`; the Biscuit Datalog
authorizer is a conformant implementation that MUST produce identical results.

The reasoning behind the major design decisions is recorded in
[`docs/design-history.md`](../docs/design-history.md).
