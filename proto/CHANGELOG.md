# RAMP Protocol Changelog

## Unreleased

**`ResourceEntry` gains typed `resource_mutability` (field 14) (additive, no wire break).**
Publishers submit `resource_mutability` as a typed `ResourceEntry` field instead of inside
`ext`/`ext_critical`; the Exchange reads the typed field, not `ext`. The field is `optional` —
when omitted the Exchange defaults to `STATIC` at Offer build; an explicit
`RESOURCE_MUTABILITY_UNSPECIFIED` is rejected (`not_in:[0]`, matching the Offer-side twin).
Offer-side `ResourceIdentity.resource_mutability` is unchanged.

**SDK parity matrix is now generated, not hand-maintained (no wire change).** The
three overlapping, drift-prone parity docs (`docs/sdk-parity-matrix.md`,
`sdk-api-parity-map.md`, `sdk-parity-audit.md`) collapse to a single generated
artifact, `docs/sdk-parity-matrix.md`, rendered by `scripts/gen-parity-matrix.py` from
the two ground-truth sources CI already enforces against the code: the API surface from
`sdk/parity/symbol-map.json` (gated by `test_api_surface_parity.py`) and the
conformance-vector replay table from the committed corpora (gated by
`test_corpus_replay_completeness.py`). A regenerate-and-diff drift gate runs both in
`scripts/ci-local.sh` and as `sdk/python/tests/test_parity_matrix_generated.py`
(`sdk-types-ci.yml`), so the matrix can no longer drift from the real surface. The two
superseded audit docs are deleted.

**Go SDK: the network-fetching resolvers move `sdk/go/helpers` → `sdk/go/resolvers`
(source move, no wire change).** The IO-bearing key/endpoint resolvers — the
well-known JWKS resolver (`NewWellKnownKeyResolver`), the revocation-aware WBA
directory resolver (`NewWBAKeyResolver`), the `ramp.json` endpoint resolver
(`WellKnownEndpointResolver` / `NewWellKnownEndpointResolver` / `WellKnownOptions` /
`ErrNoEndpoint`), and the SSRF-guarded fetch client — now live in the new L2 I/O
package `sdk/go/resolvers`, one tier above the pure, IO-free `sdk/go/helpers`. This
keeps every network dial out of the trust core (enforced by an io-leaf guard).
Migration: import these from `github.com/RAMP-Protocol/protocol/sdk/go/resolvers`
instead of `.../sdk/go/helpers`. **No alias shim is provided** — the move is a hard
rename and the downstream app already compiles against the moved layout; consumers
import the resolvers from `sdk/go/resolvers`. The pure `KeyResolver` interface and
the static `NewStaticKeyResolver` stay in `helpers`.

**SDK (all 3 languages): new public faces this cycle (additive, no wire change).**
Document-order active-key selection — `ActiveEd25519Key` /
`ActiveEd25519KeyWithExpiry` and their revocation-aware `…Screened` variants
(`active_ed25519_key*` in Python, `activeEd25519Key*` in TS) — plus a
`CachedOfferKeyResolver`, an injectable Ed25519 verify primitive on
the TS signed-URL verify (`Ed25519Verifier`), and cross-language `ErrorDetail`
readers: Go `AttachErrorDetail` / `AttachDetail` on the server binding, and
`parse_error_detail` / `error_detail_from` (Python) and `parseErrorDetail` /
`errorDetailFrom` (TS) decoders, all pinned to the shared `error-detail-vectors.json`
oracle. The SSRF-guarded transport is now a single env-driven client
(`NewGuardedClientFromEnv` / `guarded_client` / `guardedFetchFromEnv`) governed by
two flags (`SKIP_SSRF`, `ALLOW_INSECURE`). See `docs/sdk-parity-matrix.md` for the
per-language surface.

**Go SDK: `helpers.CanonicalOfferBytes` exported (additive, no wire change).**
The offer-canonical-bytes accessor — RFC 8785 JCS over canonical proto-JSON with
`signature`/`signature_algorithm` cleared, `expires_at` included, byte-identical to
what `SignOffer` signs and `VerifyOffer` verifies — is now a public Go symbol. It
exposes the single canonicalization the signer and verifier already share, so a
caller can persist the signed offer as verbatim, independently re-verifiable
evidence. Python (`canonical_offer_payload`) and TS (`canonicalOfferPayload`) already
expose the equivalent public accessor; this brings the Go surface to parity.

**Go SDK: `helpers.CanonicalAcceptanceBytes` exported (additive, no wire change).**
The acceptance-canonical-bytes accessor — RFC 8785 JCS over canonical proto-JSON of
`AgentAcceptancePayload{offer_sig, requester_id, requester_domain, idempotency_key}`,
byte-identical to what `SignOfferAcceptance` signs and `VerifyOfferAcceptance`
verifies — is now a public Go symbol, completing the pair with
`CanonicalOfferBytes`. A caller can persist an agent's acceptance as verbatim,
independently re-verifiable evidence rather than re-deriving the bytes at
verification time, which would pin an already-signed acceptance to whatever
canonicalization the SDK implements later. Python (`jcs_acceptance_payload`) and TS
(`acceptancePayload`) already expose the equivalent public accessor; this brings the
Go surface to parity.

**Acceptance canonical-form text corrected (documentation only, no wire change).**
`AgentAcceptance` and `AgentAcceptancePayload` still described the RETIRED signing
form — "the deterministic protobuf serialization", "`proto.Marshal(Deterministic:
true)`" — contradicting the canonical-signing block on `Offer.signature` in the same
file, which already states that RFC 8785 JCS over canonical proto-JSON "applies to
the agent offer-acceptance signature". The acceptance text now points at that single
normative definition instead of restating a superseded recipe:
`AgentAcceptancePayload` fixes the field set, `Offer.signature` fixes the byte
layout. Implementations that followed the stale text would have produced
non-verifying signatures. No field, message, or wire change — comments only, with
`gen/` and the website mirror regenerated.

**Python + TS SDK: the hand-built acceptance payload omits every unpopulated field
(bug fix, no wire change).** `jcs_acceptance_payload` (Python) and `acceptancePayload`
(TS) assemble the `AgentAcceptancePayload` JSON object key by key, and omitted only an
empty `requester_domain` — `requester_id` and `idempotency_key` were always emitted.
Go renders the same object through `protojson` with `EmitUnpopulated=false`, which omits
EVERY unpopulated field, so the three SDKs signed different bytes whenever `requester_id`
was empty. That input is wire-valid: `Requester.id` carries no `min_len`. Verification
failed closed on it (a byte mismatch, never a bypass), but the byte-equivalence the
canonical-bytes accessors promise did not hold. Both hand-built faces now drop each empty
string field, and a new `empty_requester_id` vector in
`sdk/go/helpers/testdata/acceptance-vectors.json` pins the agreement across Go, Python and
TS. The corpus change is purely additive — the pre-existing vectors and their signatures
are byte-identical, so no already-issued signature is affected.

**`Requester.billing_ref` removed (breaking, pre-1.0).** The caller-written
billing label on `Requester` is gone; the field is deleted outright with no
`reserved` statement — pre-v1 the number returns to the free pool, and
`reserved` becomes the tool for field removals only once v1.0.0 is tagged.
Nothing read it: billing and cost attribution key on the verified caller identity and the
account handle minted at `Register` (`RegisterResponse.billing_ref`), which the
Exchange resolves from the request signature — never from anything the caller
sends. Dropping the field also removes the name collision between the
caller-written label and the authoritative account handle. Binary
wire-compatible: an old caller still sending field 5 has it ignored as an
unknown field. JSON tolerance is a decoder property, not a protocol guarantee:
a decoder that discards unknown fields (as connect-go's default codec does)
ignores a stray `billing_ref` inside `requester`, but a strict `protojson`
decoder rejects the whole message — endpoints that hand-roll `protojson`
decoding should set `DiscardUnknown: true` if they want to keep accepting old
callers. For anyone who used the field: who pays is always the account minted
at `Register`, resolved from the request signature. For a cost-allocation
label, Broker callers use `RequestConstraints.budget_scope` on
`DiscoveryRequest` (a Broker-side spend-tracking key; it does not reach the
Exchange). Direct-to-Exchange callers who need to attach one use
`Requester.ext` — but do not name the key `billing_ref`: it is not an account
handle, and the Exchange will not read it as one.

**Agent account registration + status RPCs (additive).** `ExchangeService`
gains `Register(RegisterRequest) → RegisterResponse` and
`GetAccountStatus(GetAccountStatusRequest) → GetAccountStatusResponse` — the
agent-account front door the Web Bot Auth Registry epic needs. Registration
creates the agent's account with the Exchange and mints `billing_ref`, the
opaque, long-lived, per-Exchange account handle; the caller's identity is
derived from the verified request signature, never from the body, and the
operator-defined business payload rides in a flexible
`RegisterRequest.registration_data` (`google.protobuf.Struct`) that the
Exchange passes through uninspected. A repeat `Register` for the same agent
returns the same `billing_ref` (idempotent by design — no `idempotency_key`).
`GetAccountStatus` is the read-only "is my account active" check; its request
deliberately carries no identifying field. Refused registrations use the
pre-existing `ErrorDetail.registration_failure` / `RegistrationFailureReason`
path, which until now had no RPC front door. Pre-v1 additive change.

**Operator plane: new `ramp.admin.v1` package with `AdminService` (additive).**
Two full-replace, idempotent setters for Exchange operators —
`SetTenantFeeRate(SetTenantFeeRateRequest) → SetTenantFeeRateResponse` and
`SetReportingPolicy(SetReportingPolicyRequest) → SetReportingPolicyResponse`.
Each request and response is a thin `{ver, <payload>}` envelope carrying a
required nested payload message: `TenantFeeRate` (fee rate in basis points,
`0 <= fee_rate_bps < 10000`, plus an optional operator note) and
`ReportingPolicy` (required report fields, quantity tolerance `0`–`1`, reporting
window ≤ 1 year). The field-level protovalidate constraints live on the two
payload messages — shared by request and response, so each rule is stated once
and the echoed read-back cannot drift from the write — and flow into the
generated Pydantic/Zod types export and the validation corpus; responses echo
the state as persisted. Deliberately a separate service/package from
`ExchangeService` — the operator plane is not part of the agent contract,
carries no `idempotency_key` (full-replace setters on an unsigned internal
plane have nothing to dedupe) and no `ext`/`ext_critical` maps, and is expected
to be network-isolated by deployments. `SetOfferPrice` and
`SetDeliveryWitnessMode` are deferred to follow-up work. The conformance
tooling (corpus generator, required-fields export, reachability and
doc-coverage guards, Zod/Pydantic types pipeline) now walks both contract
packages, and the corpus generator gained int32/double boundary mutants for the
payload messages' numeric rules.

**Biscuits removed; entitlement mechanism kept for JWT (breaking).** The Biscuit
token format leaves the protocol — JWT is the sole entitlement/capability token
format. The entitlement MECHANISM is unchanged and format-neutral: a capability
token rides a covered header (renamed `X-RAMP-Entitlement-Biscuit` →
`X-Entitlement-Token`) whose signature-coverage the verifier enforces without
ever parsing the token, so it holds identically for JWT. Removed only the
biscuit-specific bits: the `token_format` value `"biscuit-v3"` (JWT stays the
default), and `DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION` (18) — attenuation is
a biscuit concept. The generic entitlement `DenialReason` family (12–17) stays.
Pre-v1 breaking change; `buf breaking` reports the deltas as expected.

**Protocol standardization — unified error/response contract + a Connect RPC for
every role (breaking).** Three threads land together:

- **Unified error model.** A typed `ErrorDetail` (plus its detail messages and
  `DenialReason`/`OfferAbsenceReason` reason enums) is carried out-of-band in the
  transport error; a failed action returns a transport error while a successful
  query — including a "no result" answer — returns in-body. Response messages are
  standardized: `ver` is field 1 on every request and response.
- **A Connect RPC for every role.** Added `BrokerService` with
  `Resolve(DiscoveryRequest) → DiscoveryResponse`, and
  `DiscoveryResponse.absence_reason` (field 16) for "the resolve ran but produced
  nothing licensable".
- **Idempotency.** A required `idempotency_key` (`min_len: 1`, `max_len: 255`,
  deduped per verified RFC 9421 signer) is added to every state-mutating RPC:
  `TransactionRequest`, `UsageReport`, and `DisputeRequest`. Broker `Resolve`
  (`DiscoveryRequest`) is pure discovery — it executes no transaction and takes
  no key.

Also: renamed `PushContent` → `PushResources`; removed `AccessPolicy` /
`ResourceAccessPolicy` and `DELIVERY_METHOD_INLINE`; removed in-body correlation
— the `request_id` fields and the residual `id` fields on
`ResourceQuery`/`DiscoveryRequest` — in favor of an `X-Request-ID` header;
extended `DenialReason` with
values 12–18 and added `OFFER_ABSENCE_REASON_BUDGET_EXCEEDED`. Accepted pre-v1
breaking change; `buf breaking` reports the deltas as expected.

Also: removed the vestigial `TransactionRequest.offer_id` (field 3). It was a
single-offer-era correlation scalar left stranded by the items-only migration —
never authoritative (the Exchange keys binding, billing, and audit off each
item's signature-verified `offer.offer_id`, never this scalar) and read by
nothing. A single-offer transaction is the degenerate one-element `items` list;
offer identity lives inside the signed Offer. Deleted outright with no reserved
(pre-v1); `buf breaking` reports the delta as expected.

**Money as an exact decimal string + field validation as standard constraints (breaking).**

- **Money is a decimal string, not a `double`.** `Pricing.rate`/`unit_cost`,
  `Cost.amount`/`unit_cost`, and `RequestConstraints.max_unit_cost` change from
  `double` to `string` carrying a decimal `string.pattern`
  (`^([0-9]+([.][0-9]+)?)?$`). Binary `double` cannot represent most decimal money
  values exactly, so it drifts and breaks settlement sums; a decimal string is exact
  and supports arbitrary sub-cent precision (e.g. `"0.0001234"`). Accepted pre-v1
  breaking change; `buf breaking` reports the five field-type deltas as expected.
- **Field-level validation moved to standard protovalidate constraints.** 18 of 25
  field-level rules moved from custom CEL to standard constraints (11 enum
  discriminators to `enum.not_in: [0]`, 7 formats to `string.pattern`) so they flow
  through JSON Schema into the generated Pydantic/Zod types export; the 7 genuine
  cross-field rules stay server-authoritative CEL.

**Wire is snake_case proto-JSON (breaking for the generated clients).** The generated
Pydantic/Zod clients and the shared conformance corpus use the proto field names
(snake_case) as the wire form (Go `protojson` with `UseProtoNames`), matching the
`.proto` and the docs. protojson still accepts the camelCase `json_name` on input, but
it is out of contract for the generated clients: they emit and accept snake_case only,
and — because JCS-canonicalized signing is over the JSON field names — snake_case is the
canonical form the signature bytes are computed over. Accepted pre-v1 breaking change.

**Discovery/offer response model (breaking).** The Agent-to-Broker discovery
messages are renamed and the response is re-modeled to carry offers rather than
a single transaction result:

- **Renamed** `RAMPRequest` to `DiscoveryRequest` and `RAMPResponse` to
  `DiscoveryResponse` — the Agent-to-Broker request/response pair (Steps 1 and 6),
  the same pair carried by `BrokerService.Resolve`.
- **Re-modeled** `DiscoveryResponse` as discovery-only. Removed the
  per-transaction fields (`transaction_id`, `billing_id`, `exchange`,
  `resource_title`, `cost`, `delivery_method`, `reporting_obligation`,
  `expires_at`, `broker_fee`, `retrieval_endpoint`, `agent_identity_hash`) —
  these are carried solely by `TransactionResponse` — and added
  `repeated OfferGroup offer_groups`, one group per requested URI, as the sole
  offer representation. A group with no offers carries its `absence_reason`.
- **Added** `Offer.exchange` (field 8): the canonical domain of the issuing
  Exchange and the target for the execute call. It sits inside the signed Offer
  bytes, so a relaying Broker cannot redirect execution to a different Exchange
  without invalidating the signature.

This is an accepted breaking change pre-v1 freeze; `buf breaking` reports the
deltas as expected.

**WBA identity split — keys move to the WBA directory (breaking).** Identity keys
are split out of `ramp.json` (`WellKnownManifest`) and into a pure WBA key
directory served at `{domain}/.well-known/http-message-signatures-directory`:

- **Added** `WBAFile` (the WBA directory body) carrying the role's
  attestation/identity JWKs (with their `not_before`/`not_after` bounds per
  RFC 7517 §5) and an optional `revocation_url`; removed `WellKnownManifest`'s
  `public_keys` and `invalidation_url`.
- **Keyed by thumbprint, no `kid`.** The RFC 9421 `keyid` is the key's RFC 7638
  JWK Thumbprint, computed locally; carrying a separate `kid` is gone. The
  attestation `keyid` field now holds the verifier key's thumbprint, resolved
  against the verifier's `WBAFile.keys`.
- **Added** `KeyRevocationList`, the snapshot body served at
  `WBAFile.revocation_url` — the complete set of revoked key thumbprints
  (RFC 7638, base64url-no-pad), polled on a 300s cadence — and the
  `RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH` / `_THUMBPRINT_MISMATCH`
  failure reasons.

This is an accepted breaking change pre-v1 freeze; `buf breaking` reports the
deltas as expected.

**CoMP re-baseline to canonical V1 (breaking).** `proto/comp/v1/comp.proto` is
re-aligned to be a 1:1 mirror of IAB Tech Lab Content Monetization Protocols
**CoMP V1** (finalized 2026-04-28,
[`CoMP-1.0.md`](https://github.com/IABTechLab/CoMP/blob/880238e0100b3d0d67d5afd7357a18fc21a97be5/CoMP-1.0.md)). Our
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
token fails to authorize). The enum is contiguous, with no reused numbers.

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
