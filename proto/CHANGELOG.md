# RAMP Protocol Changelog

## Unreleased

**`WellKnownManifest.endpoint` states its host binding (no wire change; conformance-affecting).**
The field said only "Exchange-only. ExchangeService endpoint URL", so nothing told an Exchange
operator that the address it advertises must stay on its own domain. It now does: the endpoint
MUST be on the host AND PORT that SERVE the manifest — not the self-asserted `domain` member
inside it — or on a subdomain of that host on that port, and MUST NOT carry userinfo. The manifest
is only as trustworthy as the host that served it, so an endpoint naming an unrelated host would
let whoever answers for the manifest redirect a signed call to a party the offer's signature never
covered — and a dial-time address guard has no objection to an unrelated PUBLIC host. Another port
is another service, which the party publishing the manifest need not control. The host match is on
a full dot-delimited label boundary, so `evil-a.com` is not a subdomain of `a.com`. A port equal to
the scheme's default and an omitted port are the SAME port, so `https://x`, `https://x:443` and `x`
all match; the scheme itself is not compared, and the default-port folding is scheme-relative so
that it cannot become a scheme check by accident.

**This is the first entry in this changelog that changes what conforms without changing the
wire.** The classifier is deliberately not `(breaking)`: this change moves no field, message, or
encoding, and `buf breaking` reports nothing — while the bare `(breaking)` entries below all mark
a descriptor delta, and the one qualified use ("breaking for the generated clients") names the
audience it breaks. What this change does instead is narrow what a conformant manifest may say.

**Two shapes that are conformant today will be refused after this.** The first is an Exchange
serving its API from a separate DOMAIN — a CDN, a hosting provider. The second is an Exchange on
a separate PORT: a single-domain deployment serving `/.well-known/ramp.json` on its default port
and advertising `"endpoint": "https://exchange.example:8443/v1"` is refused, as is the mirror
image (a portless endpoint under a manifest served on `:8443`) and a subdomain reached across
ports. A single domain is therefore no longer sufficient on its own — the authority must match on
both halves.

Remedies, by shape. For a separate domain, front the API under a subdomain of the domain serving
the `ramp.json`. For a separate port, either move the API onto the port the manifest is served
from, or serve the manifest from the API's own authority — `https://exchange.example:8443/.well-known/ramp.json`
alongside `https://exchange.example:8443/v1`. Writing a scheme's default port out in full is NOT
a mismatch and needs no change.

Both are refused as `ErrEndpointRefused`, which classifies as a FINAL verdict rather than a
transport failure — so a client will not retry its way out of a misconfiguration, and the symptom
is a usage report that never lands rather than one that is slow.

Enforcement moved with the rule: it now runs in the SDK's shared endpoint resolver rather than
in one client, so every consumer of that resolver inherits it without changing a line. Two
consequences for anyone re-pinning. Resolution can now fail with a new `ErrEndpointRefused`
sentinel, which is a VERDICT — the Exchange answered and the answer is unusable — and a
classifier that branches only on the older `ErrNoEndpoint` will drop it into its
transport-failure bucket and retry something that will never succeed; add the new sentinel
alongside. And a Broker that resolves endpoints through this package inherits the rule for the
paths that use it. `gen/` and the website mirror are regenerated; proto comments only.

**Go SDK: the delivery fetch correlates, and the offer-key cache is bounded (additive, no wire
change).** `resolvers.ContentFetchOptions` gained a `RequestID` hook, and `connect.NewClient`
feeds it the same mint the RPC legs read — so `WithRequestIDFunc` now reaches all three legs and
a delivery GET carries `X-Request-ID`. It did not before, and could not: the RPC legs correlate
through a Connect interceptor, which a plain GET never traverses, and there was no seam to add
one. **This changes what arrives at a delivery edge.** An edge that mints its own id when the
header is absent will now see the caller's instead, which is the point — a refused delivery used
to produce two log records under two ids with nothing joining them, on the one leg where
delivery failures are diagnosed. A fetcher built directly with no `RequestID` still sends no
header: this tier mints nothing of its own.

`resolvers.CachedOfferKeyResolver`'s per-domain cache now evicts least-recently-used at a fixed
cap, like the endpoint cache and the per-origin client pool. Its key is a domain off
`Offer.exchange`, so which entries appear is driven by incoming offers, and an entry's expiry is
a freshness check rather than a removal — a stale entry held its slot indefinitely. Reaching it
needed a resolvable host serving a valid directory per domain, so the case was narrow rather
than open, but two sibling structures over the same key space were already bounded and this one
was not.

**Go SDK: the Connect client covers the agent verb set, and its signing knobs are reachable
(additive, no wire change).** `connect.Client` gained `ReportUsage`, `Dispute` and `Fetch`, and
`connect.NewBrokerClient` gained `Resolve` — the client previously exposed `Discover` and
`Execute` alone, so a caller needing any of the rest had to assemble its own from
`rampv1connect` plus `core.NewSigningTransport`, which is the duplication the SDK exists to
remove. `Resolve` returns the same fail-closed `{verified, rejected}` split `Discover` does,
through the same `core.Verifier`; `Fetch` performs proof-of-possession on an agent-bound URL and
dials only through the SSRF-guarded client.

Five client options join them, each because a value the tier below already accepted had no way
in: `WithSignWindow` (the RFC 9421 request freshness window — pair it with
`core.MonotonicWindow` when the peer screens replays on `(key id, signature)`, since one-second
timestamp resolution makes two identical requests inside a second sign to the same bytes),
`WithSignatureAgent` (the WBA directory origin the client signs as), `WithProofWindow`,
`WithContentTimeout` and `WithMaxContentBytes`.

`WithSignatureAgent` is worth reading twice if you verify signatures. `signature-agent` is one
of the five REQUIRED covered components, so the header is signed whether or not a value was
supplied — a client that does not set it signs an EMPTY one. A peer that resolves the caller's
key by fetching the WBA directory at that origin then has nothing to resolve and refuses the
call at verification, which surfaces as a 401 from an otherwise healthy Exchange rather than as
anything the routing checks would catch. The value is stamped set-if-absent, so a relay
forwarding an originating agent's request does not overwrite the value that agent's own
signature covers. See `docs/sdk-parity-matrix.md` for the per-language surface.

**SDK (all 3 languages): the registration-failure builder can carry the field errors
(additive, no wire change).** `helpers.RegistrationFailureDetail` (Go),
`registration_failure_detail` (Python) and `registrationFailureDetail` (TS) now accept the
offending `registration_data` members alongside the reason — variadic in Go, an optional
trailing argument in Python and TS, so the six reasons that carry no per-member detail keep
their three-argument call. Without this a service refusing a non-conforming registration had
to build the `ErrorDetail` by hand or mutate the builder's result, defeating the rule these
helpers exist for: one place per language where the ADR-019 envelope is constructed. This is
the only `*Detail` builder that reaches past the reason enum — the schema refusal is useless
without naming what failed, whereas the sibling detail lists
(`TransactionDenial.restriction_mismatches`, `CatalogRejection.rejected_paths`) stay
caller-set after construction.

The shared oracle gains a `registration_failure_field_errors` vector and a `field_errors`
projection, replayed on both halves in all three languages: the construct replays feed the
members back through the builder and assert byte-parity with the Go wire, and the read
replays assert a reader extracts them positionally. The vector carries both member shapes —
a pointer into the payload and the empty root pointer for a whole-object failure. That
second one caught a real divergence: canonical proto-JSON omits an empty scalar, so the wire
form of a root-pointer entry has no `path` key at all, while the generated Pydantic model
defaults `path` to `""` and the generated Zod schema declares `.default("")`, both
materializing a member Go omits. Both builders now map an empty path to unpopulated, the
exact inverse of the read side normalizing an absent path to `""`.

**Registration data becomes schema-enforceable: `WellKnownManifest.registration_schema`
(field 29) + `REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA` (additive, no wire
break).** An Exchange MAY publish, in its `ramp.json`, a JSON Schema (draft 2020-12, max
16KB) describing the `registration_data` object it expects on `Register`. Publication and
enforcement are one decision: an Exchange that publishes the schema validates incoming
`registration_data` against it and refuses a non-conforming payload with the new failure
reason; an Exchange that publishes none accepts the payload uninspected and passes it to
its system of record exactly as before, so existing Exchanges stay conformant with no
change. This replaces the former unconditional contract text ("the Exchange passes it
through to its system of record without inspecting it") on the Agent Account Registration
banner and on `RegisterRequest.registration_data`, both of which now defer to the field
that owns the contract rather than restating it.

The field carries normative safety rules, because a consumer reads this schema out of a
third party's manifest: the schema MUST be self-contained and a consumer MUST NOT resolve
a remote `$ref` out of it — doing so would turn every reader into an SSRF vector aimed at
a URL the schema's author chose — and a consumer SHOULD bound validation time and
recursion depth, since draft 2020-12 `pattern` admits regexes with catastrophic
backtracking. The 16KB cap is measured as the UTF-8 bytes of the member as served in
`ramp.json`; an oversized schema SHOULD be rejected and its local pre-check skipped rather
than truncated, which leaves the Exchange's own enforcement deciding exactly as it does
when no schema is published. These are prose, not protovalidate rules: the field is a
`Struct`, and no field-level rule can reach inside it.

The refusal names what to fix: `RegistrationFailure` gains
`field_errors` (field 2, ≤64 items) carrying the new top-level `RegistrationFieldError`
`{path, error}`. `path` is an RFC 6901 JSON Pointer relative to `registration_data`
(`"/vat_id"`, `"/address/postal_code"`); the empty string addresses `registration_data`
itself, which is how whole-object failures (`oneOf`, `minProperties`) that belong to no
single member are reported. A free-text pair rather than a closed `kind` enum because
JSON Schema's composite keywords do not attach to any one member and the standard is
extensible by design, so a closed vocabulary could not stay complete. `error` is
developer-facing and NON-authoritative — wording is validator-defined and varies across
Exchanges, clients branch on `reason` — and, like `ErrorDetail.message`, it states the
violated constraint and never the submitted value, so a refusal cannot echo an agent's
business data back over the wire. A machine-readable `kind` can join at field 3 later
without a wire break.

Motivation: an agent integrating the SDK directly signs and sends `Register` itself and
passes through no registration front-end, so a check only a front-end performs is a
suggestion, not a rule — and the agent had nowhere to learn which fields a given Exchange
expects. Both now resolve against the manifest the agent already fetches to find the
Exchange's endpoint.

*Tooling:* `RegistrationFailure` is now seeded in the corpus generator with the new reason
and an empty-path field error, so the cross-language oracle exercises the reason this
change adds and pins the empty-path accept boundary in all three languages; without the
seed the auto-filled baseline picked the first allowed reason and published a
`DOMAIN_NOT_VERIFIED` refusal carrying `field_errors` as valid — the pairing the field
comment rules out. The generator also gained valid-item construction for repeated
**message** fields (seed-or-autofill, mirroring the top-level baseline). `field_errors` is the
contract's first repeated message field carrying its own `repeated.max_items`, and the
generator previously produced only scalar list items.

**The `ver` envelope field states its contract, and the version string gets one owner
(no wire change).** All 29 `ver` fields — 25 in `ramp.proto`, 4 in `admin.proto` — now name
the expected value `"1.0"` and the receive-side rule. Before this, 27 of them said only
"Protocol version" or "RAMP protocol version", and `DiscoveryResponse.ver` carried no comment
at all — 28 fields from which an integrator could not learn what to stamp. Only
`WellKnownManifest.ver` named the value. The contract: senders MUST stamp `ver` from a single
constant, and receivers treat it as **advisory** — `ver` is not an authenticity or
authorization control and MUST NOT be used as one, a receiver is not required to check it,
and one that does check it MAY reject an unrecognised MAJOR version but MUST NOT reject an
unrecognised MINOR version. Version negotiation, where it is needed, happens out of band via
`WellKnownManifest.protocol_versions_supported`, which is why the in-band field need not be a
rejection gate. `ver` deliberately carries no protovalidate rule: an exact-match rule would
make every peer reject a `"1.1"` message outright, contradicting the
reject-unrecognised-majors policy the manifest already states, and a major-version pattern
would additionally make `ver` structurally required on every message — a wire change no
consumer has asked for. The full reasoning is recorded under "Protocol version" in
`ramp.proto`. `WellKnownManifest.ver` keeps its stronger MUST-equal rule and now says why it
differs: it versions the `/.well-known/ramp.json` document schema, a namespace deliberately
separate from the RPC envelope and not coupled to it.

**SDK (all 3 languages): `ProtocolVersion` exported (additive, no wire change).** The RAMP
`ver` value is now a public SDK symbol — `helpers.ProtocolVersion` in Go, `ProtocolVersion`
in Python and TypeScript — pinned to the shared `wire-constants-vectors.json` oracle
alongside the existing wire constants. It is the RAMP protocol version, not the Connect
transport version that `ConnectProtocolVersion` carries. Consumers import it instead of
minting their own constant, so a protocol bump is one edit here plus a re-pin rather than a
literal hunt across every message builder. Two structural guards keep the pair honest: a
conformance guard fails the build when a contract message declares `ver` without documenting
its value and receive-side rule, and an SDK guard fails when a message builder in non-test
`sdk/go` source stamps a bare string literal on a `Ver:` struct-literal field. Both bind what
this project emits; neither can bind a third party, which is the accepted limit of an
advisory field.

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
string field, and two new vectors in `sdk/go/helpers/testdata/acceptance-vectors.json` —
`empty_requester_id` and `empty_idempotency_key`, one per omittable field left uncovered —
pin the agreement across Go, Python and TS. Without them the omission can be dropped in any
one language with every gate still green. The corpus change is purely additive — the
pre-existing vectors and their signatures are byte-identical, so no already-issued signature
is affected.

**Canonical signing refuses messages carrying unknown fields (normative; Go SDK
behavior change, no wire change).** `Offer.signature` — the single normative definition of
the canonical form — now states the rule, which turns on whether a canonicalizer omits or
preserves content it has no schema for. An OMITTING canonicalizer (proto-JSON emits only
schema-defined fields) cannot reproduce the signed bytes of a message carrying unknown
fields, so it MUST refuse the message rather than emit the reduced bytes, at EVERY depth —
a nested message and each element of a repeated or map field carries its own unknown-field
set. A PRESERVING canonicalizer carries unrecognized members through, reproduces the
signed bytes faithfully, and has nothing to refuse.

Either way an APPENDED field cannot pass, which is the point: the omitting case refuses
the message, and the preserving case renders the appended member into bytes the signer
never covered. Without the refusal the omitting case failed OPEN — an intermediary could
add unknown fields to an already-signed `Offer` **without invalidating its signature**,
smuggling unauthenticated content through a message the recipient treats as verified. That
is what the Go SDK now closes: `helpers.VerifyOffer` surfaces the refusal as
`ErrOfferSignatureInvalid` (a message that arrived carrying extra bytes is a tampered
offer, not an internal fault) wrapping the new `helpers.ErrUnknownFields`, so a caller can
branch on either; `helpers.CanonicalOfferBytes` and `helpers.SignOffer` return
`ErrUnknownFields` directly.

Python (`from_wire_offer`) and TypeScript (`canonicalOfferPayload`) are preserving
canonicalizers and need no change — they already reject the appended-field case on a byte
mismatch. They are NOT expected to reject a message whose signer covered the unknown
member: they reproduce those bytes exactly and verify, which is the forward-compatible
outcome. Go, being an omitting canonicalizer, cannot reconstruct such a message at all and
refuses it; that asymmetry is inherent to the renderer, not new here — before this change
Go rejected the same message on a byte mismatch instead.

No legitimate traffic regresses: an offer signed WITH a field this build cannot render
already failed to verify; the refusal only makes the reason explicit. Extensions are
unaffected — they ride in `ext` / `ext_critical`, defined fields that sit inside the signed
bytes, never undeclared field numbers. One new exported Go symbol (`ErrUnknownFields`,
registered as a Go-idiomatic exclusion in the parity map); no field, message, or wire
change — proto comments only, with `gen/` and the website mirror regenerated.

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
