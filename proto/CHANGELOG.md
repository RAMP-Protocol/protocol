# RAMP Protocol Changelog

## Unreleased

**The offline recipe compares every signed member, not just `offer_sig` (contract fix, no wire
change).** Binding the acceptance to the offer stopped splicing: a genuine acceptance from a
different offer no longer passes. It did not stop reuse. Two acceptances by one agent against ONE
offer share `offer_sig` and differ only in the idempotency key, so an Exchange holding a single
genuine acceptance could write two evidence rows for two different executes against one offer, and
both passed. That is fabrication by the row's writer rather than splicing by an outsider, and it is
the failure `AgentAcceptancePayload.idempotency_key` exists to prevent.

The recipe now compares all four members of the signed payload against their stored copies. Three
names coincide; the fourth does not -- the payload member is `idempotency_key` and the row stores it
as `request_idempotency_key`. The row comment that listed the payload's four fields used the row's
name for the fourth, which would send an implementer looking for a JSON member that does not exist;
it now states the mapping. The conformance test carries both cases: a spliced acceptance caught on
`offer_sig`, and a reused acceptance caught on the idempotency key.

**The admin plane no longer claims a per-tenant ACL is possible (documentation fix, no wire
change).** Four sites -- the service comment, the RPC comment, the `tenant_id` field comment and the
hand-maintained admin proto reference page -- said the `(tenant_id, transaction_id)` pair selector
is what lets a deployment put a per-tenant ACL in front of `GetTransactionEvidence`. The threat
model says the opposite twice, and it is right: `ramp.admin.v1` carries no request signing and no
per-operator identity, so there is no caller to attach an ACL to. All four now say what the pair
selector actually buys -- it narrows what a leaked transaction id is worth -- and that the network
allowlist is the only gate. This matters because the same threat model records that
`GetTransactionEvidence` widened that allowlist's blast radius from per-tenant config writes to a
cross-tenant read of every tenant's signed offers; an operator sizing it while believing a second
control sits behind it would size it too loosely.

**The no-shared-secret claim is scoped to delivery URLs (documentation fix, no wire change).** The
file header said "No shared secret in either scheme", which is true of the two signed-URL schemes
and contradicted by `cdn_type` on `DomainVerificationConfirmation`, where `"hmac"` is still an
accepted value with no validation rule. The header now says neither *delivery-URL* scheme uses a
shared secret and points at the registration plane that still admits an HMAC key format. Whether
that plane should keep admitting it is a live question, tracked with the wider HMAC sweep.

**Four parity exclusions stated reasons that were false (documentation fix, no wire change).** Three
justified themselves with "TS/Py have no server face"; both `ramp_sdk.server_verify` and
`core/verify-request.ts` exist and open by calling themselves exactly that. Those three also carried
a retirement trigger -- "if a Python or TS server face ever lands" -- that had already fired and so
could never fire again. The real reason is narrower and is now stated: the py/ts server faces carry
no request-id seam. The fourth said py/ts "mint request-ids inline"; neither SDK mints anything --
both export the `RequestIDHeader` constant and no non-test code sets that header, so every RPC from
a py/ts client arrives with no correlation id. Two older entries repeating that claim are corrected
with it. The underlying behavioural gap is now tracked as its own work rather than documented as an
intentional difference in API shape.

**The offline re-verification recipe binds the acceptance to the offer (contract fix, no wire
change).** The recipe on `TransactionEvidence` stated two independent signature checks and
introduced the second with "the agent accepted this exact offer". Nothing in the procedure
established "this exact". A genuine offer from one transaction and a genuine acceptance from
another, by the same agent, both verify against real keys and both pass the authenticity step the
same comment describes -- and the spliced row asserts an agreement that never happened.

The recipe now has a third step: read `offer_sig` back out of
`agent_acceptance_canonical_bytes` and require it to equal the row's `offer_sig`, compared
case-insensitively. The acceptance payload has always carried `offer_sig` as field 1 for exactly
this purpose; the recipe simply never read it. The Exchange MUST perform the same comparison before
persisting a row. `conformance/evidence_offline_verify_test.go` now executes all three steps and
carries a splice case: two genuine halves joined, both signatures verifying, caught only by the
binding check.

**Who may file a usage report is now stated (contract fix, no wire change).** The dedupe namespace
for `UsageReport` and `DisputeRequest` is `(transaction_id, key)`, which deliberately leaves the
verified signer out so that a Broker relaying an agent's report unchanged collapses into one report
rather than two. Dropping the signer also removed a protection that was never restated: when the
namespace included the authenticated caller, an unauthorized filer could only pollute their own
slot. The slot is now shared.

The rule is therefore explicit: only the agent the transaction was bound to at execute time may file
against it, or a Broker relaying that agent's report unchanged. Any other filing MUST be rejected
rather than deduped, since an accepted filing from an unbound party would occupy the slot the bound
agent's report needs. An unauthorized filing reports as
`USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND` on purpose -- a distinct "not authorized"
value would confirm to an unbound party that the transaction exists, turning the rejection into an
oracle for probing transaction ids. No enum value was added.

**The proto no longer describes signed URLs two ways (documentation fix, no wire change).** The
retrieval-URL block said signed URLs use HMAC-SHA256 with an Exchange-to-CDN shared secret, and
offered a fallback to "HMAC + short TTL + TLS", while the same block's identity-binding paragraph
had been rewritten to say "confirm the URL signature". RAMP has two signing schemes and both are
asymmetric: Ed25519 over a canonical message, and a CloudFront RSA canned policy. There is no shared
secret in either. Both lines now say so, and the fallback names the scheme that actually exists --
a CDN that verifies the URL itself before any function code runs, and therefore cannot check proof
of possession.

**The C2PA page no longer calls the attestation signature a JWS (documentation fix, no wire
change).** Pinning `ResourceAttestation.signature` to hex left three lines on
`protocol/ext-c2pa.mdx` naming the old format in the RAMP column of a C2PA-versus-RAMP comparison.
The audience for that page is a verification vendor -- a third party who never negotiated with the
publisher, which is the reader the hex settlement exists to protect -- and one building from the
table would emit a value the schema now rejects. Four SDK comments calling `EdDSA` "the JWS alg"
are corrected the same way: the name is the JOSE algorithm identifier, the signature is detached
hex.

**Two drift gates now cover the detached-signature rule.**
`ramp.v1.ResourceAttestation.signature` carried the hex rule and a comment saying "the same rule",
which is not the phrase `conformance/samerule_test.go` reads, so it was the one copy of five tied to
nothing. It now declares `Same rule as ramp.v1.Offer.signature`. Separately, the equality gate can
only prove the five copies stay EQUAL -- move them all in step and a changed shape passes. Measured:
widening the class to `^[0-9A-Za-z]{128}$` passed every gate and regenerated the corpus
byte-identical. `TestHexSignaturePatternAdmits` now pins what the rule admits: either case accepted,
127 and 129 characters and non-hex characters and the empty string refused.

**`ResourceAttestation.signature` states its encoding, and enforces it (BREAKING: rule addition on a
live field).** The field carried no rule and its comment described the signed BYTES precisely -- an
Ed25519 signature over the RFC 8785 JCS form of `{verifier, keyid, attested_at, uri, claims}` --
while never saying how the signature ITSELF is written. A vendor had to guess, and the published
examples guessed base64, which no part of the contract supports.

It is now hex, 128 characters, either case, with `pattern = "^[0-9A-Fa-f]{128}$"` -- the same rule
and the same convention as `Offer.signature` and `AgentAcceptance.signature`. Every detached
signature in this contract is now written the same way.

An attestation is the worst place to leave an encoding unstated, which is why this is settled rather
than documented: the signing party is a third party who never negotiated with the reader, so two
vendors guessing differently produce attestations neither side can verify and nothing on the wire
explains why. No SDK produces or verifies an attestation signature today, so nothing conformant is
refused.

The rule also makes the field mandatory in practice, since the empty string does not match. That
restates what the message already means -- an attestation without a signature is an unverifiable
assertion by an unproven author, which the field comment already calls Level 0 (no attestation
present) rather than an attestation with a field missing.

**Every published signature example is hex (documentation fix, no wire change).** 71 example values
across 14 pages showed signatures as base64 placeholders (`base64-ed25519-...`), truncated tokens
(`a1b2c3...`), or bare ellipses. They were left behind by the JWS-to-hex settlement and were wrong
for `Offer.signature` and `AgentAcceptance.signature` from that moment; the attestation ones were
merely unpinned until the rule above. All are now full 128-character hex, with one value per
distinct placeholder so a signature that appears in several places in one walkthrough stays the same
value throughout.

**`broker` is bounded printable ASCII (rule addition on a field added in this revision).** The
field is a server-written value that a ledger renders, so an unbounded string would have re-opened on
a new field exactly the surface `RequestCorrelation.request_id`'s printable-ASCII bound closes:
control characters, terminal escapes and newlines reaching a rendered forensic row. It now carries
`max_len: 255` and `^$|^[!-~]+$`.

The rule bounds the SHAPE and deliberately does not pin the FORMAT. A thumbprint pattern would
invalidate a row for a transaction that legitimately executed under a server that records provenance
some other way -- the `requester_id` reasoning. The alternation admits the empty string on purpose,
because `''` is one of the field's three states; a bare `^[!-~]+$` would delete it and leave absence
meaning both "not recorded" and "arrived direct".

**`broker` moves from `TransactionState` to `TransactionEvidence`, and gains explicit presence
(field move on a message that has not shipped).** `TransactionState.broker` was a plain `string`
describing a transaction-log column that no implementation has. Two things were wrong with that.

The message is a projection of transaction-log columns, and a field with nothing behind it breaks
the property that makes the projection meaningful. Broker routing is not operational state anyway:
it is an execute-time observation about the connection the request arrived on, covered by neither
signature — the same category as `request_correlation`, which already sits on `TransactionEvidence`.
So it moves there, and `TransactionState` goes back to being every-field-backed-by-a-column.

The field is now `optional`, which turns two states into three. Absent means the Exchange does not
record routing; `''` means it does record it and the acceptance arrived direct; a value means it
arrived through that hop. Without explicit presence the field defaults to `''`, so an Exchange with
nothing to say would have stated "arrived direct" for every row — a forensic plane asserting a
transport fact it never observed.

The value is defined as implementation-defined provenance for the outermost hop, not a resolvable
identity. A reference Exchange serves the verified RFC 7638 key thumbprint of the hop that presented
the request, and deliberately does not resolve it to a directory host: the relay hop is not
re-identified against a registry, and the recipient's own relay-permission setting is the gate. A
reader may compare the value for equality against a thumbprint it already holds, but must not expect
a hostname and must not read it as an identity the Exchange vouched for.

**Agent-plane signature fields now enforce the hex shape they describe (BREAKING: rule addition on
live fields).** `ramp.v1.Offer.signature` carried no rule at all and
`ramp.v1.AgentAcceptance.signature` carried only `min_len: 1`, while both comments described a
detached Ed25519 signature in hex. The read plane already enforced exactly that on its stored
copies (`TransactionEvidence.offer_sig`, `.agent_acceptance_signature`), so the forensic copy of a
signature was validated and the live one was not: a malformed signature was accepted on the agent
plane, failed verification later, and only failed VALIDATION once it reached an evidence row it
could never legitimately reach. Both fields now carry
`pattern = "^[0-9A-Fa-f]{128}$"` — 64 bytes of Ed25519 signature, hex-encoded, either case
accepted because hex decoding accepts both. On `AgentAcceptance.signature` the pattern REPLACES
`min_len: 1`, which it subsumes. Breaking in the descriptor, but no conformant caller is refused:
a value outside this shape cannot hex-decode into 64 bytes, so it could never have verified — the
rejection simply moves from the verify step to the validation step, where the error names the
problem. All three SDKs already emit lowercase hex. The `Same rule as` drift directives on the two
admin fields were re-anchored UPSTREAM to the ramp.v1 fields, which they could not point at while
those fields had no rule; the gate now compares the two planes against each other.
`Offer.signature` also becomes mandatory in practice, since the empty string does not match the
pattern — which is what the message already meant, an offer whose terms, pricing and expiry are
not signed being no offer.

**`transaction_id` is enforced non-empty on `UsageReport` and `DisputeRequest` (BREAKING: rule
addition on live fields).** Both comments said the field MUST be non-empty and both were bare
`string transaction_id = 3;`, so an empty value passed. The rule is not a shape preference: for
these two RPCs the named transaction IS the dedupe namespace for `idempotency_key`, so a message
that names no transaction has no namespace to dedupe within, and the namespace invariant stated on
`TransactionRequest.idempotency_key` — one caller's key never collides with another caller's
cached result — has nothing to hold it up. Both fields now carry `min_len: 1`, with no upper
bound, because the Exchange assigns the id and nothing upstream constrains its length. The prose
MUST and the schema now say the same thing.

**Operator plane: forensic evidence read — `GetTransactionEvidence` (additive).**
`AdminService` gains its first read:
`GetTransactionEvidence(GetTransactionEvidenceRequest) → GetTransactionEvidenceResponse`
returns the append-once evidence row the Exchange persists for every successfully executed
transaction — the full signed offer (`offer_json` plus the verbatim RFC 8785 JCS
`offer_canonical_bytes`), both Ed25519 proofs (`offer_sig`, `agent_acceptance_signature`) with
the acceptance's four signed inputs, both verifying public keys — plus the transaction-log and
reporting-obligation state a ledger renderer needs. New messages: `TransactionEvidence`,
`TransactionState`, `ReportingObligationState`, `RequestCorrelation`, the request/response
envelopes; new enum `ObligationState`, which is exactly the storage model's persisted vocabulary
(`PENDING`/`FULFILLED`/`EXPIRED`/`WAIVED`/`BLOCKED`). Selection is by the
`(tenant_id, transaction_id)` PAIR — transaction ids legitimately circulate to counterparty
agents, so an id alone must not act as a bearer capability for the forensic row; a tenant
mismatch is `NOT_FOUND`, byte-identical to an unknown id, so existence under another tenant is
not revealed. The row re-verifies OFFLINE, and the contract states the trust boundary
explicitly: offline verification proves the row is internally consistent, while authenticity
requires comparing the embedded keys against independently obtained copies. The Exchange anchor
is signed — `Offer.exchange` inside `offer_canonical_bytes`; the agent side has none, so
`agent_directory_url` is provenance and the agent key must be anchored independently.
The delivery join is hash-only
(`TransactionState.signed_url_hash` against the edge log) — the full signed URL, a live bearer
capability, never appears on this plane, so a signed-URL *signature* match assertion is
deliberately unproducible from this contract. The correlation id the Exchange persisted rides in
`RequestCorrelation` (bounded printable ASCII, with a `minted` provenance flag); the agent plane
still carries no correlation field in any message body. `TransactionState.signed_url_expiry` and
`TransactionState.signed_url_hash` are both optional, because not every delivery method mints a
signed URL: a `DELIVERY_METHOD_DIRECT` transaction returns the resource inline or from the
Exchange's own endpoint, so it has no URL, no expiry and nothing to hash. Requiring them would
leave a successfully executed direct transaction with no legal value to send for two mandatory
fields. Absence is the stated fact that no signed URL existed; a value that IS present must still
be a full 32-byte digest.

**`transaction_id` entropy: the guarantee is narrowed to what it actually is (wording fix; no
wire change).** `ramp.v1.TransactionResultItem.transaction_id` said RAMP places no entropy
requirement on a transaction id because the evidence read selects by a pair, and concluded that
"nothing rests on this field's format being unguessable". The first half is right and the
conclusion was too strong. What the pair selector buys is that a transaction id ALONE is never a
bearer capability for the forensic row — which matters, because counterparty agents legitimately
hold the ids of their own transactions. It does not make enumeration infeasible: tenant ids are
human brand slugs, and a tenant's slug is handed to every agent holding one of its offers,
because it prefixes the `offer_id` inside the signed offer. A caller who can reach the admin
plane and has done business with a tenant can pair a known tenant with guessed ids. Enumeration
is bounded by the network-layer reachability restriction on `ramp.admin.v1`, which is therefore
the load-bearing control rather than a deployment convenience. Both planes and the threat model's
enumeration entry now say this the same way.

The cross-package dependency is also gated. The agent-plane claim rested on the shape of
`ramp.admin.v1.GetTransactionEvidenceRequest`, and nothing failed if that shape changed — the
only other mention was inside the generated corpus, which would simply regenerate smaller. A
conformance guard now fails when the selector stops being a pair, so weakening it can no longer
leave a published agent-plane promise quietly false.

**Evidence row: the offline trust boundary now names a SIGNED anchor, and `agent_directory_url`
is bounded (rule addition on a message that has not shipped).** The trust-boundary recipe told a
verifier to check the embedded keys against independently obtained copies, then pointed at
`agent_directory_url` for the agent side — a field covered by neither signature and written by
the same party as the rest of the row. A fabricated row satisfied the entire documented procedure
using one host its author controlled. The recipe now separates the two sides. The Exchange anchor
is read OUT of `offer_canonical_bytes`: `ramp.v1.Offer.exchange` names the issuing host and sits
under `offer_sig`, so changing it invalidates the signature the check exists to confirm. The
agent side has no signed anchor, and the contract now says so — `agent_directory_url` is
provenance, never authority, and the agent key must be anchored independently, which is equally
true when the field is `''`. It is also added to the list of unsigned self-assertions under
SCOPE OF THE GUARANTEE.

The field additionally gains `max_len: 512` and a pattern accepting `''` or an https URL whose
host uses the same recipient-host grammar as `Offer.exchange`, with an optional port and an
ASCII-printable path. The rule bounds the damage from tooling that follows the value anyway; it
does not make following it safe, and the comment states what it does not catch — an IPv4-literal
host still matches, because the recipient-host grammar admits all-numeric labels. A conformance
test pins the accepted and refused set so the comment and the rule cannot drift apart.

The row's replay exposure is now stated rather than left to inference. `offer_json` + `offer_sig`
are a complete Exchange-signed offer, and `ramp.v1.Offer` binds no requester and no tenant, so a
row holder can accept the same offer under their own identity until it expires; `expires_at`,
`Offer.exchange` and this plane's reachability restriction bound that without closing it, and
closing it needs a requester audience inside the signed offer, which belongs upstream in
`ramp.v1`. The acceptance is the opposite case: the row carries a complete resubmittable
acceptance, but resubmitting it lands in the same dedupe namespace and returns the original
result, and the row holds no private key with which to mint a different one.

**The agent identity for a transaction is the ACCEPTANCE key (wording fix; no wire change).**
The schema named two different keys as the source of the same embedded value. `AgentAcceptance`
said `agent_identity_hash` is the RFC 7638 thumbprint of the acceptance key; the file header and
`TransactionResponse.agent_identity_hash` said the request-signing key. They are the same key
only on a direct hop. A Broker may author a re-packaged transaction as sender, and on that leg
the RFC 9421 signer is the broker while the in-body acceptance is the only agent-authored
signature in the request — so the transport signer cannot be the anchor. `AgentAcceptance` now
carries the normative definition and every other site cites it: the identity is the acceptance
key where an acceptance is present, and the verified request signer otherwise, which is safe
only because an acceptance-less request cannot have been relayed.

Two rules that shipping code already enforces are now written down. The ONE-KEY RULE: an agent
MUST accept an offer and fetch the delivered resource with the same key, because the URL is bound
to the acceptance-key thumbprint and an enforcing delivery endpoint checks the fetching key
against it — accepting with one key and fetching with another produces a transaction that
succeeds and a retrieval that is refused. It binds only where proof-of-possession is enforced (a
bearer-only CDN keeps the bearer posture), and a custodial registry holding the one key satisfies
it with nothing extra to do. And because `TransactionResponse.agent_identity_hash` is a single
per-request value, every acceptance in one `TransactionRequest` MUST be signed by the same key.

**Idempotency dedupe scope: one invariant, three named mechanisms (wording fix; no wire
change).** The same sentence — "uniqueness is scoped to the verified RFC 9421 signer" — was
copy-pasted onto `TransactionRequest`, `UsageReport` and `DisputeRequest`, three RPCs that do not
authenticate the same way. Under a broker-repackaged execute it namespaces every agent behind one
broker together, which is the collision the sentence exists to forbid. The invariant is now
stated once on `TransactionRequest.idempotency_key` — a key chosen by one caller MUST NEVER
collide with another caller's cached result — and each RPC names the namespace that makes it
true: `ExecuteTransaction` scopes to the acceptance identity; `ReportUsage` and `FileDispute`
carry no acceptance payload and scope to the transaction the message names, which is bound to
exactly one agent by its acceptance at execute time. Both of those RPCs therefore state that
`transaction_id` MUST be non-empty. That is prose here; the schema rule enforcing it is filed
separately.

**`Offer.signature` is a detached hex Ed25519 signature, not a JWS (wording fix; no wire
change).** The schema described one field two ways. `Offer.signature`,
`Offer.signature_algorithm` and the file-header summaries called it a JWS with `alg=EdDSA`, while
`AgentAcceptance` described the same convention as "a hex-encoded detached Ed25519 signature
(NOT a JWS)". Hex is the reading every verifier implements, and the operator plane depends on
it: `TransactionEvidence.offer_sig` is pattern-enforced as 128 hex characters and the offline
verification recipe re-verifies those bytes directly, so under the JWS reading every evidence row
would fail its own validation. The JWS wording is now gone from all four sites. The value of
`signature_algorithm` stays `"EdDSA"` — the JOSE algorithm identifier is borrowed, the envelope
is not. Nothing on the wire changes: a client emitting a JWS here was already producing a value
no Exchange accepts.

**Generated clients: `TransactionRequest.items` is now required in the Pydantic/Zod export
(breaking for the generated clients; no wire change).** The Go server has always rejected an
omitted `items` (`repeated.min_items = 1`); the generated clients accepted the omission and
diverged. The required-fields inference now covers `repeated.min_items ⇒ required`, closing that
gap for a pre-existing agent-plane type.

**Generated clients: exact-length bytes fields are enforced, and both base64 alphabets are
accepted (no wire change).** A `bytes.len = N` rule (the evidence row's Ed25519 keys and
sha256 hash) now renders in the Pydantic/Zod export as the exact encoded forms of N bytes — the
loose character window protoschema emits would also admit an N+1-byte value — and the pattern
accepts standard and url-safe base64 alike, because Go `protojson` accepts either on decode; a
client rejecting base64url (e.g. a JWK `x` value pasted verbatim) would refuse input the server
accepts. It accepts them as two ALTERNATIVES — one alphabet per value — because that is what the
decoder does: `protojson` switches to the url-safe alphabet as soon as the string contains `-` or
`_`, then decodes strictly, so a value mixing `+` with `_` is refused, and the generated pattern
refuses it too. Padding is derived from the payload length mod 4 rather than left as a free tail,
so `"AA="`, `"AAA=="` and `"AAAAA"` — none of them a legal encoded length — are rejected exactly
as the server rejects them. The signing-algorithm labels are pinned `string.const = "EdDSA"`
rather than `min_len: 1`, so a generated client also rejects a claimed `"none"`. `bytes.min_len = 1` (the
canonical-bytes fields) is translated the same way: the generated pattern now requires the
encoded payload characters of at least one real byte before the padding tail, so the
two-character string `"=="` — pure padding, zero bytes, which Go `protojson` refuses to
decode — no longer passes the clients, and the pipeline fails closed on any bytes rule shape
it cannot translate.

The conformance tooling grew with the surface: the corpus generator understands `string.const`
and fails closed on any rule shape it cannot classify, and the restated-rule drift gate now
derives its scope from the descriptor itself — every rule-identical field group must carry a
`Same rule as` directive or an explicit coincidence exemption — instead of an opt-in comment
marker plus a hand-maintained list. The base64 wire forms the two generated clients must decide
identically now live in one shared vector file (`conformance/testdata/bytes_wire_forms.json`)
that a conformance test pins against Go `protojson` + protovalidate, so each row is written once,
cannot drift between the Pydantic and Zod suites, and states the server's real verdict rather
than a belief about it. The evidence-read messages contribute 94 of the new corpus cases; the
committed corpus goes from 549 at the branch point to 703, a net +154 made of 179 added and 25
removed across 31 messages, because tightened rules elsewhere in this revision replace cases
rather than only adding them.

Nineteen of those additions close a gap in the generator rather than in the contract. Where a
field rejects its zero enum with `not_in: [0]` and has no explicit presence, protojson drops the
value, so the emitted case pins "omission is rejected". The explicit `*_UNSPECIFIED` string is a
different parse path in a generated client — the name is absent from the emitted enum, so the
client must refuse it — and it had no case at all. The enum edge now emits the same
omitted/explicit pair that the `string.min_len`, `bytes.min_len` and `repeated.min_items` edges
already emitted, which is where the shape was copied from.

**Every addressed request names its recipient: `exchange` becomes required (breaking,
pre-1.0).** `ResourceQuery` (field 10), `DisputeRequest` (field 10), `RegisterRequest`
(field 3), `GetAccountStatusRequest` (field 2), `DomainVerificationRequest` (field 4),
`DomainVerificationConfirmation` (field 6), `PushResourcesRequest` (field 5),
`RemoveResourcesRequest` (field 4) and `RefreshCatalogRequest` (field 3) gain the field;
`UsageReport.exchange` keeps field 8 and is promoted from `optional`, which is the breaking
half — an absent or empty value used to skip the recipient check entirely, so the check was
opt-in for the caller, and it is now a rejection. The value is the bare host of the
recipient ("exchange.example", "exchange.example:8081"), never an endpoint URL: an endpoint
in the payload would hand the caller the choice of where the next hop dials, which is the
lever the well-known resolver exists to remove. A recipient MUST reject a request whose
`exchange` is not its own domain, with `INVALID_ARGUMENT` and no typed reason — a
mis-addressed request is malformed rather than a domain-level failure.

The signature does not already establish this. It proves the sender signed *the URL it
dialled*, not that the URL was right: the dial target is resolved from a fetched, cached
manifest, so a poisoned or stale resolution redirects the request while every signature
still verifies. The body field states whom the sender meant, independently of that
resolution, and the genuine recipient rejects a request naming someone else. The field is
stamped by whoever authors each request — the agent on the requests it signs, a Broker on
the legs it authors as sender — so it is a statement by that sender, not tamper-evidence
against it. On a verbatim-forwarded path the agent signs its `@target-uri` against the
final recipient's endpoint, not the Broker's. Two messages are exempt and
both absences are load-bearing: `DiscoveryRequest` travels one direct hop and terminates at
the Broker, which authors fresh per-Exchange `ResourceQuery` messages rather than
forwarding it, and the agent cannot name the fan-out set in any case
(`RequestConstraints.exchanges` stays its optional filter); `TransactionRequest` carries no
top-level field because its audience statement is per item.

The pattern is deliberately permissive — one or more labels, an optional port, no scheme,
path, query, userinfo or trailing root dot, and case normalised (both sides lowercase
before comparing). It matches the structural bare-host rule the reference clients already
apply, whose job is to stop a path or query being smuggled into a value that gets
concatenated into a URL, not to check that a name looks like a DNS record. A stricter rule
demanding a dotted name with an alphabetic suffix would reject single-label service hosts
such as `exchange:8081`, which real deployments use.

The same constraint is applied in one pass to the domain-carrying fields that until now
accepted any string at all: `ResourceResponse.exchange`, `RequestConstraints.exchanges`,
`RequestConstraints.preferred_exchanges`, `Requester.domain` and
`AuthorizedExchange.domain`. Tightening them is breaking for the same reason the
`UsageReport` promotion is — a value accepted today becomes a rejection — and it is done
now because one value space with two contracts is the state that produces the bugs.
`Requester.domain` earns it most: a verifier concatenates that value into
`{domain}/.well-known/ramp.json` and fetches the result, so a smuggled path or query would
choose WHAT gets fetched, not merely from where.
The port group spells the range out rather than counting digits: `:0` and `:99999` are
refused like any other value that cannot name a listening service, where a `[0-9]{1,5}`
group would have admitted both. And `TransactionDenial.exchange` is documented as a HINT,
not an instruction — it rides in a response, a relayed response passed through an
intermediary, so nothing signs it. A caller MUST check it against a domain it already
trusts for the transaction (the denied item's signed `offer.exchange`, or its own
`RequestConstraints.exchanges`) before acting, because registering hands an operator's
business data and a signed acceptance of that Exchange's terms to whoever answers. A conformance guard walks the descriptor
for every field carrying the shared pattern and asserts each refuses a scheme prefix, a
path or query suffix, userinfo, a malformed port, a trailing root dot and an empty label —
shapes the corpus generator cannot produce, because its bad-string table is shared with the
money and token fields and widening it there would add a mutant to every pattern-ruled
field in the contract.

**`Offer.exchange` is presence-enforced (breaking, pre-1.0).** It was a plain string with no
rule, so an empty value passed. It is the execute-routing target, the value a relaying
Broker groups a mixed batch by, and — because `TransactionRequest` has no top-level
`exchange` — the audience statement of an execute: on receipt an Exchange MUST reject the
request unless EVERY item's `offer.exchange` names its own domain. An empty value is
unroutable, and the swap-protection the offer signature is supposed to provide is vacuous
when the signed bytes carry no recipient at all. Adding the rule does not change any signed
bytes: a protovalidate rule is a field option, not a field.

**Manifest registration becomes a block: `WellKnownManifest.account_registration` (field 30)
replaces `registration_schema` (field 29), and `terms_digest` (field 31) joins `terms_uri`
(breaking, pre-1.0).** The new top-level `AccountRegistration` message carries the same JSON
Schema, now as `data_schema`, with the same publish-is-enforce contract and the same safety
rules. The block exists because registration has more than one publishable facet: field 2 is
left free for a future web mode, a URL to a page where a human completes steps an API call
cannot carry. The precedence rule is fixed now, while it is still cheap: an Exchange
publishing `data_schema` MUST accept registration through the API, and a registration URL is
an additional option an agent may offer its user, never a replacement. Field 29 is not
reused — the manifest already leaves 5 and 6 free after the WBA split, and appending keeps
the numbering legible.

`terms_digest` pins the document served at `terms_uri` in the existing `method:hexdigest`
form, and `RegisterRequest.terms_digest` (field 4) echoes it. A URL alone cannot say WHICH
terms were accepted: its content changes, so after the first revision every earlier
registration points at text that no longer says what was agreed. The echo is covered by the
request signature, and the Exchange records the accepted digest with the account — which
also makes keeping the historical terms documents retrievable the Exchange's obligation, since
a digest identifies a document only while a copy of it still exists. It sits at the top level
rather than inside the block so an Exchange with pass-through registration can still pin its
terms version; a message rule (`well_known_manifest.terms_digest_requires_terms_uri`) keeps
it from being published without the address it pins, mirroring the existing
`license.digest_required_with_uri`. Operators should treat first publication as a
coordinated change: it refuses every client that does not yet echo the value.

**`REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE` (additive, no wire break).** All
four digest cases are now defined rather than only the stale one. Matching echo: the
registration proceeds. Differing echo: refused with the new reason. Absent echo while the
Exchange publishes a digest: refused with the SAME reason, because the caller's remedy is
identical — read the manifest, echo, retry — and a second reason would split one fix in two.
An echo sent to an Exchange that publishes no digest: ignored, and explicitly NOT recorded as
an acceptance, since an Exchange publishing none cannot verify what document the value refers
to and storing it would put an unverifiable claim exactly where the field exists to hold a
verified one. A registering client MUST read the digest from a freshly fetched manifest
rather than a cached copy: a client cannot detect staleness locally — only the Exchange can —
so a warm cache would otherwise make it retry a refused value until the cache expired.
Registration happens once per Exchange, so the extra fetch is cheap.

**`DENIAL_REASON_BILLING_REF_INACTIVE` splits into `DENIAL_REASON_ACCOUNT_INACTIVE` (keeping
its wire number) and `DENIAL_REASON_ACCOUNT_NOT_REGISTERED`, and `TransactionDenial` gains
`exchange` (field 4) (breaking, pre-1.0).** The agent hits this wall at execute, not at
register, and the old single reason conflated two states of the caller with two different
remedies: wait for an operator to activate an account that exists, versus call `Register`
because none does — an action an agent can take unattended. The denial names the Exchange
that produced it, which on a relayed or fanned-out execute need not be one the agent named,
so the agent learns where to register without fetching a manifest to work it out. This
reverses a recorded decision; the reasoning, and why the neighbouring
`DELEGATION_EXPIRED` → `DENIAL_REASON_DELEGATION_INVALID` broadening still stands, are in
`docs/design-history.md` under "DenialReason consolidation".

**Contract text: `registration_data` is documented as business-registration data (no wire
change).** The details an Exchange needs to open a commercial account — legal entity,
address, jurisdiction, tax identifiers. The specific members stay operator-defined; what is
now explicit is that this is not an identity claim, since the caller's identity comes from
the verified request signature and nothing in the payload is trusted as authentication.

*Tooling:* the corpus grows from 208 to 319 cases and `Offer` enters it for the first time,
because a message with no field rules produces no cases at all and `Offer` previously had
none. `WellKnownManifest` gains a seed: auto-fill populates `terms_digest` (it carries a
pattern) but never `terms_uri` (no field rule to trigger on), so the generated baseline
would otherwise violate the new message rule. The reviewable part of that diff is the seed
and the pattern, not the generated output.

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
helpers exist for: one place per language where the ErrorDetail envelope is constructed. This is
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
(no wire change).** All `ver` fields — 29 at the time of this change (25 in `ramp.proto`, 4 in
`admin.proto`); the evidence-read envelopes later added 2 more with the same wording — now name
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
At introduction, two full-replace, idempotent setters for Exchange operators (the forensic
evidence read joined later in this cycle — see the entry above) —
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
