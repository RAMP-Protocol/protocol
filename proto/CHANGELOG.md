# RAMP Protocol Changelog

## Unreleased

Additive, non-breaking (1.0.x). Introduces the buf-native vocabulary mechanism
for open metering-basis tokens: a `(ramp.v1.vocab)` custom field option
(`FieldOptions` extension 50001, defined in `ramp/v1/vocab.proto`) carries the
registered bare tokens directly on `Pricing.unit`, and the `protoc-gen-rampvocab`
buf plugin emits typed Go constants (`gen/go/vocab/pricingunits`), `All`, and
`IsRegistered`. Adopts `protovalidate`: a structural field CEL on `Pricing.unit`
(empty / lowercase-dashed / `vendor:namespaced`) and message-level CEL on
`Pricing` (`PER_UNIT ⇒ unit`, `FREE ⇒ rate 0`). Adding a unit edits the option
list only — no message-shape change. Replaces the side-car
`vocab/pricing-units.json` registry.

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

The reasoning behind the major design decisions is recorded in
[`docs/design-history.md`](../docs/design-history.md).
