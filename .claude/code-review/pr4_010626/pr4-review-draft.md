# PR #4 — RAMP v1.0 clean-cut — review draft

**Ticket:** RAMP-1 (matched on title, not referenced in the PR body).
**Branch:** `v1.0-clean-cut` @ `3d204f3`.
**Stance:** request changes — one real issue, otherwise clean.

## Mechanical (PASS)

- `buf lint` clean.
- `buf generate` reproduces the committed `gen/` (zero diff).
- `buf breaking` against `main` reports the intentional, well-scoped breaks (reserved-range removal, deprecated message removal, field deletions on the messages the commit message names). Aligns with the "intentionally breaking, no external clients" framing in the README note.
- `website/` builds clean: 73 pages, no new warnings.

## Acceptance criteria (RAMP-1) — all met or accounted for

- [x] No `reserved` blocks remain in `proto/ramp/v1/ramp.proto`.
- [x] Field renumbering done on the messages listed in the commit body (ResourceQuery, Requester, TransactionRequest, TransactionItem, PushResourcesRequest, DisputeRequest, DomainVerificationRequest, DomainVerificationConfirmation). WellKnownManifest retains its non-contiguous numbering — defensible (already widely cited as a wire-format anchor for the well-known doc).
- [x] Three multi-hop additions present: `WellKnownManifest.max_intermediary_hops = 28`, `RequestConstraints.max_hops = 11`, `IntermediaryHop.signature_label = 4`. Documented inline.
- [x] Response-path coverage: explicit "responses do not retrace the chain" prose in `ramp.proto:1019-1023` (IntermediaryHop header) and mirrored at `transaction-flow.mdx:27`.
- [x] `proto/CHANGELOG.md` collapsed to a single `v1.0.0 — Initial release` entry.
- [x] `docs/design-history.md` captures the rationale for RFC 9421 hop auth, marketplace→exchange, unified WellKnownManifest, inline JWKs, CoMP-as-extension, and attestations-vs-quality-scores.
- [x] `buf.yaml`: rename-era `breaking.except` suppressions dropped.
- [x] `reference/proto-ramp.mdx` re-mirrored to the new field numbers, with new `signature_label`, `max_hops`, `max_intermediary_hops` rows.
- [x] `reference/changelog.mdx` collapsed to the same single v1.0.0 entry.
- [x] README carries an explicit "pre-1.0 clean-cut — no backward-compat guarantees" note.

No surviving `Marketplace`, `ProviderManifest`, `ExchangeManifest`, `marketplace-manifest`, `ramp-exchange.json`, `ramp-agent.json`, `ramp-verifier.json`, or `/exchange/v1/keys` references in `proto/` or `website/src/content/docs/`.

## Requested changes

1. **Strip the per-version archaeology block from `proto/comp/v1/comp.proto:6-12`.** The commit body says it strips per-version archaeology comments and the squash narrative is built around that, but the comp.proto sibling preamble was not touched — it still carries:

   ```
   // v0.2 additions:
   //   - License message + LicenseUse enum (CoMP §license.json)
   //   - Package.license: repeated License for per-package licensing terms
   //   - Retrieval.ratelmt: rate limit signaling on retrieval endpoints
   //   - Text.authority, Text.originality: content quality signals
   //   - Video.c2pa, Image.c2pa, Audio.c2pa: C2PA content credentials
   //   - Image.alt, Image.caption: accessibility and display metadata
   ```

   This block names *what RAMP added on top of CoMP* across pre-v1.0 revisions — exactly the archaeology the rest of the PR removed. Two ways to resolve:

   a. **Drop the block.** Most consistent with the squash story; the comment above it already explains that `comp.proto` is a 1:1 mapping of the IAB CoMP spec, which is the only invariant a reader needs.

   b. **Restate it as a single non-versioned paragraph** that describes the RAMP-side additions to CoMP (License/LicenseUse, per-package license, retrieval rate-limits, C2PA fields, etc.) without the "v0.2 additions:" header — same content, no version archaeology.

   Either works; (a) is the lower-risk default.
