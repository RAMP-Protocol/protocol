# PR #2 — Multi-Agent Sweep Synthesis

**Scope**: full working tree of branch `well-known-ramp-json-unified` at HEAD `2fe4e6d` (after the two follow-up commits `480cadd` proto + `2fe4e6d` website).
**Agents**: 3 — terminology, intent, website.
**Stance**: read-only verification; no rebase/resolve (per user, author's job).

## Verdict

**Pass on intent. Material drift on terminology. One real bug in a getting-started example.** No mechanical or wire issues. Recommend a follow-up commit before merge that resolves §A and §B; §C/§D are nits.

---

## Mechanical (PASS)
- `buf generate` produces zero diff vs committed `gen/`.
- `buf lint` clean.
- `buf breaking` vs `main` clean (after the `buf.yaml except` rules for the rename).
- `astro build` not independently verified — author asserts "73 pages green"; the sweep didn't have `node_modules` available and the instructions said don't `npm install`.

## Intent (PASS, with minor footnotes)
All 12 deliverables verified by the intent agent: `WellKnownManifest` (`:1774`), `JsonWebKey` (`:1737`), `KeyInvalidationList` (`:1886`), `Role` enum (`:1720`, no `ROLE_VERIFIER`), the `480cadd` half-open `[not_before, not_after)` fix (`:1735`), caching contract (`:1691-1702`), domainless-requester note (`:1704-1714`), all four deprecation annotations, full CHANGELOG including `480cadd` follow-ups (`:65-75`), `buf.yaml` suppressions with explanatory comment.

---

## Findings — prioritized for the author

### §A — must-fix (real bugs / internal contradictions)

| # | File:line | Issue |
|---|---|---|
| A1 | `website/.../poc-walkthrough.mdx:365` | Tells reader to `curl http://localhost:3000/exchange/v1/keys` — an endpoint **this PR removes**. Fix to `/.well-known/ramp.json`. |
| A2 | `website/.../protocol/authentication.mdx:544` | Prose still references `/exchange/v1/keys`. Same fix. |
| A3 | `website/.../protocol/authentication.mdx:301` | Signature-fields table still lists `orchestrator_signature` — directly contradicts the same page at `:286` which says the field was renamed. **Self-contradiction within one document.** |
| A4 | `website/.../ext-news.mdx:400` | The `exchange_signature` JSON example value base64-decodes to literally `"marketplace-signature"`. Re-encode the placeholder. |
| A5 | `proto/comp/v1/comp.proto:53` & `:126` | Two surviving `Marketplace` mentions in comp.proto comments — missed by the rename sweep. |

### §B — the deferred axes the user explicitly pulled back into scope

The author's `2fe4e6d` commit message says *"Deferred (separate axes): orchestrator→broker rename; the 'a Exchange' grammar artifact"*. You said: **do them now**.

**B1 — `orchestrator → broker` rename, end-to-end:**

- **Proto**: 6 occurrences of `Orchestrator(s)` in `proto/ramp/v1/ramp.proto` (lines `131, 245, 280, 418, 429, 727`). Mirrored automatically into `gen/go/...` and `gen/ts/...` via `buf generate` — so the proto fix is the only edit; SDKs regenerate.
- **Website dir**: still `website/src/content/docs/components/orchestrator/` (3 files). Rename to `.../components/broker/`.
- **Dead inbound links**: ~10 other docs already link to `/components/broker/...` — those become live the instant the directory rename lands. *Without* the rename, those links are 404s.
- **Reverse-dead link**: `website/src/pages/index.astro` and `website/.../index.mdx:58` show *"Broker"* as the label but href points at `/components/orchestrator/overview/`. Same rename fixes both directions.

**B2 — "a Exchange" / "an Broker" grammar (49 occurrences total):**

- Pattern is consistent: *every* `a Exchange` is wrong (→ `an Exchange`); *every* `an Broker` is wrong (→ `a Broker`).
- Present in **both** proto and website. Trivial sed-able pass.

### §C — discoverability / housekeeping (small)

| # | File:line | Issue |
|---|---|---|
| C1 | `website/astro.config.mjs` | The new `protocol/exchange-manifest.mdx` (the canonical `WellKnownManifest` page) is **not in the sidebar**. The deleted `marketplace-manifest.mdx` wasn't either, so it's pre-existing — but easy to fix now. |
| C2 | `website/.../poc-walkthrough.mdx:130,142,157` | Uses camelCase `exchangeSignature`/`offerSignature` while every other walkthrough uses `snake_case`. RAMP convention is snake_case. |
| C3 | `proto/CHANGELOG.md` (deprecation block) | States deprecation removal "next minor release" but no tracked schedule or target version. Nice-to-have to pin. |

### §D — style only (defer freely)
The grammar items in B2 are cosmetic; if you'd rather keep them out of this PR for review-surface reasons, that's defensible. Everything in §A and B1 should land before merge.

---

## Legitimate retentions (sweep confirmed — should stay)

- `proto/CHANGELOG.md` v1.1.0 — the rename table, "Renamed from `marketplaces` in v1.1.0" annotations on proto fields, `(Renamed from ProviderManifest.marketplaces)` notes — historical/migration prose.
- `proto/buf.yaml` — `except: FIELD_SAME_NAME` block with its explanatory comment about the rename.
- `website/.../reference/changelog.mdx` v1.1.0 — mirrors the rename table.
- `proto/ramp/v1/ramp.proto` — deprecation comments on `ProviderManifest` / `ExchangeManifest` may mention the old terminology in the migration explanation.

Roughly ~30 such legitimate "marketplace" mentions across these surfaces. Sweep agent confirms each is migration-explainer prose, not drift.

---

## Cross-PR note (informational, not actionable here)

After PR #1's squash-merge as `b7c3b1e`, `proto/CHANGELOG.md` on `main` has `v1.0.3`. PR #2's CHANGELOG has `v1.1.0` but not `v1.0.3`. When the author rebases, they'll need to interleave (`v1.1.0` above, `v1.0.3` below). The website changelog likewise needs `v1.0.3` added. **Not in scope of this sweep** — flagged so it doesn't get lost.
