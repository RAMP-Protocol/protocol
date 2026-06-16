# Requested changes

1. **Regenerate `gen/`.** `cd proto && buf generate` produces a non-empty diff: `RAMPResponse`'s descriptor in the embedded `FileDescriptorProto` is 152 bytes short of the actual schema (missing fields 13 / 14 from PR #1). Struct-based code works; reflection-based code (gRPC reflection, descriptor JSON, dynamic dispatch) does not. Commit the regenerated `gen/`.

2. **Replace the removed `/exchange/v1/keys` endpoint** with `/.well-known/ramp.json`:
   - `website/src/content/docs/getting-started/poc-walkthrough.mdx:360` (live `curl` example)
   - `website/src/content/docs/protocol/authentication.mdx:555` (prose)

3. **Replace `Marketplace` with `Exchange`** in `proto/comp/v1/comp.proto:53` and `:126`.

4. **Re-encode `ext-news.mdx:400`.** The `exchange_signature` placeholder is `bWFya2V0cGxhY2Utc2lnbmF0dXJl...`, which base64-decodes to `marketplace-signature`. Encode `exchange-signature` (or any non-stale string) instead. (`:469` decodes to `npr-podcast-signature` — looks intentional for the news extension; confirm.)

5. **Finish the `orchestrator → broker` rename.** It's already half-done — the website currently has ~10 inbound links to `/components/broker/*` paths that 404 because the directory is still `components/orchestrator/`.
   - Proto: rename `Orchestrator(s)` in `proto/ramp/v1/ramp.proto` (lines 147, 261, 296, 434, 445, 743). Will mirror to `gen/` on `buf generate`.
   - Website: `git mv website/src/content/docs/components/orchestrator/ .../components/broker/` (3 files).
   - Fix `website/src/content/docs/index.mdx:58` — label `"Broker"` with href pointing at the old `/components/orchestrator/overview/`.

6. **Grammar pass: `a Exchange` → `an Exchange`, `an Broker` → `a Broker`.** ~30 occurrences across proto + website. Pattern is perfectly asymmetric — every `a Exchange` is wrong, every `an Broker` is wrong.

7. **Add `protocol/exchange-manifest.mdx` to the sidebar** in `website/astro.config.mjs`.

8. **Convert camelCase → snake_case** in `website/src/content/docs/getting-started/poc-walkthrough.mdx:130, 142, 157` (`exchangeSignature` → `exchange_signature`, `offerSignature` → `offer_signature`). Every other walkthrough uses snake_case.

9. **Pin the deprecation removal version** in `proto/CHANGELOG.md`. Currently says "next minor release"; replace with a concrete target (e.g. `v1.2.0`).
