# PR #2 Website Sweep — `well-known-ramp-json-unified` @ `2fe4e6d`

Read-only verification of `/Users/konst/projects/RAMP-Protocol/protocol/website/`
against the proto-side intent of PR #2 (unified `/.well-known/ramp.json`,
`marketplace` → `exchange`, deprecation of `ProviderManifest` /
`ExchangeManifest`, addition of `WellKnownManifest`, `JsonWebKey`,
`KeyInvalidationList`, `Role`, etc.).

The PR's commit message explicitly defers two axes:
1. `orchestrator/` → `broker/` directory + link rename
2. "a Exchange" article-agreement grammar (also present in proto)

Findings about those two axes are **noted but not counted as PR drift**.

---

## A. Broken internal links from file renames

Searched the entire site for the three pre-rename basenames:
`components/marketplace`, `marketplace-manifest`, `for-marketplace-operators`.

```
$ grep -rn -E "(components/marketplace|marketplace-manifest|for-marketplace-operators)" website/{src,astro.config.mjs}
(no matches)
```

`astro.config.mjs` sidebar entries are clean (lines 19–48). The new
`for-exchange-operators` is linked from `src/content/docs/index.mdx:23`.

**Verdict: PASS.** No broken links from the renames.

### Sub-finding (out of scope but worth flagging)
The new file `src/content/docs/protocol/exchange-manifest.mdx` is **not in the
sidebar** (`astro.config.mjs` Protocol list, lines 29–41). The page is reachable
only via inline links — readers browsing the sidebar won't find it. The deleted
`marketplace-manifest.mdx` wasn't in the sidebar either, so this is a **pre-
existing gap, not new drift**, but still: this is the canonical reference page
for the new `WellKnownManifest` shape and almost certainly belongs in the
sidebar.

---

## B. Old well-known endpoint references

Searched for: `ramp-agent.json`, `ramp-exchange.json`, `ramp-verifier.json`,
`/marketplace/v1/keys`, `/exchange/v1/keys`, `keys_uri`, `jwks_uri`.

| File:line | Excerpt | Verdict |
|---|---|---|
| `src/content/docs/protocol/authentication.mdx:544` | "…The per-role files (`ramp-agent.json`, `ramp-exchange.json`, `ramp-verifier.json`) and the legacy `/exchange/v1/keys` endpoint are removed in v1.1.0; keys are inline JWKs." | **legitimate** (migration prose) |
| `src/content/docs/protocol/exchange-manifest.mdx:12` | "The legacy per-role `/.well-known/ramp-exchange.json` is **removed in v1.1.0**." | **legitimate** |
| `src/content/docs/protocol/exchange-manifest.mdx:118` | "(v1.0 used four per-role files — `ramp-agent.json`, `ramp-exchange.json`, `ramp-verifier.json`, and the provider `ramp.json`; the per-role variants are removed in v1.1.0.)" | **legitimate** |
| `src/content/docs/protocol/exchange-manifest.mdx:172` | "…its `keys_uri` pointer is replaced by inline `public_keys`." | **legitimate** |
| `src/content/docs/getting-started/poc-walkthrough.mdx:365` | ```curl http://localhost:3000/exchange/v1/keys``` | **DRIFT** — see below |
| `src/content/docs/reference/changelog.mdx:8,21,41,54` | All migration prose | **legitimate** |
| `src/content/docs/reference/proto-ramp.mdx:588,598` | Inside the **DEPRECATED** `ExchangeManifest` section | **legitimate** |

### B.1 — DRIFT (the one real bug in this section)

`src/content/docs/getting-started/poc-walkthrough.mdx`, lines 363–366:

```bash
# Test
curl http://localhost:3000/health
curl http://localhost:3000/exchange/v1/keys
```

This is teaching the reader to **use** an endpoint the same PR removed from the
spec. Should be:

```bash
curl http://localhost:3000/.well-known/ramp.json
```

(or whatever path the local PoC actually serves the unified manifest at).
**Verdict: drift to fix.**

### B.2 — Note on `keys_uri` / `jwks_uri`

Every remaining hit is in a deprecation explainer or the deprecated-message
reference table. None tells the reader to populate or consume those fields as
current behaviour. Clean.

---

## C. Deprecated message references (`ProviderManifest` / `ExchangeManifest`)

```
$ grep -rn "ProviderManifest\|ExchangeManifest" website/src --include="*.mdx"
```

Eleven hits across `exchange-manifest.mdx`, `changelog.mdx`, `proto-ramp.mdx`.

Every hit is in one of:
- explicit "deprecated in v1.1.0" prose,
- the JSON-rename table (`ProviderManifest.marketplaces` → `exchanges`),
- the reference page's labelled **DEPRECATED** sections
  (`proto-ramp.mdx:553,586`).

No JSON or YAML *example* in the site shows a `ProviderManifest` or
`ExchangeManifest` shape as the recommended producer output. The legacy
`marketplaces` array under provider is referenced only by name, never by shape.

**Verdict: PASS.**

---

## D. JSON examples use the new `WellKnownManifest` shape

Three places carry a full JSON manifest example:

### D.1 `src/content/docs/reference/ramp-json-example.mdx` (lines 10–52)

Publisher manifest. Has `ver`, `role: "ROLE_PUBLISHER"`, `domain`, `contact`,
`public_keys` (inline JWK with `kid`/`kty`/`crv`/`alg`/`use`/`x`/`not_before`/
`not_after`), `invalidation_url`, `catalog_contributors`, `exchanges`.

Cross-checked against `proto/ramp/v1/ramp.proto` lines 1774–1875:
- Field tags match (5=public_keys, 6=invalidation_url, 7=exchanges, 8=catalog_contributors).
- Embedded `protobuf` block at lines 116–158 mirrors the canonical proto.
- `Role` enum values match proto (line 1720).

**Verdict: PASS.**

### D.2 `src/content/docs/protocol/exchange-manifest.mdx` (lines 24–84)

Exchange manifest. Has `ver:"1.1"`, `role:"ROLE_EXCHANGE"`, `domain`, `name`,
`operator`, `operator_domain`, `endpoint`, inline `public_keys`,
`invalidation_url`, `health_endpoint`, `catalog_endpoint`,
`protocol_versions_supported`, `pricing_models_supported`,
`delivery_methods_supported`, `supported_profiles`, `base_currency`,
`hash_methods_supported`, `accepted_verifiers`, `supported_auth_methods`,
`oidc_issuer`, `contact`, `terms_uri`, `privacy_uri`.

All field tags and shapes match `proto/ramp/v1/ramp.proto` lines 1774–1875.
The example does **not** show `keys_uri` / `jwks_uri`. Clean.

**Verdict: PASS.**

### D.3 `src/content/docs/protocol/authentication.mdx` (lines 54–73 & 556–574)

Two embedded agent manifests. Both have `ver:"1.1"`, `role:"ROLE_AGENT"`,
`domain`, `contact`, `public_keys` with all required JWK fields and
`[not_before, not_after)` bounds.

**Verdict: PASS.**

---

## E. New `authentication.mdx` sections

Read `src/content/docs/protocol/authentication.mdx`:

| Section | Line | Verdict |
|---|---|---|
| Key Validity Windows | 588–590 | **PASS.** "The window is **half-open** `[not_before, not_after)` — a key is valid at `not_before` and invalid **at and after** `not_after`. At least one key in `public_keys` MUST be valid at serve time…" matches proto line 1791 invariant. |
| Caching Contract | 592–596 | **PASS.** Routine cache OK for `ramp.json`; `invalidation_url` body MUST be short / `no-store`. Notes operational-not-protocol-guaranteed enforcement. Mirrors proto comment block at lines 1680–1700. |
| Emergency Revocation | 598–600 | **PASS.** 300s cadence (±10% jitter), snapshot semantics, kid-only list, `as_of` + `revoked[]`. Matches `KeyInvalidationList` (proto 1886). |
| Domainless Agents | 602–604 | **PASS.** Registry-hosted `WellKnownManifest`; `Requester.domain` set to the registry host; "no protocol change"; deferral noted. Matches proto comment at lines 1701–1716. |

---

## F. `exchange-manifest.mdx` replaces `marketplace-manifest.mdx` cleanly

Read end-to-end. The page:
- Describes `WellKnownManifest` with `role=ROLE_EXCHANGE` (line 8).
- Calls out the unified `/.well-known/ramp.json` and "single canonical file
  every RAMP participant serves" (line 12).
- Documents inline-JWK keys (`public_keys`) with `not_before`/`not_after`
  (lines 33–43, 97, 180).
- Mentions the four-to-one migration explicitly (line 118).
- Calls the legacy `ExchangeManifest` **deprecated** and notes
  `keys_uri` is replaced by inline `public_keys` (line 172).
- Does **not** teach the old `keys_uri`/`jwks_uri` pointer pattern as current
  behaviour anywhere.

**Verdict: PASS.**

(Aside: the page links to `/components/broker/overview/` on line 210 — broken
until the deferred orchestrator→broker rename lands. Per commit message, this
is deliberately deferred.)

---

## G. `proto-ramp.mdx` has the new messages

Read `src/content/docs/reference/proto-ramp.mdx`:

| Item | Location | Verdict |
|---|---|---|
| `WellKnownManifest` section | lines 494–527 | **PASS.** Full field table; tags match proto. |
| `JsonWebKey` section | lines 529–542 | **PASS.** All 8 fields documented; half-open `[not_before, not_after)` window noted on line 542. |
| `KeyInvalidationList` section | lines 544–551 | **PASS.** Snapshot semantics, `as_of` + `revoked[]`. |
| `Role` enum | lines 880–890 | **PASS.** All five values (`UNSPECIFIED`, `AGENT`, `EXCHANGE`, `BROKER`, `PUBLISHER`). |
| `ProviderManifest` marked deprecated | line 553 | **PASS.** Explicit "DEPRECATED v1.1.0" heading. |
| `ExchangeManifest` marked deprecated | line 586 | **PASS.** Explicit "DEPRECATED v1.1.0" heading. |
| `DiscoveryMethod` rename `MARKETPLACE` → `EXCHANGE` | lines 892–900 | **PASS.** Value 1 = `EXCHANGE`. |

**Verdict: PASS.**

---

## H. `changelog.mdx` mirrors proto `CHANGELOG.md`

Versions present in proto CHANGELOG: v1.1.0, v1.0.2, v1.0.1, v0.3.0, v0.2.0.
Versions present in website changelog: v1.1.0, v1.0.2, v1.0.1, v1.0.

| Item | Verdict |
|---|---|
| v1.1.0 entry exists | **PASS** (line 6) |
| v1.0.2 entry exists | **PASS** (line 56) |
| v1.0.1 entry exists | **PASS** (line 74) |
| v1.1.0 has JSON-rename table | **PASS** (lines 27–35, 7 rows) |
| v1.1.0 says binary holds, JSON consumers MUST update | **PASS** (line 25: "All proto wire tags preserved; binary compatibility holds. JSON field names change. Every consumer reading renamed fields MUST update.") |
| v1.1.0 covers deprecations | **PASS** (lines 17–21) |
| v1.1.0 covers verifier transition | **PASS** (lines 39–41) |
| v1.1.0 covers caching contract / key-validity / domainless | **PASS** (lines 43–47) |
| v1.0.3 from PR #1 | **NOT PRESENT** — but PR #1 was a small clarification PR; task notes this is optional. **Verdict: not drift.** |

Minor note: the website changelog has a `## v1.0` section (lines 100–153)
where the proto CHANGELOG has `## v0.3.0` and `## v0.2.0`. This is a stylistic
choice (lump the pre-v1.0 history under a single "v1.0" header) that predates
this PR. Not in scope for PR #2.

**Verdict: PASS.**

---

## I. Build sanity

`/Users/konst/projects/RAMP-Protocol/protocol/website/node_modules/` **does
not exist** on disk (the initial `ls` returned `EXISTS` only because of bash
shortcircuit semantics — directly listing the path returns
`No such file or directory`, and `npm run build` fails with
`sh: astro: command not found`).

Per instructions: skipped `npm install` and skipped the build. Build sanity
**not independently verified**. The author's claim of "73 pages green" stands
unchecked.

---

## J. Contradictions vs. the new proto

Sweep results:

- **`marketplaces` (publisher field) as current:** Not present. Only in
  rename tables / migration prose.
- **JWKS-URI lookup taught as current:** Not present. Every `keys_uri` /
  `jwks_uri` hit is in deprecation context. The OAuth `jwks.json` reference
  in `components/mcp-server/overview.mdx:95` is for an unrelated OIDC OAuth
  flow (`--oauth-jwks-url`), not RAMP key publication.
- **"JWKS pattern" mentions** in `security/threat-model.mdx:201`,
  `content-attestation.mdx:132`, `ext-c2pa.mdx:200,210` — these use "JWKS"
  generically to describe the inline-key-with-validity-window approach. Not
  contradictory with the new proto (the keys *are* RFC 7517 JWKs, just
  inline). **Legitimate.**
- **No dedicated verifier role:** Consistently stated across
  `content-attestation.mdx:90`, `ext-c2pa.mdx:217`,
  `edge-function/overview.mdx:15`, `production-architecture.mdx:94`,
  `for-providers.mdx:178`, `for-verification-vendors.mdx:198`,
  `threat-model.mdx:190`, `changelog.mdx:15`, `exchange-manifest.mdx:126`.
  Matches proto comment at line 673.
- **`MARKETPLACE_*` env vars:** Zero remaining occurrences in `*.mdx`.
- **`a Exchange` grammar:** ~15 occurrences (`extension-profiles.mdx:271`,
  `discovery-paths.mdx:275`, `scenario-walkthrough.mdx:774`,
  `agent-sdk/fetch-flow.mdx:135`, `agent-sdk/budget-reporting.mdx:188,244`,
  `exchange/overview.mdx:8`, `exchange/storage-model.mdx:259`,
  `exchange/multi-tenant.mdx:8`, `mcp-server/overview.mdx:10`,
  `edge-function/overview.mdx:22`, `ext-legal.mdx:111`). **Deferred by
  commit; not counted as PR drift.**

**Verdict: PASS** (no semantic contradictions with the new proto).

---

## Overall: PASS (with one drift fix and two known deferrals)

The website is substantively coherent with PR #2's proto changes. The
`marketplace`→`exchange` rename, the unification of `/.well-known/ramp.json`,
the introduction of `WellKnownManifest`/`JsonWebKey`/`KeyInvalidationList`/
`Role`, the deprecation of `ProviderManifest`/`ExchangeManifest`, and the four
new authentication-page sections (key validity windows, caching contract,
emergency revocation, domainless agents) are all consistently propagated.

JSON examples carry the correct shape and field tags. Deprecation references
are clearly labelled. The JSON-rename table in the changelog matches the
proto rename intent (binary holds, JSON consumers MUST update).

### Prioritized fix list

1. **[P1 — drift]** `src/content/docs/getting-started/poc-walkthrough.mdx:365`
   — replace `curl http://localhost:3000/exchange/v1/keys` with
   `curl http://localhost:3000/.well-known/ramp.json` (or the path the local
   PoC actually serves; verify locally). The current command teaches readers
   to hit an endpoint the same PR removed from the spec.

2. **[P2 — discoverability]** Add `protocol/exchange-manifest` to the
   `astro.config.mjs` Protocol sidebar (between Authentication and Dispute
   Resolution, say). The new reference page for the unified well-known
   document is currently unreachable from the sidebar. Pre-existing gap,
   but worth fixing while reviewing this PR.

3. **[Deferred — known]** `orchestrator/` → `broker/` directory rename and
   the ~10 dangling `/components/broker/...` links (`exchange-manifest.mdx:210`,
   `agent-sdk/overview.mdx:12`, `mcp-server/overview.mdx:10`,
   `orchestrator/budget-enforcement.mdx:89`, `orchestrator/content-dedup.mdx:162`,
   `orchestrator/selection-engine.mdx:361`, `exchange/health-checks.mdx:16,121`,
   `poc-walkthrough.mdx:345,382`). Per PR #2 commit message, deferred to a
   separate change.

4. **[Deferred — known]** "a Exchange" → "an Exchange" article-agreement pass
   (~15 occurrences listed under §J). Per PR #2 commit message, also present
   in proto, deferred.

5. **[Optional — not drift]** Consider adding the v1.0.3 changelog entry from
   merged PR #1 if that change has user-visible impact. Currently missing
   from both proto CHANGELOG and website changelog.
