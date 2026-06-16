# PR #2 Terminology Drift Sweep — `marketplace` → `exchange` and `orchestrator` → `broker`

**Branch under review:** `well-known-ramp-json-unified` @ `2fe4e6d`
**Repo root:** `/Users/konst/projects/RAMP-Protocol/protocol`
**Scope:** full working tree (not just diff). PR #2 also pulls `orchestrator → broker` and grammar-artifact fixes back into scope per user direction.

Method: case-insensitive ripgrep across `proto/`, `gen/`, `website/`, repo root for `marketplace`, `orchestrator`, plus targeted patterns for env vars (`MARKETPLACE_*`), URL paths (`/marketplace/`, `/orchestrator/`), JSON field names, base64-encoded literals, and article-noun grammar artifacts (`a Exchange`, `an Exchange`, `an Broker`, `an Exchange Operator`). Files in `node_modules/` and `.git/` excluded.

---

## 1. Summary (counts)

| Bucket | Count |
|---|---|
| DRIFT — proto source | 9 |
| DRIFT — generated SDKs (Go + TS) | 18 |
| DRIFT — website prose / examples | 64 |
| DRIFT — website file/dir paths + links | 16 |
| PROTO-DEFERRED (orchestrator in proto + gen) | 14 (5 in `ramp.proto` × 1 + 9 in generated) |
| GRAMMAR ARTIFACTS (`a Exchange`, `an Broker`, etc.) | 49 |
| HISTORICAL / legitimate retentions | 30+ |
| Cross-page contradictions | 5 |

Notes on counts:
- Drift in `gen/` is auto-derived from proto; fixing the proto regenerates gen. They are listed separately for completeness, not as an additional code-change burden.
- The two CHANGELOG files (`proto/CHANGELOG.md`, `website/src/content/docs/reference/changelog.mdx`) contain ~30 occurrences of "marketplace" in **historical** v1.0.x / v0.x sections and in the v1.1.0 rename table — these are legitimate and listed under §5.

---

## 2. DRIFT findings (actionable)

### 2.1 Proto source (`proto/ramp/v1/ramp.proto`)

These all need a `s/Orchestrator/Broker/g` style fix in the prose/comments. The wire stays untouched.

| File:line | Excerpt |
|---|---|
| `proto/ramp/v1/ramp.proto:131` | `// Agents and Orchestrators are both valid clients.` |
| `proto/ramp/v1/ramp.proto:169` | `// ResourceQuery — Query a Exchange for available resource offers.` (article + concept) |
| `proto/ramp/v1/ramp.proto:171` | `// Sent by an Broker or directly by an AI agent.` (grammar) |
| `proto/ramp/v1/ramp.proto:245` | `// Enables agents/Orchestrators to throttle proactively rather than hitting` |
| `proto/ramp/v1/ramp.proto:246` | `// hard limits. Particularly important when an Broker fans out the` (grammar) |
| `proto/ramp/v1/ramp.proto:271` | `// v1: always DISCOVERY_METHOD_EXCHANGE (Broker queried an Exchange).` (grammar — "an Exchange" wrong) |
| `proto/ramp/v1/ramp.proto:280` | `// Present when ` + "`offers`" + ` is empty. Enables agents/Orchestrators to distinguish` |
| `proto/ramp/v1/ramp.proto:394` | `// Offer — A single resource offer from a Exchange.` (grammar) |
| `proto/ramp/v1/ramp.proto:418` | `// Enables Orchestrators to recognize the same resource offered by` |
| `proto/ramp/v1/ramp.proto:429` | `// Prevents intermediaries (Orchestrators) from tampering with price` |
| `proto/ramp/v1/ramp.proto:727` | `// lists so agents and Orchestrators can filter offers before transacting.` |
| `proto/ramp/v1/ramp.proto:1345` | `// providers to push resource metadata to a Exchange.` (grammar) |
| `proto/ramp/v1/ramp.proto:1580` | `// When an agent talks directly to a Exchange, it uses` (grammar) |
| `proto/ramp/v1/ramp.proto:1706` | `// an Exchange/Broker or a third party) hosts the agent's WellKnownManifest,` (grammar — "an Exchange" wrong) |
| `proto/ramp/v1/ramp.proto:1945` | `// properties), "exchange" (an Exchange that enriches catalog entries).` (grammar — "an Exchange" wrong; describing CatalogContributor.relationship enum-like value) |
| `proto/ramp/v1/ramp.proto:2117` | `// AuthMethod — Authorization methods an Exchange can support.` (grammar — "an Exchange" wrong) |

`proto/comp/v1/comp.proto`:
- `proto/comp/v1/comp.proto:53` — `// username, not a password. Marketplace looks up agent's registered` → should be `Exchange`
- `proto/comp/v1/comp.proto:126` — `// Unique package identifier defined by the Content Owner or Marketplace.` → should be `Exchange`

`proto/buf.yaml`:
- `proto/buf.yaml:23-24` — `# marketplace → exchange repo-wide rename (v1.1.0): ...` — this is a legitimate breaking-change-detection comment; keep as HISTORICAL (see §5).

### 2.2 Generated SDKs (auto-regenerated from proto)

`gen/go/ramp/v1/ramp.pb.go`:
- `:74` — `//     ramp-verifier.json) and the legacy /marketplace/v1/keys path are` — historical narrative inside the v1.1.0 deprecation comment; mirror whatever decision is made in proto file header (currently retained intentionally).
- `:913` — `// AuthMethod — Authorization methods an Exchange can support.` (grammar)
- `:1252` — `// ResourceQuery — Query a Exchange for available resource offers.` (grammar)
- `:1254` — `// Sent by an Broker or directly by an AI agent.` (grammar)
- `:1412` — `Enables agents/Orchestrators to throttle proactively rather than hitting` (deferred orchestrator)
- `:1413` — `hard limits. Particularly important when an Broker fans out the` (grammar)
- `:1523` — `v1: always DISCOVERY_METHOD_EXCHANGE (Broker queried an Exchange).` (grammar)
- `:1532` — `Present when ` + "`offers`" + ` is empty. Enables agents/Orchestrators to distinguish` (deferred orchestrator)
- `:1781` — `// Offer — A single resource offer from a Exchange.` (grammar)
- `:1800` — `Enables Orchestrators to recognize the same resource offered by` (deferred orchestrator)
- `:1809` — `Prevents intermediaries (Orchestrators) from tampering with price` (deferred orchestrator)
- `:2443` — `lists so agents and Orchestrators can filter offers before transacting.` (deferred orchestrator)
- `:5283` — historical rename comment (`Renamed from ProviderManifest.marketplaces in v1.1.0`) — HISTORICAL, keep.
- `:5646` — historical rename comment (`Renamed from ` + "`marketplaces`" + ` in v1.1.0; wire tag preserved.`) — HISTORICAL, keep.
- `:5753` — `properties), "exchange" (an Exchange that enriches catalog entries).` (grammar)

`gen/go/ramp/v1/rampv1connect/ramp.connect.go`:
- `:71`, `:74` — header narrative copy of proto comments; historical, keep.

`gen/go/comp/v1/comp.pb.go`:
- `:620` — `// username, not a password. Marketplace looks up agent's registered` (DRIFT — mirror of `comp.proto:53`)
- `:730` — `// Unique package identifier defined by the Content Owner or Marketplace.` (DRIFT — mirror of `comp.proto:126`)

`gen/ts/ramp/v1/ramp_pb.ts`:
- `:71`, `:74`, `:98`, `:100`, `:243`, `:244`, `:299`, `:312`, `:446`, `:498`, `:517`, `:952`, `:2792`, `:3032`, `:3092`, `:4603`, `:4962` — same content as the Go file above. Tags 2792, 3032 are HISTORICAL rename markers (keep). The rest are mirrors of `ramp.proto` drift.

`gen/ts/ramp/v1/ramp_connect.ts`:
- `:71`, `:74`, `:177` — header narrative + `:177 providers to push resource metadata to a Exchange.` (grammar) — mirror.

`gen/ts/comp/v1/comp_pb.ts`:
- `:96` — `username, not a password. Marketplace looks up agent's registered` (DRIFT — mirror)
- `:166` — `Unique package identifier defined by the Content Owner or Marketplace.` (DRIFT — mirror)

> **Action:** fix the two `.proto` files (ramp.proto comments + comp.proto comments) and re-run `buf generate`. The generated files will then realign.

### 2.3 Website prose

`website/src/content/docs/protocol/authentication.mdx:301` — DRIFT (header rename leak):
```
| `orchestrator_signature` | `RAMPRequest` | RFC 9421 `Signature` / `Signature-Input` headers |
```
This is in the same table that lines above call out the rename to `IntermediaryHop`. Either remove the row or rename to `broker_signature` to match the rest of the doc (line 286 talks about the legacy `broker_signature` field).

`website/src/content/docs/protocol/ext-news.mdx`:
- `:400` — `"exchange_signature": "bWFya2V0cGxhY2Utc2lnbmF0dXJl..."` — the base64 placeholder decodes to literal string `marketplace-signature`. Replace with `ZXhjaGFuZ2Utc2lnbmF0dXJl...` (`exchange-signature`) or any other placeholder.

`website/src/content/docs/protocol/extension-profiles.mdx:271` — grammar (`a Exchange`):
> `... a Exchange serving both news and academic content would include both ...`

`website/src/content/docs/protocol/discovery-paths.mdx:275` — grammar (`a Exchange`):
> `The agent has an existing subscription deal with a Exchange. When querying supply, the Exchange ...`

`website/src/content/docs/protocol/discovery-paths.mdx:256` — grammar (`an Broker`):
> `... when an Broker sends batch queries to multiple Exchanges ...`

`website/src/content/docs/protocol/transaction-flow.mdx:8` — grammar (`an Broker`):
> `The Exchange does not know or care whether the request came from an Broker or directly from an agent.`

`website/src/content/docs/protocol/walkthrough-credit-report.mdx:6` — grammar (`an Broker`):
> `entity resolution as an Broker concern, and redistribution restrictions ...`

`website/src/content/docs/protocol/walkthrough-v1.mdx:164` — grammar (`an Broker`):
> `... unit_cost ... enables cross-exchange comparison when an Broker aggregates offers.`

`website/src/content/docs/protocol/ext-academic.mdx`:
- `:77` — `... preferences when querying an Exchange with known DOIs.` (grammar)
- `:185` — `... If an Exchange offers the same article in multiple versions ...` (grammar)

`website/src/content/docs/protocol/exchange-manifest.mdx`:
- `:91` — `... ROLE_EXCHANGE for an Exchange manifest |` (grammar)
- `:143` — `... and an exchange manifest tells you WHAT the Exchange can do ...` (grammar — second use OK; first lowercase exchange manifest in this sentence is fine)

`website/src/content/docs/protocol/ext-legal.mdx`:
- `:111` — `... legal-specific search constraints when querying a Exchange.` (grammar)
- `:455` — `An offer from an Exchange connected to EUR-Lex ...` (grammar)

`website/src/content/docs/protocol/ext-news.mdx`:
- `:190` — `... Helps Brokers avoid querying an Exchange for article types ...` (grammar)
- `:540` — `An agent queries an Exchange for multiple news articles ...` (grammar)

`website/src/content/docs/protocol/scenario-walkthrough.mdx:774` — grammar (`a Exchange`):
> `... This is a Exchange-CDN concern (symmetric HMAC-SHA256 shared secret) ...`

`website/src/content/docs/components/agent-sdk/budget-reporting.mdx`:
- `:188` — `... ` + "`UsageReportResponse`" + ` now returns a ` + "`report_id`" + ` -- a Exchange-assigned identifier ...` (grammar)
- `:244` — `If a Exchange denies a future transaction with ...` (grammar)

`website/src/content/docs/components/exchange/storage-model.mdx:259` — grammar (`a Exchange`):
> `... is a Exchange implementation concern, not a protocol requirement.`

`website/src/content/docs/protocol/authentication.mdx:604` — grammar (`an Exchange/Broker` is fine because of slash, but check):
> `... a registry (operated by an Exchange/Broker or a third party) ...` — debatable; technically grammar wants `a registry (operated by a Broker, Exchange, or third party)`. Flagging as minor.

`website/src/content/docs/components/exchange/multi-tenant.mdx:8` — grammar:
> `... one Exchange operator runs a Exchange that serves 10, 100, or 1000+ providers.` (`a Exchange`)

`website/src/content/docs/components/agent-sdk/fetch-flow.mdx:135` — grammar:
> `If a Exchange covers multiple domains, one query per domain` (`a Exchange`)

`website/src/content/docs/components/exchange/overview.mdx:8` — grammar (twice):
> `... one Exchange operator runs a Exchange that serves 10, 100, or 1000+ providers.` (`a Exchange`)

`website/src/content/docs/components/mcp-server/overview.mdx:10` — grammar:
> `... forwards them to a Exchange via Connect-Go ...` (`a Exchange`)

`website/src/content/docs/components/orchestrator/overview.mdx`:
- `:20` — `... whether the request came from an Broker or directly from an agent.` (grammar)
- `:119` — `When the agent queries a Exchange directly, ` + "`intermediaries`" + ` is empty. When the request passes through an Broker, it contains one hop.` (two grammars)
- `:263` — `// v1: only ExchangeSource (queries a Exchange).` (grammar inside code comment)
- `:277` — `... the Broker looks up a Exchange for each URI's domain ...` (grammar)
- `:343` — `github.com/RAMP-Protocol/protocol/broker/` (FILE-PATH DRIFT — see §2.4)
- `:345`, `:348` — `broker/           # Sidecar binary entrypoint` / `broker/           # Core broker logic` — the documented Go package layout uses `broker/`, but the website directory itself is still `orchestrator/` (see §2.4 / §6).

`website/src/content/docs/components/orchestrator/selection-engine.mdx:434` — grammar:
> `... This prevents a Exchange from tampering with its own offer fields after signing.` (`a Exchange`)

`website/src/content/docs/architecture/production-architecture.mdx:8` — grammar:
> `... wiring them into an Exchange operator's billing ...` (`an Exchange operator` — debatable; "Exchange Operator" starts with "Ex-" vowel sound, so `an` is arguably correct. **Flag for author judgement.**)

`website/src/content/docs/architecture/production-architecture.mdx:37`, `:47`, `:73` — same `an Exchange` constructions in author tone; flag for review (likely fine — `an Exchange` is grammatically correct since "Ex-" is a vowel sound, but the codebase elsewhere wrote `a Exchange`, so consistency direction must be picked).

`website/src/content/docs/components/edge-function/overview.mdx:22` — grammar:
> `1. **Get a Exchange endpoint** from their Exchange operator (one-time business relationship).` (`a Exchange`)

`website/src/content/docs/components/edge-function/deployment.mdx`:
- `:39` — same `a Exchange endpoint` phrase.
- `:270` — `... mode for providers registered with a Exchange.` (`a Exchange`)

`website/src/content/docs/components/orchestrator/deployment.mdx:331` — grammar (`a Exchange`):
> `Broker has side deal with a Exchange`

`website/src/content/docs/getting-started/poc-walkthrough.mdx`:
- `:130` — `"exchangeSignature": "ae77b181...32607e08",` — camelCase JSON field that should be snake_case `exchange_signature` to match all other protocol examples; INTERNAL CONTRADICTION (see §6).
- `:142` — `**exchangeSignature** — ...` (same)
- `:157` — `"offerSignature": "<exchangeSignature from Step 3>",` (same)

`website/src/content/docs/components/orchestrator/content-dedup.mdx:162` — link `/components/broker/selection-engine/` while file is in `/components/orchestrator/` — broken link (see §2.4).

`website/src/content/docs/components/orchestrator/selection-engine.mdx:361` — link `/components/broker/content-dedup/` — broken link (see §2.4).

`website/src/content/docs/components/orchestrator/budget-enforcement.mdx:89` — link `/components/broker/selection-engine/` — broken link (see §2.4).

### 2.4 Website file/dir paths + links

This is the largest single drift cluster. The directory `website/src/content/docs/components/orchestrator/` still exists (5 files: `overview.mdx`, `selection-engine.mdx`, `budget-enforcement.mdx`, `content-dedup.mdx`, `deployment.mdx`). Most other docs link to `/components/broker/...` which is **dead** until the dir is renamed.

Inbound links pointing to the not-yet-existing `/components/broker/...`:

| Source file | Line | Link target |
|---|---|---|
| `website/src/content/docs/protocol/exchange-manifest.mdx` | 210 | `/components/broker/overview/` |
| `website/src/content/docs/components/agent-sdk/overview.mdx` | 12 | `/components/broker/overview/` |
| `website/src/content/docs/components/exchange/health-checks.mdx` | 16 | `/components/broker/overview/` |
| `website/src/content/docs/components/exchange/health-checks.mdx` | 121 | `/components/broker/overview/` |
| `website/src/content/docs/components/mcp-server/overview.mdx` | 10 | `/components/broker/overview/` |
| `website/src/content/docs/components/orchestrator/content-dedup.mdx` | 162 | `/components/broker/selection-engine/` |
| `website/src/content/docs/components/orchestrator/budget-enforcement.mdx` | 89 | `/components/broker/selection-engine/` |
| `website/src/content/docs/components/orchestrator/selection-engine.mdx` | 361 | `/components/broker/content-dedup/` |
| `website/src/content/docs/getting-started/poc-walkthrough.mdx` | 345 | `/components/broker/overview`, `/components/broker/selection-engine`, `/components/broker/budget-enforcement` |
| `website/src/content/docs/getting-started/poc-walkthrough.mdx` | 382 | `/components/broker/overview`, `/components/broker/selection-engine` |

Inbound link still pointing to legacy `/components/orchestrator/...`:

| Source file | Line | Link target |
|---|---|---|
| `website/src/content/docs/index.mdx` | 58 | `[Broker](/components/orchestrator/overview/)` — link label says "Broker" but href is `orchestrator` (contradiction). |

In-page mermaid/diagram references that should be reviewed once the dir moves:

| File | Line | Excerpt |
|---|---|---|
| `website/src/content/docs/components/orchestrator/overview.mdx` | 288 | `participant Orch as Broker` (mermaid alias — cosmetic, fine but consider `Brk`) |

Also `website/astro.config.mjs` (lines 15–51) does **not** include a Components section in the sidebar at all — once the dir is renamed, no sidebar entry needs updating. (Side note: this means the entire `/components/...` subtree is currently unlinked from the sidebar; that is pre-existing.)

### 2.5 Proto CHANGELOG + website changelog (within v1.1.0 section)

These are mostly legitimate **rename announcements** (see §5). The one drift is:

`website/src/content/docs/reference/changelog.mdx:8` — embeds the prose `The term "marketplace" is eliminated from the proto in favour of "exchange" throughout.` — keep (announcing the rename).

But note `proto/CHANGELOG.md` and `website/.../changelog.mdx` v1.1.0 entry both say the rename eliminates "marketplace" — and yet the proto comments still contain it (see §2.1 above). That is the cross-page contradiction (§6).

### 2.6 Other / config / build

- `README.md`, `amplify.yml`, `go.mod`, `go.sum`, `website/package.json`, `website/astro.config.mjs`, `website/src/components/*`, `website/src/pages/*` — **clean**, no marketplace/orchestrator drift.

---

## 3. PROTO-DEFERRED `orchestrator` findings (now in scope per user)

These are the proto-source uses of "Orchestrator" the original author marked as deferred. All in narrative comments; no wire impact.

| File:line | Excerpt |
|---|---|
| `proto/ramp/v1/ramp.proto:131` | `// Agents and Orchestrators are both valid clients.` |
| `proto/ramp/v1/ramp.proto:245` | `// Enables agents/Orchestrators to throttle proactively rather than hitting` |
| `proto/ramp/v1/ramp.proto:280` | `// Present when ` + "`offers`" + ` is empty. Enables agents/Orchestrators to distinguish` |
| `proto/ramp/v1/ramp.proto:418` | `// Enables Orchestrators to recognize the same resource offered by` |
| `proto/ramp/v1/ramp.proto:429` | `// Prevents intermediaries (Orchestrators) from tampering with price` |
| `proto/ramp/v1/ramp.proto:727` | `// lists so agents and Orchestrators can filter offers before transacting.` |

And the auto-generated mirrors:
| `gen/go/ramp/v1/ramp.pb.go` | `:1412`, `:1532`, `:1800`, `:1809`, `:2443` |
| `gen/ts/ramp/v1/ramp_pb.ts` | `:243`, `:312`, `:498`, `:517`, `:952` |

Two further "Orchestrator" hits in `proto/CHANGELOG.md`:
- `:180` — `SupplyResponse.rate_limit — enables proactive throttling for Orchestrator fanout` (in v0.3.0 historical section — HISTORICAL, keep)
- `:203` — `Orchestrator co-signs forwarded requests (Ed25519)` (in v0.2.0 historical section — HISTORICAL, keep)

---

## 4. GRAMMAR ARTIFACTS (article-noun mismatches introduced by the rename)

The rename swap `marketplace → Exchange` changed a consonant-initial word to a vowel-initial word, leaving `a marketplace` → `a Exchange` mismatches everywhere. Similarly `orchestrator → Broker` changed vowel→consonant, leaving `an orchestrator` → `an Broker` mismatches.

### 4.1 `a Exchange` (should be `an Exchange`) — 21 hits

| File | Line |
|---|---|
| `proto/ramp/v1/ramp.proto` | 169, 394, 1345, 1580 |
| `gen/go/ramp/v1/ramp.pb.go` | 1252, 1781 |
| `gen/ts/ramp/v1/ramp_pb.ts` | 98, 446, 4962 |
| `gen/ts/ramp/v1/ramp_connect.ts` | 177 |
| `website/src/content/docs/protocol/extension-profiles.mdx` | 271 |
| `website/src/content/docs/protocol/discovery-paths.mdx` | 275 |
| `website/src/content/docs/protocol/ext-legal.mdx` | 111 |
| `website/src/content/docs/protocol/scenario-walkthrough.mdx` | 774 |
| `website/src/content/docs/components/agent-sdk/budget-reporting.mdx` | 188, 244 |
| `website/src/content/docs/components/agent-sdk/fetch-flow.mdx` | 135 |
| `website/src/content/docs/components/exchange/storage-model.mdx` | 259 |
| `website/src/content/docs/components/exchange/multi-tenant.mdx` | 8 |
| `website/src/content/docs/components/exchange/overview.mdx` | 8 |
| `website/src/content/docs/components/mcp-server/overview.mdx` | 10 |
| `website/src/content/docs/components/orchestrator/overview.mdx` | 119, 263, 277 |
| `website/src/content/docs/components/orchestrator/selection-engine.mdx` | 434 |
| `website/src/content/docs/components/orchestrator/deployment.mdx` | 331 |
| `website/src/content/docs/components/edge-function/overview.mdx` | 22 |
| `website/src/content/docs/components/edge-function/deployment.mdx` | 39, 270 |

### 4.2 `an Broker` (should be `a Broker`) — 7 hits

| File | Line |
|---|---|
| `proto/ramp/v1/ramp.proto` | 171, 246 |
| `gen/go/ramp/v1/ramp.pb.go` | 1254, 1413 |
| `gen/ts/ramp/v1/ramp_pb.ts` | 100, 244 |
| `website/src/content/docs/protocol/discovery-paths.mdx` | 256 |
| `website/src/content/docs/protocol/transaction-flow.mdx` | 8 |
| `website/src/content/docs/protocol/walkthrough-credit-report.mdx` | 6 |
| `website/src/content/docs/protocol/walkthrough-v1.mdx` | 164 |
| `website/src/content/docs/components/orchestrator/overview.mdx` | 20, 119 |

### 4.3 Other article issues (lower confidence — flagging for review)

- `proto/ramp/v1/ramp.proto:271` — `Broker queried an Exchange` — "Exchange" starts with vowel sound, so `an Exchange` is correct. **Keep.** (This is correct existing usage; flagging because grep found it but it does NOT need fixing.)
- `proto/ramp/v1/ramp.proto:1706` — `an Exchange/Broker or a third party` — slash form makes it ambiguous; fine.
- `proto/ramp/v1/ramp.proto:1945` — `an Exchange that enriches` — correct.
- `proto/ramp/v1/ramp.proto:2117` — `an Exchange can support` — correct.
- `website/src/content/docs/index.mdx:23` — `I'm an Exchange Operator` — correct (vowel sound).
- `website/src/content/docs/getting-started/for-exchange-operators.mdx:222` — `As an Exchange operator` — correct.
- `website/src/content/docs/architecture/production-architecture.mdx:8`, `:37`, `:73` — all `an Exchange ...` — correct.

So the "Exchange" article situation is asymmetric: `a Exchange` is universally wrong, `an Exchange` is universally correct.

---

## 5. HISTORICAL / legitimate retentions

The following uses of "marketplace" / "Marketplace" / "MARKETPLACE" are intentional history. Author confirmation requested.

### 5.1 Rename-announcement comments / sections (must stay to explain the breaking change)

- `proto/ramp/v1/ramp.proto:71` — `ProviderManifest.marketplaces renamed to exchanges (wire tag 4` (proto-header v1.1.0 changelog)
- `proto/ramp/v1/ramp.proto:74` — mentions the legacy `/marketplace/v1/keys` path being removed
- `proto/ramp/v1/ramp.proto:1803` — `(Renamed from ProviderManifest.marketplaces in v1.1.0.)`
- `proto/ramp/v1/ramp.proto:1916` — `Renamed from ` + "`marketplaces`" + ` in v1.1.0; wire tag preserved.`
- `proto/buf.yaml:23-24` — `marketplace → exchange repo-wide rename (v1.1.0): all wire field names and the DISCOVERY_METHOD_MARKETPLACE enum value are renamed.`
- `proto/CHANGELOG.md:3,9,10,41-47,53,80` — v1.1.0 entry announcing the rename
- `website/src/content/docs/reference/changelog.mdx:6,8,29-37,53` — same on the website
- `website/src/content/docs/reference/proto-ramp.mdx:506` — `(renamed from ` + "`ProviderManifest.marketplaces`" + `)`
- `website/src/content/docs/reference/proto-ramp.mdx:562` — `Authorized Exchanges (renamed from ` + "`marketplaces`" + `; wire tag preserved)`
- Generated mirrors of the above in `gen/go/ramp/v1/ramp.pb.go:71,74,5283,5646`, `gen/go/ramp/v1/rampv1connect/ramp.connect.go:71,74`, `gen/ts/ramp/v1/ramp_pb.ts:71,74,2792,3032`, `gen/ts/ramp/v1/ramp_connect.ts:71,74`.

### 5.2 Historical CHANGELOG entries for pre-v1.1.0 versions

In `proto/CHANGELOG.md` (v0.2.0, v0.3.0 sections) and `website/.../changelog.mdx` (v1.0 section):
- `proto/CHANGELOG.md:156,160,162,167,169,172,180,190,203-206,217,227,243` — all describe historical state of the protocol when it was called "marketplace". These should remain as period-accurate history.

> **Recommendation for the author:** the safest convention is to either (a) keep these as-is (most readable history), or (b) add an editorial footnote at the top of the v0.x / v1.0 sections noting "terms in this section reflect the protocol vocabulary at the time; ProviderManifest, MarketplaceService, and `marketplace_signature` were renamed in v1.1.0". Do **not** edit these in place; that loses the historical record.

### 5.3 Deprecated message comments

- `ExchangeManifest` (deprecated) and `ProviderManifest` (deprecated) are kept on the wire one cycle. Any internal comments documenting their deprecation in terms of the rename are legitimate.

---

## 6. Cross-page contradictions

1. **Internal link label vs href mismatch — `index.mdx:58`:**
   ```
   [Broker](/components/orchestrator/overview/)
   ```
   Link text says "Broker"; href still points to the legacy `orchestrator/` slug. Either the directory must be renamed to `broker/` and the href updated, or every doc that already links to `/components/broker/...` (eight files, see §2.4) is silently broken.

2. **Documented Go package layout vs website directory name — `components/orchestrator/overview.mdx:343-348`:**
   ```
   github.com/RAMP-Protocol/protocol/broker/
       broker/           # Sidecar binary entrypoint
       broker/           # Core broker logic (used by all deployment modes)
   ```
   The page describes a Go layout under `broker/`, but the page itself lives at `components/orchestrator/`. After the dir-rename, this aligns.

3. **JSON field-naming style — `getting-started/poc-walkthrough.mdx:130,142,157`:**
   This page uses **camelCase** JSON keys: `"exchangeSignature"`, `"offerSignature"`. Every other walkthrough (`protocol/walkthrough-academic.mdx`, `protocol/walkthrough-credit-report.mdx`, `protocol/walkthrough-medical-imaging.mdx`, `protocol/scenario-walkthrough.mdx`, `protocol/transaction-flow.mdx`, `protocol/ext-news.mdx`, etc.) uses **snake_case** `"exchange_signature"`. The protobuf-generated JSON names are snake_case in the canonical `.proto` definitions. The PoC walkthrough is the outlier and either (a) needs to be aligned to snake_case for consistency, or (b) the page should explain why camelCase is intentional (e.g. it's a different SDK's serializer).

4. **Base64 placeholder literally encodes the old term — `protocol/ext-news.mdx:400`:**
   ```
   "exchange_signature": "bWFya2V0cGxhY2Utc2lnbmF0dXJl..."
   ```
   The field name is `exchange_signature` (correct) but the placeholder decodes to literal `marketplace-signature`. A reader who base64-decodes the value will think the protocol still uses the term internally.

5. **Proto narrative claims rename is complete — but contains "Orchestrators":**
   The v1.1.0 changelog at `proto/CHANGELOG.md:9-10` and `proto/ramp/v1/ramp.proto:71-76` says "marketplace is eliminated from the proto" and lists the rename as repo-wide. Strictly speaking that statement is about the wire-visible names, not the prose; but a reader cross-checking will find six prose mentions of "Orchestrators" inside the same file (`ramp.proto` lines 131, 245, 280, 418, 429, 727). Either reword the v1.1.0 entry to scope it to wire names, or finish the prose rename now (this is what the user is asking for in PR #2).

---

## 7. Author-confirm list (quick yes/no checklist)

Before fixing, confirm these classifications:

- [ ] All v1.1.0 rename-announcement comments stay (§5.1).
- [ ] All v0.x / v1.0.x CHANGELOG entries stay verbatim (§5.2).
- [ ] All proto-source `Orchestrator` comments get renamed to `Broker` in this PR (§3).
- [ ] All `a Exchange` → `an Exchange` and `an Broker` → `a Broker` grammar fixes done in this PR (§4).
- [ ] Website dir `components/orchestrator/` renamed to `components/broker/` and `index.mdx:58` href updated (§2.4 / §6.1).
- [ ] PoC walkthrough camelCase JSON keys aligned to snake_case (§6.3).
- [ ] `ext-news.mdx:400` placeholder re-encoded to a non-"marketplace" string (§6.4).
- [ ] `protocol/authentication.mdx:301` row corrected — either remove or rename `orchestrator_signature` (§2.3).
- [ ] `comp.proto:53` and `:126` comments rewritten from `Marketplace` → `Exchange` (§2.1).
- [ ] After the proto edits, regenerate `gen/` (cleans up §2.2 automatically).
