# Verifier B — Independent Verification (PR #2 Sweep)

Branch: `well-known-ramp-json-unified` @ HEAD `f3be91d`
Read-only verification.

---

## F1 — Legacy `/exchange/v1/keys` curl line in poc-walkthrough

**Verdict: VERIFIED**

Evidence — `website/src/content/docs/getting-started/poc-walkthrough.mdx:359-360`:
```
359:curl http://localhost:3000/health
360:curl http://localhost:3000/exchange/v1/keys
```

Verified the endpoint is gone from `proto/ramp/v1/ramp.proto` — searching for `/keys` or `exchange/v1/keys` in the proto returns only one match (line 77), and it explicitly describes the path as removed:
```
77://     ramp-verifier.json) and the legacy /marketplace/v1/keys path are
```
The walkthrough's path (`/exchange/v1/keys`) is not present anywhere in `proto/ramp/v1/ramp.proto`. All other key URLs in the proto are unified under `/.well-known/ramp.json` (lines 112-115, 688, 697, 702, 934, 976, 1421, 1709-1793, etc.).

CHANGELOG (`proto/CHANGELOG.md:9`) confirms removal of legacy `/marketplace/v1/keys`:
```
9:`/marketplace/v1/keys` path are removed from the spec. The term
```

Note: CHANGELOG cites the *historical* path `/marketplace/v1/keys` (pre-rename). The walkthrough uses the post-rename form `/exchange/v1/keys`, which was never a valid spec path; either way the endpoint is removed.

Summary: curl line exists at line 360; endpoint is fully removed from spec & changelog.

---

## F2 — Legacy `/exchange/v1/keys` referenced in authentication.mdx

**Verdict: VERIFIED**

Evidence — `website/src/content/docs/protocol/authentication.mdx:555`:
```
Every party publishes its keys in **one** place — `{domain}/.well-known/ramp.json`
(`WellKnownManifest.public_keys`, role-tagged). The per-role files (`ramp-agent.json`,
`ramp-exchange.json`, `ramp-verifier.json`) and the legacy `/exchange/v1/keys` endpoint
are removed in v1.1.0; keys are inline JWKs.
```

Note: this is a "removed in v1.1.0" prose mention. The reference is contextually a historical note, not an active instruction. It is real and present.

Summary: present at line 555 as a "removed" historical note.

---

## F3 — authentication.mdx self-contradiction (rename note + lingering row)

**Verdict: NOT REPRODUCIBLE** (as framed)

Evidence — full content of relevant section, `website/src/content/docs/protocol/authentication.mdx`:

Line 286 (the alleged "rename" note):
```
This replaces the previous `broker_signature` / `broker_signature_algorithm` fields
with a generalized chain that supports any number of intermediaries.
```
This is about **`broker_signature`** being replaced by an intermediaries chain — it does **not** say `orchestrator_signature` was renamed.

Line 298-302 (the alleged "current row" table):
```
| Deprecated Field | Message | Replacement |
|---|---|---|
| `agent_signature` | `RAMPRequest` | RFC 9421 `Signature` / `Signature-Input` headers |
| `orchestrator_signature` | `RAMPRequest` | RFC 9421 `Signature` / `Signature-Input` headers |
| `caller_signature` | `RAMPRequest` | RFC 9421 `Signature` / `Signature-Input` headers |
```
This is a **"Deprecated Field"** table (heading at line 298) — `orchestrator_signature` is explicitly listed as deprecated, not as a current field.

The finding's framing fails on two counts: (1) the rename note is about `broker_signature`, not `orchestrator_signature`; (2) the table row marks `orchestrator_signature` as deprecated, not current. There is no internal contradiction on this page about `orchestrator_signature`.

Summary: page does not contain the contradiction as described; `orchestrator_signature` appears once, in a deprecated-fields table.

---

## F4 — base64 decode of `exchange_signature` in ext-news.mdx

**Verdict: VERIFIED**

Evidence — `website/src/content/docs/protocol/ext-news.mdx:400`:
```
400:  "exchange_signature": "bWFya2V0cGxhY2Utc2lnbmF0dXJl...",
```

Decoded:
```
$ echo -n "bWFya2V0cGxhY2Utc2lnbmF0dXJl" | base64 -d
marketplace-signature
```

(Bonus: line 469 has `"bnByLXBvZGNhc3Qtc2lnbmF0dXJl"` which decodes to `npr-podcast-signature` — a second leftover pre-rename token in the same file.)

Summary: decodes to the literal string `marketplace-signature`. Confirmed.

---

## F5 — "Marketplace" mentions in comp.proto

**Verdict: VERIFIED**

Evidence — `proto/comp/v1/comp.proto`:
```
53:  // username, not a password. Marketplace looks up agent's registered
126:  // Unique package identifier defined by the Content Owner or Marketplace.
```

Exactly 2 occurrences, both in current prose comments (no changelog/deprecation context in those lines).

Summary: 2 mentions at lines 53 and 126. Confirmed.

---

## F6 — Orchestrator → Broker rename status

**Verdict: VERIFIED**

Evidence — `Orchestrator(s)` occurrences in `proto/ramp/v1/ramp.proto` (6 lines):
```
147:// Agents and Orchestrators are both valid clients.
261:  // Enables agents/Orchestrators to throttle proactively rather than hitting
296:  // Present when `offers` is empty. Enables agents/Orchestrators to distinguish
434:  // Enables Orchestrators to recognize the same resource offered by
445:  // Prevents intermediaries (Orchestrators) from tampering with price
743:// lists so agents and Orchestrators can filter offers before transacting.
```

Directories:
- `website/src/content/docs/components/orchestrator/` — **exists**
- `website/src/content/docs/components/broker/` — **does NOT exist** (ls shows only `agent-sdk, content-ingestion, edge-function, exchange, mcp-server, orchestrator, transaction-log`)

`/components/broker/...` link references across `website/` — **10 occurrences** across 8 files (would 404):
```
website/src/content/docs/protocol/exchange-manifest.mdx:210
website/src/content/docs/components/agent-sdk/overview.mdx:12
website/src/content/docs/components/exchange/health-checks.mdx:16
website/src/content/docs/components/exchange/health-checks.mdx:121
website/src/content/docs/components/mcp-server/overview.mdx:10
website/src/content/docs/components/orchestrator/budget-enforcement.mdx:89
website/src/content/docs/components/orchestrator/selection-engine.mdx:361
website/src/content/docs/components/orchestrator/content-dedup.mdx:162
website/src/content/docs/getting-started/poc-walkthrough.mdx:340
website/src/content/docs/getting-started/poc-walkthrough.mdx:377
```

`website/src/content/docs/index.mdx:58`:
```
[Exchange](/components/exchange/overview/) -- [Edge Function](/components/edge-function/overview/) -- [Broker](/components/orchestrator/overview/) -- [Agent SDK](/components/agent-sdk/overview/) -- [MCP Server](/components/mcp-server/overview/)
```
Confirmed: "Broker" label whose href points at `/components/orchestrator/overview/`.

Summary: 6 `Orchestrator(s)` in ramp.proto; orchestrator/ dir exists, broker/ does not; 10 broker-link 404s; index.mdx has Broker label → orchestrator URL.

---

## F7 — Article-noun mismatches `a Exchange` / `an Broker`

**Verdict: VERIFIED (with refined counts)**

`a Exchange` (word-bounded, `\ba Exchange\b`): **23** occurrences across `proto/` + `website/`. All 23 violate (every instance is a grammar bug — should be "an Exchange").

Breakdown:
- proto/ramp/v1/ramp.proto — 4 (lines 185, 410, 1374, 1609)
- website/src/content/docs/protocol/discovery-paths.mdx:275
- website/src/content/docs/protocol/extension-profiles.mdx:271
- website/src/content/docs/protocol/ext-legal.mdx:111
- website/src/content/docs/protocol/scenario-walkthrough.mdx:765
- website/src/content/docs/components/agent-sdk/budget-reporting.mdx:188,244
- website/src/content/docs/components/exchange/storage-model.mdx:259
- website/src/content/docs/components/agent-sdk/fetch-flow.mdx:135
- website/src/content/docs/components/exchange/overview.mdx:8
- website/src/content/docs/components/exchange/multi-tenant.mdx:8
- website/src/content/docs/components/edge-function/overview.mdx:22
- website/src/content/docs/components/edge-function/deployment.mdx:39, 270
- website/src/content/docs/components/mcp-server/overview.mdx:10
- website/src/content/docs/components/orchestrator/overview.mdx:119, 263, 277
- website/src/content/docs/components/orchestrator/deployment.mdx:331
- website/src/content/docs/components/orchestrator/selection-engine.mdx:434

`an Broker` (word-bounded): **8** occurrences. All 8 violate (should be "a Broker"):
- proto/ramp/v1/ramp.proto:187, 262
- website/.../discovery-paths.mdx:256
- website/.../transaction-flow.mdx:8
- website/.../walkthrough-credit-report.mdx:6
- website/.../walkthrough-v1.mdx:164
- website/.../orchestrator/overview.mdx:20, 119

Asymmetry check: `an Exchange` (the *correct* form for "Exchange") — **31** occurrences (raw grep; mix of correct uses like "an Exchange" and false-positives like "than Exchange"). The correct form is well-represented across the codebase, demonstrating the bugs are typos rather than systematic.

Note: the original task said "Count both patterns across proto/ and website/." Naive (substring) grep count for "a Exchange" = 26, refined to 23 with `\b` boundary (excluding e.g. "via Exchange"). For "an Broker": 8 in both cases.

Summary: 23 `a Exchange` (all bugs) + 8 `an Broker` (all bugs). 31 raw `an Exchange` hits confirms the correct form coexists with the bugs.

---

## F8 — `exchange-manifest.mdx` not in astro.config.mjs sidebar

**Verdict: VERIFIED**

Evidence: `grep -n "exchange-manifest" website/astro.config.mjs` returns **no matches**. File exists at `website/src/content/docs/protocol/exchange-manifest.mdx`. Sidebar `protocol/` entries (lines 29-40) include transaction-flow, standards-layering, discovery-paths, content-attestation, authentication, dispute-resolution, extension-profiles, ext-news, ext-academic, ext-legal, ext-comp, ext-c2pa — but no `exchange-manifest`.

Summary: file orphaned from sidebar.

---

## F9 — camelCase signature fields in poc-walkthrough

**Verdict: VERIFIED**

Evidence — `website/src/content/docs/getting-started/poc-walkthrough.mdx`:
```
130:          "exchangeSignature": "ae77b181...32607e08",
142:- **exchangeSignature** — [Ed25519 signature](/protocol/authentication) over the offer...
148:Commit to an offer. Pass the `offerId` and `offerSignature` from Step 3...
157:    "offerSignature": "<exchangeSignature from Step 3>",
158:    "offerSignatureAlgorithm": "ed25519",
```

Sampled other walkthroughs (walkthrough-v1, walkthrough-academic, walkthrough-credit-report) — they uniformly use `exchange_signature`, `offer_signature`, `offer_signature_algorithm` (snake_case), e.g.:
```
walkthrough-v1.mdx:           "exchange_signature": "base64-ed25519-offer-sig...",
walkthrough-credit-report.mdx: "exchange_signature": "base64-ed25519-bb-offer-sig...",
walkthrough-academic.mdx:      "exchange_signature": "base64-ed25519-arxiv-offer-sig...",
                                 "offer_signature": "base64-ed25519-dnb-offer-std-sig...",
                                 "offer_signature_algorithm": "ed25519",
```

Summary: poc-walkthrough is the outlier — camelCase at lines 130, 142, 148, 157, 158 vs. snake_case convention everywhere else.

---

## F10 — Stale rawDesc in committed `gen/`

**Verdict: VERIFIED**

Commands run:
```
cd proto && buf generate
git diff --stat gen/
```
Output:
```
 gen/go/ramp/v1/ramp.pb.go | 2 +-
 gen/ts/ramp/v1/ramp_pb.ts | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)
```
Exactly 2 files changed, 2 insertions, 2 deletions — matches the predicted shape.

Diff of `gen/go/ramp/v1/ramp.pb.go` around line 7611:
```
@@ -7611,7 +7611,7 @@ const file_ramp_v1_ramp_proto_rawDesc = "" +
 	"\x05rules\x18\x02 \x03(\v2\x19.ramp.v1.AccessPolicyRuleR\x05rules\"c\n" +
 	"\x10AccessPolicyRule\x12\x18\n" +
 	"\apattern\x18\x01 \x01(\tR\apattern\x125\n" +
-	"\x06policy\x18\x02 \x01(\x0e2\x1d.ramp.v1.ResourceAccessPolicyR\x06policy\"\xa3\x05\n" +
+	"\x06policy\x18\x02 \x01(\x0e2\x1d.ramp.v1.ResourceAccessPolicyR\x06policy\"\xbb\x06\n" +
 	"\fRAMPResponse\x12\x10\n" +
```

The byte change is `\xa3\x05` → `\xbb\x06`, immediately preceding `\n\fRAMPResponse` — i.e., this is the protobuf varint-encoded length of the RAMPResponse descriptor (tag-then-length introducer for the embedded message descriptor).

Varint decode (LSB-first, 7 bits per byte):
- `\xa3\x05`: 0x23 | (0x05 << 7) = 35 + 640 = **675 bytes**
- `\xbb\x06`: 0x3b | (0x06 << 7) = 59 + 768 = **827 bytes**
- Delta: **+152 bytes** — exactly matches predicted "~152 bytes".

Source-side correctness check — committed `gen/go/ramp/v1/ramp.pb.go` (pre-regen) contains the new fields as Go struct fields on `RAMPResponse`:
```
6354:	RetrievalEndpoint *string `protobuf:"bytes,13,opt,name=retrieval_endpoint,json=retrievalEndpoint,proto3,oneof" json:"retrieval_endpoint,omitempty"`
6357:	AgentIdentityHash *string `protobuf:"bytes,14,opt,name=agent_identity_hash,json=agentIdentityHash,proto3,oneof" json:"agent_identity_hash,omitempty"`
6480:func (x *RAMPResponse) GetRetrievalEndpoint() string { ... }
6487:func (x *RAMPResponse) GetAgentIdentityHash() string { ... }
```
Both struct fields and getters are present in the committed file. Only the embedded `rawDesc` byte string (the length prefix) is stale.

Both halves of the inconsistency confirmed:
- Go struct: **correct** (fields 13 & 14 present on RAMPResponse).
- Embedded rawDesc: **stale** (claims 675 bytes; correct length is 827; 152 bytes of new field descriptors not reflected).

Cleanup: `git checkout -- gen/` executed; `git status` confirms working tree clean (only `.claude/` untracked).

Summary: rawDesc length prefix is stale by +152 bytes on both Go (line 7611) and TS files; struct fields are correct. Reproducibility bug confirmed.

---

## Counts table

| Finding | Verdict |
|---|---|
| F1  | VERIFIED |
| F2  | VERIFIED |
| F3  | NOT REPRODUCIBLE |
| F4  | VERIFIED |
| F5  | VERIFIED |
| F6  | VERIFIED |
| F7  | VERIFIED |
| F8  | VERIFIED |
| F9  | VERIFIED |
| F10 | VERIFIED |

**Totals:** VERIFIED: 9 · PARTIAL: 0 · NOT REPRODUCIBLE: 1
