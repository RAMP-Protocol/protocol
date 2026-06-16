# Verifier A — Independent Verification Report

Branch: `well-known-ramp-json-unified` @ `f3be91d`
Scope: read-only (one temporary `buf generate` for NEW, reset with `git checkout`).

---

## A1 — `curl /exchange/v1/keys` in poc-walkthrough.mdx

**Verdict: VERIFIED**

Evidence:
- `website/src/content/docs/getting-started/poc-walkthrough.mdx:360`
  `curl http://localhost:3000/exchange/v1/keys`
- No matches for `exchange/v1/keys` anywhere in `proto/` (confirmed endpoint is removed from the proto).
- `proto/CHANGELOG.md:3` documents v1.1.0 introduces the unified `/.well-known/ramp.json`; multiple lines in `proto/ramp/v1/ramp.proto` (e.g. lines 112-115, 1421, 1709-1738, 1793, 2009-2010) confirm the legacy per-role endpoints (including `/.well-known/ramp-exchange.json` and the older `/exchange/v1/keys` style) are removed in favor of `/.well-known/ramp.json`.

Summary: The `poc-walkthrough.mdx` contains a curl to a removed endpoint at line 360; replacement should be `/.well-known/ramp.json`.

---

## A2 — `/exchange/v1/keys` reference in authentication.mdx prose

**Verdict: VERIFIED**

Evidence:
- `website/src/content/docs/protocol/authentication.mdx:555`:
  > "...The per-role files (`ramp-agent.json`, `ramp-exchange.json`, `ramp-verifier.json`) and the legacy `/exchange/v1/keys` endpoint are removed in v1.1.0; keys are inline JWKs."

Note: This reference is actually *describing the removal* (correctly stating it as a legacy/removed endpoint), but it does still appear in the prose. The reviewer's claim that a reference exists is technically correct.

Summary: A prose reference to `/exchange/v1/keys` exists at authentication.mdx:555 — describing it as removed in v1.1.0.

---

## A3 — authentication.mdx self-contradiction on `orchestrator_signature`

**Verdict: PARTIAL**

Evidence:
- Table row at `website/src/content/docs/protocol/authentication.mdx:301`:
  `| \`orchestrator_signature\` | \`RAMPRequest\` | RFC 9421 \`Signature\` / \`Signature-Input\` headers |`
- The table itself (lines 296-302) is titled "The following proto fields are now **reserved** and MUST NOT be populated in new implementations". It lists `orchestrator_signature` as a **deprecated** field — NOT as a "current field". This is internally consistent.
- The "renamed" prose at line 286 is about `broker_signature` / `broker_signature_algorithm` being replaced by the intermediary chain — NOT about `orchestrator_signature` being renamed.

I do not find a statement that `orchestrator_signature` was renamed. The table lists it as deprecated, which is consistent with how the doc treats it. The reviewer's claim of a self-contradiction does not hold up: the field is in a "Deprecated Field" column, not listed as a current/active field.

Summary: Table row at line 301 exists and lists `orchestrator_signature` as deprecated; there is no "renamed" claim at ~line 286 about it. No contradiction reproducible.

---

## A4 — base64 `exchange_signature` decodes to `marketplace-signature`

**Verdict: VERIFIED**

Evidence:
- `website/src/content/docs/protocol/ext-news.mdx:400`:
  `"exchange_signature": "bWFya2V0cGxhY2Utc2lnbmF0dXJl...",`
- Decoded: `echo bWFya2V0cGxhY2Utc2lnbmF0dXJl | base64 -d` → `marketplace-signature`
- Additionally line 469: `"exchange_signature": "bnByLXBvZGNhc3Qtc2lnbmF0dXJl..."` decodes to `npr-podcast-signature` (this one is fine post-rename, just noted).

Summary: Line 400 in ext-news.mdx has an `exchange_signature` whose base64 value literally decodes to `marketplace-signature` — a leftover from the marketplace→exchange rename.

---

## A5 — Two surviving "Marketplace" references in comp.proto

**Verdict: VERIFIED**

Evidence (`proto/comp/v1/comp.proto`):
- Line 53: `// username, not a password. Marketplace looks up agent's registered`
- Line 126: `// Unique package identifier defined by the Content Owner or Marketplace.`

Both are in prose comments (not deprecated message names or migration notes) and use the old terminology.

Summary: Two prose-comment occurrences of "Marketplace" remain in comp.proto at lines 53 and 126.

---

## B1 — Orchestrator → Broker rename incomplete

**Verdict: VERIFIED**

Evidence:

a) `proto/ramp/v1/ramp.proto` `Orchestrator(s)` count: **6 occurrences**
- Line 147: `// Agents and Orchestrators are both valid clients.`
- Line 261: `// Enables agents/Orchestrators to throttle proactively rather than hitting`
- Line 296: `// Present when 'offers' is empty. Enables agents/Orchestrators to distinguish`
- Line 434: `// Enables Orchestrators to recognize the same resource offered by`
- Line 445: `// Prevents intermediaries (Orchestrators) from tampering with price`
- Line 743: `// lists so agents and Orchestrators can filter offers before transacting.`

b) `website/src/content/docs/components/orchestrator/` directory **exists** (confirmed via `ls`).

c) `website/src/content/docs/components/broker/` directory **does NOT exist** (not in `ls` output: only `agent-sdk content-ingestion edge-function exchange mcp-server orchestrator transaction-log`).

d) `/components/broker` references in `website/`: **10 matches** (will 404 because the directory does not exist).

e) `website/src/content/docs/index.mdx:58`:
   `[Exchange](/components/exchange/overview/) -- [Edge Function](/components/edge-function/overview/) -- [Broker](/components/orchestrator/overview/) -- [Agent SDK](/components/agent-sdk/overview/) -- [MCP Server](/components/mcp-server/overview/)`
   The label "Broker" points at `/components/orchestrator/overview/` — matches claim.

Summary: All five sub-claims confirmed. Rename is incomplete: 6 Orchestrator(s) in proto, broker dir absent, 10 broken /components/broker links, index.mdx line 58 has Broker label with old orchestrator path.

---

## B2 — Article-noun mismatches (~49)

**Verdict: PARTIAL**

Evidence (raw grep counts across `proto/` and `website/`):
- `a Exchange\b` (incorrect): **26 matches**
- `an Broker\b` (incorrect): **8 matches**
- **Total incorrect: 34** (not 49)
- `an Exchange\b` (correct): **31 matches**
- `a Broker\b` (correct): **12 matches**

Asymmetry check:
- All 26 `a Exchange` matches I inspected are incorrect (article-noun mismatch). A few include compound nouns like "Media Exchange" or "cross-exchange" but on inspection: `Media Exchange` follows "to" not "a"; `cross-exchange` does not match `a Exchange\b` (word boundary). Filtering for clearly compound proper nouns like "data Exchange" gives 23 strictly bad cases, but the remaining 3 ("data Exchange", "Media Exchange") are arguably proper-noun phrases where "a" is correct. Conservative count of pure errors: ~23-26.
- All 8 `an Broker` matches are incorrect (should be "a Broker").
- Spot-checked `an Exchange` matches — all are correctly using "an" before a vowel sound.
- Spot-checked `a Broker` matches — all are correctly using "a" before consonant sound.

The pattern asymmetry holds (every `a Exchange` ≈ wrong, every `an Broker` = wrong), but the **count is 34, not 49**. The "49" figure is overstated by ~15.

Summary: Pattern correct, count off — 34 actual mismatches (26 `a Exchange` + 8 `an Broker`), not 49.

---

## C1 — `exchange-manifest.mdx` missing from astro sidebar

**Verdict: VERIFIED**

Evidence:
- File exists: `website/src/content/docs/protocol/exchange-manifest.mdx` (confirmed by `ls` of `website/src/content/docs/protocol/`).
- `website/astro.config.mjs` (lines 27-41) Protocol section enumerates: `transaction-flow`, `standards-layering`, `discovery-paths`, `content-attestation`, `authentication`, `dispute-resolution`, `extension-profiles`, `ext-news`, `ext-academic`, `ext-legal`, `ext-comp`, `ext-c2pa`.
- No entry for `exchange-manifest`.

Summary: `exchange-manifest.mdx` exists in the protocol docs folder but is not listed in the astro.config.mjs Protocol sidebar.

---

## C2 — poc-walkthrough.mdx uses camelCase signature fields

**Verdict: VERIFIED**

Evidence:
- `website/src/content/docs/getting-started/poc-walkthrough.mdx`:
  - Line 130: `"exchangeSignature": "ae77b181...32607e08",`
  - Line 142: `**exchangeSignature** — [Ed25519 signature]...`
  - Line 148: `Pass the 'offerId' and 'offerSignature' from Step 3.`
  - Line 157: `"offerSignature": "<exchangeSignature from Step 3>",`
  - Line 158: `"offerSignatureAlgorithm": "ed25519",`

Convention comparison:
- `website/src/content/docs/protocol/walkthrough-credit-report.mdx` uses snake_case: lines 190, 256, 324 all show `"exchange_signature"`; lines 104, 191, 257 show `"signature_algorithm"`.
- proto JSON convention (proto3) and most other walkthroughs use snake_case for JSON keys.

Summary: poc-walkthrough.mdx uniquely uses camelCase (`exchangeSignature`, `offerSignature`, `offerSignatureAlgorithm`) at lines 130/142/148/157/158, contrasting with snake_case convention used in walkthrough-credit-report.mdx and the proto field names themselves.

---

## NEW — `gen/` reproducibility broken (stale rawDesc)

**Verdict: VERIFIED**

Method:
1. Ran `cd proto && buf generate` (no errors, no output).
2. `git diff --stat gen/`:
   ```
    gen/go/ramp/v1/ramp.pb.go | 2 +-
    gen/ts/ramp/v1/ramp_pb.ts | 2 +-
    2 files changed, 2 insertions(+), 2 deletions(-)
   ```
   → Exactly 2 files, 2 insertions + 2 deletions. **Matches claim.**

3. Diff around the RAMPResponse descriptor in `gen/go/ramp/v1/ramp.pb.go` line 7614:
   ```
   - "\x06policy\x18\x02 \x01(\x0e2\x1d.ramp.v1.ResourceAccessPolicyR\x06policy\"\xa3\x05\n" +
   + "\x06policy\x18\x02 \x01(\x0e2\x1d.ramp.v1.ResourceAccessPolicyR\x06policy\"\xbb\x06\n" +
   ```
   The length-prefix preceding `RAMPResponse` changes from `\xa3\x05` to `\xbb\x06`. **Matches claim.**

4. Varint decode (proto wire format = little-endian, 7 bits per byte, MSB = continuation):
   - `\xa3\x05`:
     - byte 0 = 0xA3 = `1010 0011` → continuation set, 7-bit payload = `010 0011` = 0x23 = 35
     - byte 1 = 0x05 = `0000 0101` → no continuation, payload = 5
     - varint = (5 << 7) | 35 = 640 + 35 = **675 bytes**
   - `\xbb\x06`:
     - byte 0 = 0xBB = `1011 1011` → continuation set, payload = `011 1011` = 0x3B = 59
     - byte 1 = 0x06 = `0000 0110` → no continuation, payload = 6
     - varint = (6 << 7) | 59 = 768 + 59 = **827 bytes**
   - Stale descriptor was 675 bytes; correct descriptor is 827 bytes. **Difference: 152 bytes** of descriptor bytes missing in the committed `gen/`.

5. Confirmed Go struct fields ARE already present in the committed `gen/go/ramp/v1/ramp.pb.go` (checked under `git stash` of the regenerate, then inspected the original):
   - Line 6354 (original committed file): `RetrievalEndpoint *string ... protobuf:"bytes,13,opt,name=retrieval_endpoint,..."`
   - Line 6357 (original committed file): `AgentIdentityHash *string ... protobuf:"bytes,14,opt,name=agent_identity_hash,..."`

6. Restored: `git stash pop` followed by `git checkout -- gen/`. `git status` confirms no tracked changes remain (only the pre-existing untracked `.claude/` directory).

Findings:
- **rawDesc is indeed stale.**
- **Stale by 152 bytes** (descriptor grew from 675 to 827 bytes).
- **Go struct fields ARE present** (`RetrievalEndpoint` field 13 and `AgentIdentityHash` field 14 on `RAMPResponse`), so the Go code can construct the new fields, but the embedded protobuf FileDescriptor (used for runtime reflection / dynamic message handling / well-known field discovery) lacks them.

Summary: Reproducibility check confirmed — committed `gen/` is out of sync; rawDesc for `RAMPResponse` is 152 bytes shorter than the source proto would generate. Go struct fields are present so static use works, but reflection-based consumers (grpcurl, dynamic proxies, BSR, etc.) will see a `RAMPResponse` descriptor missing fields 13 and 14.

---

## Counts

| Verdict | Count | Findings |
|---|---|---|
| VERIFIED | 8 | A1, A2, A4, A5, B1, C1, C2, NEW |
| PARTIAL | 2 | A3 (no contradiction reproducible — table marks field as deprecated, no "renamed" prose); B2 (pattern correct, count 34 not 49) |
| NOT REPRODUCIBLE | 0 | — |
