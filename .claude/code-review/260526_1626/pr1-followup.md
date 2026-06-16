# Follow-up review — commit `11dfc94`

Thanks for the fast turnaround. Mechanically clean (`buf generate` reproduces, `buf lint` / `buf breaking` pass). Five of six items from the previous review landed exactly. **Two things still need to be fixed before merge:** (1) a comment-semantics error in three places, and (2) the website was not updated, including one page that now directly contradicts the new proto.

---

## ⚠️ 1. `agent_identity_hash` is always sent — not "iff signed URL"

The field is **REQUIRED — always populated by the Exchange** (which always knows the agent's key from request authentication). The OPTIONAL aspect lives at the **delivery endpoint** (capable edges enforce; bearer CDNs ignore) — not at the field's presence on the response. Three places couple the wrong way:

- `proto/ramp/v1/ramp.proto:1221-1222` — *"Empty string when absent; non-empty iff a signed retrieval_endpoint is present."*
- `proto/ramp/v1/ramp.proto:1979` — *"Present iff retrieval_endpoint is."*
- `proto/CHANGELOG.md` (v1.0.3 → "Binding semantics" last bullet) — *"agent_identity_hash carries a value iff a signed retrieval_endpoint is present (empty string on TransactionResponse, field absent on RAMPResponse, otherwise)."*

Drop-in replacements:

**`TransactionResponse.agent_identity_hash` (`:1219`)**
```proto
// REQUIRED. RFC 7638 JWK Thumbprint (SHA-256) of the agent's Ed25519
// request-signing key (see "Retrieval-URL identity binding" above). Always
// populated by the Exchange — the agent's key is always known from request
// authentication. When a signed retrieval_endpoint is also returned, the
// Exchange embeds this same value into the HMAC-signed URL, binding the URL
// to the agent. Delivery-endpoint enforcement of the binding is OPTIONAL:
// capable edge functions verify it; bearer-only CDNs ignore it.
string agent_identity_hash = 10;
```

**`RAMPResponse.agent_identity_hash` (`:1978-1980`)**
```proto
// RFC 7638 JWK Thumbprint of the agent's Ed25519 request-signing key, echoed
// by the Broker from the Exchange's TransactionResponse. Same value and
// semantics as TransactionResponse.agent_identity_hash. Always populated when
// the response carries a transaction outcome.
optional string agent_identity_hash = 14;
```

**CHANGELOG → replace the last "Binding semantics" bullet with:**
> `agent_identity_hash` is always populated by the Exchange (and echoed by the Broker) — the field captures the agent's identity, not the URL's binding. The binding exists when a signed `retrieval_endpoint` is also returned; enforcement of the binding is OPTIONAL at the delivery endpoint.

---

## ⚠️ 2. Website was not updated — including a page that now contradicts the proto

PR #1 touches zero files under `website/`. The following pages need work; **2a is a blocker** because it describes a fundamentally different (and weaker) binding mechanism than the new proto.

### 2a — `website/src/content/docs/components/edge-function/signed-url-verification.mdx` — **REWRITE the "Agent Identity Binding" section (~lines 80-171)**

Today this page is the website's authoritative binding spec and it defines:

- `agent_identity_hash` = **`SHA-256(license_id)`** (`:85`, `:100`) — not RFC 7638 JWK Thumbprint.
- Binding = agent self-reports `X-Agent-License-Id` header; edge re-hashes and compares (`:131-139`, `:147-152`).
- Page itself rates this as *"Medium — agent self-reports. **Can be spoofed**"* (`:164`) and *"does not prevent a determined attacker who knows the license ID"* (`:169`).

The new proto defines a strictly stronger mechanism (RFC 7638 thumbprint, HMAC-bound, RFC 9421 proof-of-possession, no JWKS fetch). Required rewrite, summary form:

- **Definition**: `agent_identity_hash` = RFC 7638 JWK Thumbprint (SHA-256) of the agent's Ed25519 request-signing key — base64url, one canonical computation per RFC 7638. Embed it as a signed URL parameter so it is covered by the HMAC.
- **What the agent presents at fetch**: its public key (header or query — security-equivalent because the thumbprint is HMAC-locked) **and** an RFC 9421 HTTP Message Signature over the retrieval request.
- **What the edge does, fully offline** (drop the `X-Agent-License-Id` mechanism):
  1. Recompute the URL HMAC with the shared secret → proves the embedded `agent_identity_hash` is Exchange-issued and untampered.
  2. Check expiry.
  3. `thumbprint(presented key) == agent_identity_hash`.
  4. Verify the RFC 9421 signature with the presented key (proof-of-possession).
- **Why a stolen URL is harmless**: the attacker must present the agent's *public* key (to pass step 3) and prove possession of its *private* key (to pass step 4) — one without the other doesn't work, and `agent_identity_hash` itself is HMAC-locked so it can't be swapped.
- **Cite RFC 9449 (DPoP) as the pattern**, RFC 7638 as the thumbprint definition, RFC 9421 as the request signature spec.
- **Optionality**: bearer-only CDNs that can't run code fall back to HMAC + short TTL + TLS. Reference implementations run on edge functions and enforce the binding.
- Update the existing mermaid sequence (`:141-158`) to: `present key + sign request` instead of `send X-Agent-License-Id`; edge does HMAC + thumbprint + Ed25519-verify, not `SHA-256(header value)`.
- The "Identity verification methods" table (`:160-167`) becomes obsolete — replace with a small "edge-function vs. bearer-only CDN" capability matrix.

### 2b — `website/src/content/docs/reference/proto-ramp.mdx` — stale field reference

- `:282` still reads *"`agent_identity_hash` … REQUIRED. Agent identity bound into URLs"*. Update to the new full definition.
- Missing every new field: `TransactionResponse.retrieval_endpoint = 18`, `TransactionResultItem.retrieval_endpoint = 12`, `RAMPResponse.retrieval_endpoint = 13`, and `RAMPResponse.agent_identity_hash = 14`. Add entries.

### 2c — `website/src/content/docs/reference/changelog.mdx` — stale by three versions

Currently stops at v1.0. Mirror `proto/CHANGELOG.md` for v1.0.1, v1.0.2, v1.0.3 — at minimum v1.0.3 from this PR.

### 2d — `website/src/content/docs/protocol/authentication.mdx` — silent

Add a "Retrieval-URL identity binding" subsection (or forward link to `signed-url-verification.mdx`) so the binding is reachable from the canonical auth docs page. Mirror the proto header paragraph at `ramp.proto:103-117`.

### 2e — Old CoMP nested `retrieval.{endpoint,auth,type}` JSON in examples — 7 files

The PR removed the "CoMP Package with `retrieval.endpoint`" comments from the proto, but these pages still show the old nested CoMP JSON shape in examples:

- `protocol/transaction-flow.mdx` — line 326 also contains *"The `retrieval.endpoint` contains a CDN signed URL. The agent fetches it directly — **no further authorization needed**. The CDN verifies the signature natively."* — this directly contradicts the new binding contract; replace.
- `protocol/walkthrough-medical-imaging.mdx`
- `protocol/scenario-walkthrough.mdx`
- `components/agent-sdk/fetch-flow.mdx`
- `architecture/production-architecture.mdx`
- `getting-started/poc-walkthrough.mdx`
- `reference/proto-ramp.mdx` (also covered by 2b)

In each, replace the nested `"retrieval": { "endpoint": "...", "auth": "...", "type": [...] }` object with the flat top-level `"retrieval_endpoint": "..."` field, and surface `agent_identity_hash` and `expires_at` alongside it.

---

## Net

- **Proto**: three small comment fixes (drop-in text above).
- **Website**: §2a is a blocker (it documents the wrong mechanism); 2b–2e are propagation work but should ship with this PR so the spec, proto comments, generated SDKs, and site stay in lockstep — that was the original principle of this review.

Keeping `CHANGES_REQUESTED`. Happy to look at the next push as soon as you have it.
