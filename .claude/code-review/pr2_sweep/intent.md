# PR #2 Intent Sweep — `well-known-ramp-json-unified` @ `2fe4e6d`

Read-only verification of each stated intent against the branch tip.
Baseline: pre-`596d895` (everything on this branch before that commit is the
PR #2 surface).

---

## 1. Unified `/.well-known/ramp.json` for every role; legacy paths gone

**Verdict: ✅ delivered correctly**

- `WellKnownManifest` is defined once and is the only manifest carried
  forward as the canonical document: `proto/ramp/v1/ramp.proto:1774`.
- Top-of-file roadmap is explicit that every role serves the same path:
  `proto/ramp/v1/ramp.proto:109-112`
  ```
  Agent:      {domain}/.well-known/ramp.json
  Broker:     {domain}/.well-known/ramp.json
  Exchange:   {domain}/.well-known/ramp.json
  Publisher:  {domain}/.well-known/ramp.json (keys + authorization)
  ```
- Legacy per-role filenames and `/marketplace/v1/keys` are declared
  removed from the spec: `proto/ramp/v1/ramp.proto:73-74` and
  `proto/CHANGELOG.md:7-10`.
- Website: every appearance of the legacy filenames is now in a "removed
  in v1.1.0" framing — see `website/.../protocol/authentication.mdx:544`,
  `.../protocol/exchange-manifest.mdx:12,118`,
  `.../reference/proto-ramp.mdx:588`,
  `.../reference/changelog.mdx:8`. No instruction tells the reader to
  fetch any of the legacy paths.

**One cosmetic blemish (not a regression):**
`website/.../protocol/authentication.mdx:544` writes
"`/exchange/v1/keys` endpoint are removed" while the proto + CHANGELOG say
`/marketplace/v1/keys`. The path being deprecated is the legacy
`marketplace` form; the website prematurely renamed even the deprecated
path. Reader-facing, harmless.

---

## 2. `WellKnownManifest` shape (role-tagged, inline keys, per-role fields)

**Verdict: ✅ delivered correctly**

`proto/ramp/v1/ramp.proto:1774-1876` — full message. Sweep of the
required surface:

| Required by intent | Field | Line |
|---|---|---|
| Role enum | `Role role = 2` | 1780 |
| Inline JWK keys | `repeated JsonWebKey public_keys = 5` | 1791 |
| Optional `invalidation_url` | `optional string invalidation_url = 6` | 1799 |
| Publisher-only `exchanges[]` | `repeated AuthorizedExchange exchanges = 7` | 1804 |
| Publisher-only `catalog_contributors[]` | field 8 | 1808 |
| Exchange-only pricing models | `pricing_models_supported` (PricingModel) | 1834 |
| Exchange-only delivery methods | `delivery_methods_supported` | 1837 |
| Exchange-only auth methods | `supported_auth_methods` | 1858 |
| OIDC issuer | `oidc_issuer` | 1861 |
| GNAP grant endpoint | `gnap_grant_endpoint` | 1864 |
| Base currency | `base_currency` | 1868 |
| Supported profiles | `supported_profiles` | 1854 |

Comment block at 1769-1770 explicitly states "consumers MUST ignore
non-applicable fields based on `role`," matching the intent.

`Role` enum (line 1720): `ROLE_UNSPECIFIED=0, ROLE_AGENT=1,
ROLE_EXCHANGE=2, ROLE_BROKER=3, ROLE_PUBLISHER=4` — exact set the
intent asked for, no verifier role.

---

## 3. `JsonWebKey` (RFC 7517 inline JWK; Ed25519-only; half-open interval)

**Verdict: ✅ delivered correctly**

`proto/ramp/v1/ramp.proto:1737-1762`:

- `kty=OKP` (1742), `crv=Ed25519` (1745), `use=sig` (1748),
  `alg=EdDSA` (1751), `x` = base64url Ed25519 public key (1754) —
  matches RFC 7517 OKP/Ed25519.
- Ed25519-only restriction stated at 1730; "Additional curves are a
  v1.2+ concern" (1731).
- `not_before` (1757) and `not_after` (1759-1761) — both RFC3339
  strings; `not_after` is explicitly named a "strict upper bound."
- **The 480cadd fix is in and correct.** The at-least-one-valid-key
  invariant at 1734-1735 reads
  `MUST have `not_before <= now < not_after``. Half-open `<=, <`. This
  is internally consistent: `not_after` is documented (1759-1760) as
  "Key is invalid at and after this instant (strict upper bound)" —
  the `<` matches that exactly.
- Git provenance: see `git show 480cadd -- proto/ramp/v1/ramp.proto`
  — the diff changes `<= now <= not_after` to `<= now < not_after`,
  no other behavioral change.

---

## 4. `KeyInvalidationList`

**Verdict: ✅ delivered correctly**

`proto/ramp/v1/ramp.proto:1886-1893`:
- Comment block (1878-1885) states snapshot semantics: "`revoked` is the
  complete list of revoked kids at `as_of`. Consumers replace their local
  revocation set on each successful poll (no diff protocol)."
- Permanent-revocation note: "A revoked kid stays revoked permanently;
  once dropped from the list, consumers MAY drop it from their local set
  but the corresponding key SHOULD NOT be re-introduced into
  WellKnownManifest.public_keys" (1882-1885).
- Fields: `as_of` (Timestamp), `revoked` (repeated string of kids). Kid-only,
  as required.
- Served-at-`invalidation_url` linkage stated in the comment header at
  line 1878.

---

## 5. Caching contract (`480cadd`)

**Verdict: ✅ delivered correctly**

`proto/ramp/v1/ramp.proto:1691-1702`:
- "`/.well-known/ramp.json` MAY be cached by consumers and CDNs for
  routine periods (minutes to hours)" (1692-1693).
- "The `invalidation_url` body, by contrast, SHOULD be served with a
  short or zero freshness lifetime (e.g. Cache-Control: max-age=60, or
  no-store) so the 300s consumer poll is not defeated by an intermediary
  cache" (1694-1697).
- "Enforcement is operational, not protocol-guaranteed: a consumer that
  grants access against a stale revocation set bears that as its own
  business risk — it is not a protocol deficiency" (1700-1702).
- Pointer from the field is present:
  `proto/ramp/v1/ramp.proto:1797-1798` — the `invalidation_url` field
  comment ends with "This list's freshness bounds revocation latency —
  see the caching contract in the Well-Known Discovery section above."

---

## 6. Domainless requesters (`480cadd`)

**Verdict: ✅ delivered correctly**

`proto/ramp/v1/ramp.proto:1704-1714`:
- Registry-hosted-manifest pattern documented: "a registry … hosts the
  agent's WellKnownManifest, and the agent sets Requester.domain to that
  registry host" (1705-1708).
- Anchor relaxation explicitly deferred: "Relaxing the discovery anchor
  (e.g. an explicit per-requester keys URL) is intentionally deferred:
  revisit at the protocol level only if self-hosting or registry-hosting
  proves too rigid in practice" (1712-1714).

---

## 7. Verifier transition (claims_schema → ext; no dedicated role)

**Verdict: ✅ delivered correctly**

- `Role` enum comment (`proto/ramp/v1/ramp.proto:1717-1719`):
  "Verifiers fold into the role of the domain that operates them
  (typically EXCHANGE or PUBLISHER); they are not a distinct role." No
  `ROLE_VERIFIER` value.
- `ResourceAttestation` block updated:
  `proto/ramp/v1/ramp.proto:671-676` — verifier keys published at
  `/.well-known/ramp.json` (no more `ramp-verifier.json`), and the
  claims-schema migration is explicit: "Claims-schema location migrated
  to `ext` under key `\"ramp.attestation.claims_schema\"` (see Verifier
  transition in CHANGELOG)."
- `verifier` and `kid` field comments echo the new location
  (`proto/ramp/v1/ramp.proto:681-682, 685-689`).
- CHANGELOG verifier-transition section: `proto/CHANGELOG.md:55-63`.
- Website also updated:
  - `website/.../reference/changelog.mdx:41` — full verifier-transition
    paragraph, including the
    `ROLE_PUBLISHER` (self-attesting) / `ROLE_EXCHANGE` (standalone)
    operator-role guidance.
  - `website/.../protocol/content-attestation.mdx:90` — "RAMP has no
    dedicated verifier role… the claims schema … moves into
    `ext[\"ramp.attestation.claims_schema\"]`."
  - `website/.../protocol/content-attestation.mdx:114,146` — JSON example
    and prose both anchor on the new `ext["ramp.attestation.claims_schema"]`
    key.

---

## 8. Deprecations kept on the wire

**Verdict: ✅ delivered correctly**

All four required `[deprecated = true]` annotations are present and the
messages/fields remain on the wire (not removed):

| Target | Annotation | Line |
|---|---|---|
| `message ProviderManifest` | `option deprecated = true;` | `proto/ramp/v1/ramp.proto:1903-1904` |
| `message ExchangeManifest` | `option deprecated = true;` | `proto/ramp/v1/ramp.proto:1992-1993` |
| `ExchangeManifest.keys_uri` | `[deprecated = true]` | `proto/ramp/v1/ramp.proto:2014` |
| `ExchangeManifest.jwks_uri` | `[deprecated = true]` | `proto/ramp/v1/ramp.proto:2080` |

CHANGELOG mirrors the list at `proto/CHANGELOG.md:26-32`.

---

## 9. JSON-breaking rename documented loudly in CHANGELOG

**Verdict: ✅ delivered correctly**

`proto/CHANGELOG.md:34-53` carries the rename table and the
"binary holds / JSON consumers MUST update" statement (lines 36-37,
"All proto wire tags preserved; binary compatibility holds. JSON field
names change. Every consumer reading renamed fields MUST update").

Rename table covers `ProviderManifest`, `WellKnownManifest`,
`ResourceResponse`, `UsageReport`, `RequestConstraints` (twice), and
`DomainVerificationRequest`. Enum value rename
(`DISCOVERY_METHOD_MARKETPLACE` → `DISCOVERY_METHOD_EXCHANGE`, number 1
preserved) is its own sub-table (51-53).

Verifier-transition section at lines 55-63.

---

## 10. `buf.yaml` rename suppressions

**Verdict: ✅ delivered correctly**

`proto/buf.yaml:19-29`:
```
breaking:
  use:
    - FILE
  except:
    # marketplace → exchange repo-wide rename (v1.1.0): all wire field names
    # and the DISCOVERY_METHOD_MARKETPLACE enum value are renamed. Wire tags
    # preserved throughout; binary compatibility holds. JSON consumers must
    # update field names.
    - FIELD_SAME_NAME
    - FIELD_SAME_JSON_NAME
    - ENUM_VALUE_SAME_NAME
```

All three required `except` rules are present with the explanatory
comment.

---

## 11. Mechanical checks

All three pass.

| Check | Command (from `proto/` unless noted) | Result |
|---|---|---|
| `buf generate` reproducibility | `cd proto && buf generate` then `git status -s gen/ proto/` | **clean** — zero diff against committed `gen/` |
| `buf lint` | `cd proto && buf lint` | **exit 0**, no findings |
| `buf breaking` vs `main` | `buf breaking proto --against ".git#branch=main,subdir=proto"` (from repo root) | **exit 0**, no findings |

Note: `buf breaking` must be invoked from the repo root with the
`proto` argument (`buf breaking proto …`) — running from inside
`proto/` fails because there is no `.git` directory there. This is a
buf invocation detail, not a protocol issue.

---

## 12. CHANGELOG completeness vs the wire changes

**Verdict: ✅ delivered correctly**

The 480cadd follow-ups are all present in `proto/CHANGELOG.md`
"Discovery & key-validity semantics" subsection (lines 65-75):

- Caching contract (66-69): "MAY be cached (minutes–hours); … SHOULD be
  short/no-store … Stale-revocation enforcement is operational, not
  protocol-guaranteed."
- Key-validity bound (70-72): "half-open `[not_before, not_after)`.
  Clarified the at-least-one-valid-key invariant comment
  (`not_before <= now < not_after`) to match the `not_after` \"strict
  upper bound\" definition — no behavior change."
- Domainless requesters (73-75): "accommodated via a registry-hosted
  `WellKnownManifest` (agent sets `Requester.domain` to the registry
  host); no protocol change. Relaxing the discovery anchor is deferred."

The CHANGELOG also covers everything the proto actually does:
new messages (12-24), deprecations (26-32), rename table (34-53),
verifier transition (55-63), compatibility summary (77-84).

---

## Overall verdict

**✅ All 12 intent items delivered correctly.** The PR fulfils its stated
goal: a single canonical `/.well-known/ramp.json` for every role,
inline JWK keys with explicit half-open validity windows, a kid-only
revocation list with snapshot semantics, an operational caching
contract that doesn't lie about emergency-revocation latency, a
domainless-agent escape hatch documented at the protocol level, the
verifier role folded into operator role with metadata migrated to
`ext`, deprecated predecessors kept on the wire, and a buf
configuration that lets the JSON rename land without lying about
binary compatibility. All mechanical gates (lint, breaking, gen
reproducibility) are green.

---

## Open items / risks

1. **Cosmetic doc inconsistency (low):**
   `website/.../protocol/authentication.mdx:544` writes
   `/exchange/v1/keys` while the spec source-of-truth (proto + proto
   CHANGELOG) says `/marketplace/v1/keys`. Both refer to the same
   removed-in-v1.1 endpoint; the website pre-renamed the legacy path
   name. Worth a one-character fix on the next pass — not a wire issue.

2. **Branch is behind main:** PR #1 merged after this branch forked.
   `buf breaking` is still clean against current `main`, but the user
   will want to rebase before merging PR #2 so the public history is
   linear. (Explicitly out of scope for this read-only sweep — flagging
   only.)

3. **`comp.proto` still mentions "Marketplace" in two comments**
   (`proto/comp/v1/comp.proto:53,126`). Those are descriptive prose
   inside CoMP-aligned messages, not wire identifiers, and the CoMP
   alignment lineage may justify keeping the historical term. Worth a
   conscious decision; not a defect.

4. **Deprecation removal cadence is stated but not scheduled:** the
   CHANGELOG says deprecated messages "kept on the wire for one cycle"
   (line 26) and "before the next minor release removes the deprecated
   fields" (lines 83-84). No tracking item ties the next minor's removal
   to a date or version — fine for now, but worth tracking in an issue
   so removal actually happens on schedule.
