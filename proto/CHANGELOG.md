# RAMP Protocol Changelog

## ## v1.1.0 (2026-05-26) — Unified well-known endpoint

Every RAMP participant — agent, broker, exchange, publisher — now serves
a single canonical document at `/.well-known/ramp.json`, populated from
`WellKnownManifest`. The per-role filenames (`ramp-agent.json`,
`ramp-exchange.json`, `ramp-verifier.json`) and the legacy
`/marketplace/v1/keys` path are removed from the spec.

### New messages
- `WellKnownManifest` — unified self-description. Role-tagged via the new
  `Role` enum. Carries inline `JsonWebKey` keys, optional
  `invalidation_url`, publisher-only `exchanges[]` + `catalog_contributors[]`,
  and exchange-only capability fields (pricing, delivery, auth methods,
  OIDC issuer, GNAP grant endpoint, base currency, supported profiles).
- `JsonWebKey` — inline RFC 7517 JWK. Ed25519 only in v1.1.0 (`kty="OKP"`,
  `crv="Ed25519"`, `alg="EdDSA"`). Carries explicit `not_before` / `not_after`
  RFC3339 time bounds.
- `KeyInvalidationList` — kid-only revocation list served at
  `invalidation_url`. Snapshot semantics.
- `Role` enum: `AGENT`, `EXCHANGE`, `BROKER`, `PUBLISHER`. Verifiers fold
  into the role their operator holds — there is no separate verifier role.

### Deprecations (kept on the wire for one cycle)
- `ProviderManifest` — replaced by `WellKnownManifest` with
  `role=ROLE_PUBLISHER`.
- `ExchangeManifest` — replaced by `WellKnownManifest` with
  `role=ROLE_EXCHANGE`.
- `ExchangeManifest.keys_uri` and `ExchangeManifest.jwks_uri` — pointer
  patterns replaced by inline `JsonWebKey` objects.

### JSON wire rename (intentional consumer-visible change)
- `ProviderManifest.marketplaces` → `ProviderManifest.exchanges`. Proto
  wire tag 4 preserved. JSON consumers reading the legacy key MUST update.
  The same rename applies to the corresponding field on
  `WellKnownManifest` (field 7).

### Verifier transition
Verifier-specific metadata historically published at
`/.well-known/ramp-verifier.json` migrates to `WellKnownManifest`.
Verifier signing keys appear in `public_keys`. The verifier's
`claims_schema` URL (and any vendor-specific metadata) move into
`WellKnownManifest.ext` under a namespaced key — recommended
`"ramp.attestation.claims_schema"`. Implementations operating a verifier
on a dedicated domain serve `WellKnownManifest` under whichever role
matches the operating party (typically `ROLE_EXCHANGE`).

### Compatibility
- Wire-additive at the proto-binary layer; no existing field tags moved
  or removed.
- JSON consumers of `ProviderManifest.marketplaces` MUST update to read
  `exchanges`.
- Consumers of the deprecated `ExchangeManifest.keys_uri` /
  `.jwks_uri` should switch to `WellKnownManifest.public_keys` before
  the next minor release removes the deprecated fields.

## v1.0.3 (2026-05-26) — Canonical retrieval endpoint field

Adds the missing scalar field for the signed retrieval URL on transaction
responses. Resolves stranded "CoMP Package with retrieval.endpoint" comments
left after the v1.0 CoMP decoupling.

### New fields
- `TransactionResponse.retrieval_endpoint` (string, field 18)
- `TransactionResultItem.retrieval_endpoint` (string, field 12)
- `RAMPResponse.retrieval_endpoint` (string, field 13)
- `RAMPResponse.agent_identity_hash` (string, field 14)

### Cleanup
- Removed orphan `// CoMP Package with retrieval.endpoint…` comments from
  `TransactionResultItem.resource_title` and `RAMPResponse.resource_title`.
- Reworded `TransactionResponse.expires_at` doc to reference
  `retrieval_endpoint` by name.
- Clarified `agent_identity_hash` doc (definition + binding) and aligned the
  `expires_at` and `retrieval_endpoint` absence wording across TransactionResponse,
  TransactionResultItem, and RAMPResponse.

### Design notes
- Pure RAMP-native scalar; does not re-couple core to `comp.v1`.
- No `RetrievalAuth` enum: signed URL is the only delivery auth mechanism
  today, identity binding lives on `agent_identity_hash`, lifetime lives on
  `expires_at`. Future auth mechanisms will be additive or extension-profile
  based.
- Backward compatible: optional, additive, no renumbering.

### Binding semantics
- `agent_identity_hash` is the RFC 7638 JWK Thumbprint (SHA-256) of the agent's
  Ed25519 request-signing key. The Exchange MAY embed it into the HMAC-signed
  `retrieval_endpoint` (DPoP-style, RFC 9449) and echo it in the response.
- Bound to the agent's request-signing key, never to the principal/delegation.
- A capable delivery endpoint (edge function) verifies the binding fully offline:
  confirm the URL HMAC, then require the fetcher to present its public key + an
  RFC 9421 signature and check `thumbprint(presented key) == agent_identity_hash`.
  No JWKS fetch required.
- Enforcement is OPTIONAL: bearer-only signed-URL CDNs fall back to HMAC + short
  TTL + TLS. RAMP reference implementations run on edge functions and DO enforce it.
- `agent_identity_hash` carries a value iff a signed `retrieval_endpoint` is
  present (empty string on `TransactionResponse`, field absent on `RAMPResponse`,
  otherwise).

## v1.0.2 (2026-04-01) — Resource Previews

Lightweight resource previews on Offers for pre-transaction evaluation.

### Preview Message (new)
- `url`: CDN-hosted preview URL (thumbnail, clip, snippet, sample)
- `media_type`: MIME type of the preview asset
- `width`, `height`: dimensions in pixels (for images/video)
- `duration`: duration in seconds (for audio/video clips)
- `size`: category hint — `"thumbnail"`, `"preview"`, `"sample"`

### Offer.previews (field 18)
- `repeated Preview previews` on the `Offer` message
- Zero Exchange memory impact — URLs only, bytes served by provider CDN
- Modeled after Shutterstock (multi-size thumbnails), Spotify (preview_url), IIIF (parameterized URLs), OpenRTB native (img + dimensions)

## v1.0.1 (2026-03-30) — C2PA Content Provenance Integration

C2PA Content Credentials integration via new core proto fields and the `ramp-c2pa-v1` extension profile.

### ResourceIdentity — C2PA Fields
- **`c2pa_manifest`** (field 7): expanded comment documenting sidecar, embedded, and Content Credentials Cloud URI formats
- **`c2pa_status`** (field 9): new `C2PAStatus` enum — `TRUSTED`, `VALID`, `INVALID`, `ABSENT`. Summary validation result populated by Exchange or verification vendor after validating the C2PA manifest
- **`soft_binding`** (field 10): content-derived identifier surviving format transcoding (perceptual hash, watermark). Extracted from C2PA soft binding assertion
- **`soft_binding_method`** (field 11): algorithm used for soft binding — `"phash-v1"`, `"c2pa-watermark"`, `"chromaprint"`

### C2PAStatus Enum
- `C2PA_STATUS_UNSPECIFIED` (0)
- `C2PA_STATUS_TRUSTED` (1): valid + chains to C2PA Trust List root
- `C2PA_STATUS_VALID` (2): signature verifies, signer not in Trust List
- `C2PA_STATUS_INVALID` (3): validation failed
- `C2PA_STATUS_ABSENT` (4): content checked, no C2PA manifest

### Extension Profile: ramp-c2pa-v1
- 16 standardized attestation claim names (`c2pa.status`, `c2pa.signer`, `c2pa.actions`, `c2pa.training_allowed`, `c2pa.mining_allowed`, etc.)
- Rights enforcement mapping: `c2pa.training_mining` → `AccessRestrictions.prohibited_functions`
- Soft binding dispute enhancement: post-transcoding content verification
- Three conformance levels: Level A (status + URI), Level B (bridged attestation + rights), Level C (full provenance + soft binding + TSA)
- Trust bridging: C2PA X.509/COSE validated by vendor, results published as RAMP Ed25519 attestation

## v0.3.0 (2026-03-18) — Content Attestation + Dispute Resolution

Content integrity verification via cryptographic attestations, structured dispute resolution, provider domain verification, and operational diagnostics.

### ResourceAttestation (replaces ResourceQuality)
- **ResourceAttestation** message — signed claim envelope from a trusted party (provider or verification vendor)
  - `verifier`: domain of the attesting party
  - `kid`: key ID from the verifier's JWKS
  - `attested_at`: timestamp of attestation
  - `uri`: content URI covered
  - `claims`: JSON claims (max 4KB) — `estimated_tokens`, `word_count`, `language`, `iab_categories`, `content_hash`, `hash_method`, plus vendor-specific claims
  - `signature`: Ed25519 over JCS-canonicalized (RFC 8785) representation
- Three verification levels:
  - **Level 0** (no attestations): identifiers only (DOI, IPTC GUID), nothing cryptographically verifiable; only CDN delivery failure is auto-disputable
  - **Level 1** (self-attested): provider signs own claims with Ed25519; agent can independently verify content hash; CDN delivery failure + hash mismatch are auto-disputable
  - **Level 2** (third-party attested): independent verification vendor crawled and attested; agent trusts attestation without re-verifying hash; token count discrepancy is auto-disputable when corroborated by CDN response size
- `ramp-verifier.json` well-known endpoint — verifiers MUST publish keys and claims schema at `https://{verifier}/.well-known/ramp-verifier.json` (JWKS pattern)
- **Offer.attestations** (`repeated ResourceAttestation`) replaces `ResourceQuality`
- **CatalogEntryProto.attestations** — attestations at catalog level
- **ResourceQuality message REMOVED** — subsumed by attestation claims; quality scores live in vendor-specific attestation claims, not as a protocol-level concept

### Dispute Resolution
- **DisputeStatus** enum (10 values): `UNSPECIFIED`, `FILED`, `AUTO_RESOLVED`, `EVIDENCE_NEEDED`, `UNDER_REVIEW`, `ESCALATED`, `RESOLVED`, `APPEALED`, `SETTLED`, `FINAL`
  - Three-tier resolution: Tier 1 automated (<1s), Tier 2 rule-based (<24h), Tier 3 pattern investigation (async)
  - Appeals: `RESOLVED` → `APPEALED` → re-enters `UNDER_REVIEW`
- **ResolutionType** enum (5 values): `UNSPECIFIED`, `CREDIT`, `REDELIVERY`, `REJECTED`, `INVESTIGATION`
- **DisputeRequest** message — agent signals content delivery problem
  - `transaction_id`, `billing_id`, `reason` (DisputeReason enum), `description`
  - `received_content_hash` + `received_hash_method` — evidence of what was actually received
  - `report_id` — MUST reference a filed UsageReport (dispute chain enforcement)
- **DisputeResponse** message — marketplace acknowledges and processes dispute
  - `dispute_id`, `rejection_reason`, `estimated_resolution`
  - `status` (DisputeStatus) — current lifecycle state
  - `resolution` (ResolutionType) — populated at terminal states
- **DisputeTransaction RPC** on MarketplaceService — `DisputeRequest` → `DisputeResponse`
- **Dispute chain**: `Offer` → `Transaction` (transaction_id) → `UsageReport` → `UsageReportResponse` (report_id) → `DisputeRequest` (transaction_id + report_id)
- **UsageReportResponse.report_id** — marketplace-assigned identifier enabling the dispute chain

### Domain Verification (Provider Onboarding)
- **RequestDomainVerification RPC** — `DomainVerificationRequest` → `DomainVerificationChallenge`
- **ConfirmDomainVerification RPC** — `DomainVerificationConfirmation` → `DomainVerificationResult`
- ACME HTTP-01 style flow: request challenge → place token at `{domain}/.well-known/ramp-verify/{token}` → confirm → marketplace verifies
- Atomic key registration: signing key registered upon successful verification
- Double protection: marketplace also checks `ramp.json` authorization

### Catalog Contributors
- **CatalogContributor** message — `domain` + `relationship` (e.g., "verifier", "marketplace")
- **ProviderManifest.catalog_contributors** — authorized third-party catalog pushers
- Prevents unauthorized parties from pushing fake attestations for providers they don't represent

### Operational Diagnostics
- **OfferAbsenceReason** enum (7 values + UNSPECIFIED): `NOT_IN_CATALOG`, `CONTENT_BLOCKED`, `FUNCTION_PROHIBITED`, `GEO_RESTRICTED`, `USER_CATEGORY_PROHIBITED`, `TEMPORARILY_UNAVAILABLE`, `NOT_AUTHORIZED`
- **OfferGroup.absence_reason** — per-URI diagnostic when no offers available
- **RateLimitInfo** message — `limit`, `remaining`, `reset_at`, `window` (modeled after IETF RateLimit header fields)
- **SupplyResponse.rate_limit** — enables proactive throttling for Orchestrator fanout

### Breaking Changes from v0.2
- **ResourceQuality removed** — use `Offer.attestations` with `ResourceAttestation` claims instead
- **Offer.quality removed** — replaced by `Offer.attestations`

## v0.2.0 (2026-03-16) — Production-Ready Protocol

First complete protocol specification with full system design, threat model, and expert review.

### MarketplaceService RPCs
- `DiscoverSupply` — single and batch (multi-URI via OfferGroup)
- `ExecuteTransaction` — single and batch (TransactionItem/TransactionResultItem)
- `ReportUsage` — mandatory post-usage reporting

### CatalogService RPCs (for content intelligence providers)
- `PushContent` — signed, with provenance tracking
- `RemoveContent`
- `RefreshCatalog`

### Authentication
- Ed25519 at every boundary (RAMP Authentication Principle)
- Agent signs requests (Ed25519, key at `/.well-known/ramp-agent.json`)
- Orchestrator co-signs forwarded requests (Ed25519)
- Marketplace signs offers (Ed25519, key at `/marketplace/v1/keys`)
- Provider authorizes Marketplaces via `ramp.json`
- Signed URLs use HMAC-SHA256 (Marketplace↔CDN shared secret)
- `lid` is a public identifier, not a credential

### Offers and Pricing
- ResourceQuality metadata (editorial_tier, quality_score, quality_scorer)
- ResourceIdentity with layered verification (Level 0/1/2: none/SimHash/SHA-256)
- AccessRestrictions from RSL permits/prohibits
- IAB Content Taxonomy codes (iab_categories)
- 8 PricingModel values (per_article, per_token, per_crawl, subscription, free, attribution, contribution, training)
- Subscription offers (subscription_id, zero marginal cost)
- subscription_unit_value for ASC 606 cost attribution
- Mandatory marketplace_signature (Ed25519) on every Offer

### Transaction Security
- DenialReason enum (11 values) for structured denial vocabulary
- agent_identity_hash bound into signed URLs
- Idempotency via TransactionRequest.id
- Write-before-sign invariant (WAL)

### Discovery
- ProviderManifest at `/.well-known/ramp.json`
- DiscoveryMethod enum (marketplace, search, recommendation, syndication) — v2 extension point
- IngestionSource enum (7 sources + catalog API)

### Reporting
- Mandatory UsageReport with required token_count
- ReportingObligation with window and required_fields
- Two independent metrics: compliance rate vs token accuracy

### Built on
- IAB Tech Lab CoMP v1.0 (all 9 objects mapped 1:1)
- RSL 1.0 (pricing, permits, prohibits mapped to RAMP)
- Protobuf + Connect (HTTP/JSON + gRPC dual protocol)

### Changes from v0.1 (IAB draft)
- Added transaction protocol (CoMP defines data model only, not transport)
- Added discovery mechanism (ramp.json, edge function 403 redirect)
- Added content identity and cross-marketplace dedup
- Added pricing normalization (eCPT)
- Added mandatory usage reporting
- Added threat model with 30 attack vectors and countermeasures
- Added Ed25519 authentication principle
- Added subscription/direct deal transaction mode
- Added batch multi-URL queries
- Added content quality signals
- Added provider audit API
