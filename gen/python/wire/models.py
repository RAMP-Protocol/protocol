# Code generated from the RAMP proto (via JSON Schema). DO NOT EDIT.
# Regenerate: scripts/gen-sdk-types.sh   Base class / extension seam: wire/base.py

from __future__ import annotations

from typing import Any
from pydantic import AwareDatetime, Field, RootModel, conint, constr
from enum import Enum
from wire.base import WireModel



class AuthMethod(Enum):
    AUTH_METHOD_GNAP = 'AUTH_METHOD_GNAP'
    AUTH_METHOD_OAUTH_DPOP = 'AUTH_METHOD_OAUTH_DPOP'
    AUTH_METHOD_OAUTH_BEARER = 'AUTH_METHOD_OAUTH_BEARER'
    AUTH_METHOD_OAUTH_MTLS = 'AUTH_METHOD_OAUTH_MTLS'


class C2PAStatus(Enum):
    C2PA_STATUS_TRUSTED = 'C2PA_STATUS_TRUSTED'
    C2PA_STATUS_VALID = 'C2PA_STATUS_VALID'
    C2PA_STATUS_INVALID = 'C2PA_STATUS_INVALID'
    C2PA_STATUS_ABSENT = 'C2PA_STATUS_ABSENT'


class CatalogContributor(WireModel):
    domain: str | None = Field(
        '',
        description='Canonical domain of the authorized contributor (e.g., "doubleverify.com").',
    )
    relationship: str | None = Field(
        '',
        description='Relationship of this contributor to the provider.\n Examples: "verifier" (resource intelligence vendor that attests to resource\n properties), "exchange" (an Exchange that enriches catalog entries).',
    )


class CatalogRejectionReason(Enum):
    CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR = (
        'CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR'
    )
    CATALOG_REJECTION_REASON_TENANT_MISMATCH = (
        'CATALOG_REJECTION_REASON_TENANT_MISMATCH'
    )
    CATALOG_REJECTION_REASON_DOMAIN_NOT_VERIFIED = (
        'CATALOG_REJECTION_REASON_DOMAIN_NOT_VERIFIED'
    )
    CATALOG_REJECTION_REASON_SIGNATURE_INVALID = (
        'CATALOG_REJECTION_REASON_SIGNATURE_INVALID'
    )
    CATALOG_REJECTION_REASON_MALFORMED_ENTRY = (
        'CATALOG_REJECTION_REASON_MALFORMED_ENTRY'
    )
    CATALOG_REJECTION_REASON_UNKNOWN_VOCAB_TOKEN = (
        'CATALOG_REJECTION_REASON_UNKNOWN_VOCAB_TOKEN'
    )
    CATALOG_REJECTION_REASON_QUOTA_EXCEEDED = 'CATALOG_REJECTION_REASON_QUOTA_EXCEEDED'


class CitationFormat(Enum):
    CITATION_FORMAT_LINK = 'CITATION_FORMAT_LINK'
    CITATION_FORMAT_FOOTNOTE = 'CITATION_FORMAT_FOOTNOTE'
    CITATION_FORMAT_INLINE = 'CITATION_FORMAT_INLINE'


class Cost(WireModel):
    amount: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$') | None = Field(
        '',
        description='Exact decimal string (not a float), e.g. "19.99". Denominated in `currency`.',
    )
    currency: str | None = ''
    unitCost: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$') | None = None


class Delegation(WireModel):
    expiresAt: AwareDatetime | None = Field(
        None,
        description='When this delegation expires. Exchange MUST reject expired tokens.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    issuer: str | None = Field(
        None,
        description='Token issuer. OIDC issuer URL or GNAP grant server URL.\n Exchange uses this for JWT validation (OIDC discovery → JWKS)\n or GNAP token introspection.',
    )
    maxAccesses: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Maximum number of accesses allowed under this delegation.\n Exchange tracks cumulative access count against this cap.\n Deny with DENIAL_REASON_QUOTA_EXCEEDED when count >= limit.\n For subscriptions with "10,000 accesses/month", this carries the ceiling.',
    )
    maxSpendCents: int | None = Field(
        None,
        description='Maximum spend in currency minor units (e.g., cents for USD).\n Exchange tracks cumulative spend against this cap.',
    )
    principalDomain: str | None = Field(
        '', description='Who granted this delegation (domain for public key lookup).'
    )
    principalId: str | None = Field(
        '',
        description='Principal\'s identifier (e.g., "user@acme.com", "marketdata.example.com").',
    )
    quotaPeriod: str | None = Field(
        None,
        description='Quota reset period. How often the access/spend counters reset.\n Example: 720h (30 days) for monthly subscriptions.\n When absent, the quota is lifetime (bounded only by expires_at).',
    )
    revocationUri: str | None = Field(
        None,
        description='Optional: URI for real-time revocation checking.\n Exchange MAY check this for high-value transactions.\n Not checked for routine low-value access (performance tradeoff).',
    )
    scopes: list[str] | None = Field(
        None,
        description="Scopes granted by this delegation. MUST be a subset of the\n principal's own scopes (attenuation — can only narrow, not widen).",
    )
    token: constr(pattern=r'^[A-Za-z0-9+/]*={0,2}$') | None = Field(
        None,
        description='Token bytes. A JWT (base64url-encoded JWS) by default, or a Biscuit (binary,\n base64-encoded) when token_format is "biscuit-v3".',
    )
    tokenFormat: str | None = Field(
        '',
        description='Token format: "jwt" (default) or "biscuit-v3" (optional, for deep\n multi-hop offline attenuation). Empty is treated as "jwt".',
    )


class DeliveryMethod(Enum):
    DELIVERY_METHOD_DIRECT = 'DELIVERY_METHOD_DIRECT'
    DELIVERY_METHOD_INSTRUCTIONS = 'DELIVERY_METHOD_INSTRUCTIONS'
    DELIVERY_METHOD_STREAMING = 'DELIVERY_METHOD_STREAMING'


class DenialReason(Enum):
    DENIAL_REASON_BILLING_REF_INACTIVE = 'DENIAL_REASON_BILLING_REF_INACTIVE'
    DENIAL_REASON_INSUFFICIENT_BALANCE = 'DENIAL_REASON_INSUFFICIENT_BALANCE'
    DENIAL_REASON_RATE_LIMITED = 'DENIAL_REASON_RATE_LIMITED'
    DENIAL_REASON_CONTENT_UNAVAILABLE = 'DENIAL_REASON_CONTENT_UNAVAILABLE'
    DENIAL_REASON_RESTRICTION_NOT_SATISFIED = 'DENIAL_REASON_RESTRICTION_NOT_SATISFIED'
    DENIAL_REASON_REPORTING_OVERDUE = 'DENIAL_REASON_REPORTING_OVERDUE'
    DENIAL_REASON_OFFER_EXPIRED = 'DENIAL_REASON_OFFER_EXPIRED'
    DENIAL_REASON_SIGNATURE_INVALID = 'DENIAL_REASON_SIGNATURE_INVALID'
    DENIAL_REASON_QUOTA_EXCEEDED = 'DENIAL_REASON_QUOTA_EXCEEDED'
    DENIAL_REASON_DELEGATION_INVALID = 'DENIAL_REASON_DELEGATION_INVALID'
    DENIAL_REASON_SCOPE_INSUFFICIENT = 'DENIAL_REASON_SCOPE_INSUFFICIENT'
    DENIAL_REASON_ENTITLEMENT_MISSING = 'DENIAL_REASON_ENTITLEMENT_MISSING'
    DENIAL_REASON_ENTITLEMENT_MALFORMED = 'DENIAL_REASON_ENTITLEMENT_MALFORMED'
    DENIAL_REASON_ENTITLEMENT_EXPIRED = 'DENIAL_REASON_ENTITLEMENT_EXPIRED'
    DENIAL_REASON_ENTITLEMENT_WRONG_BUYER = 'DENIAL_REASON_ENTITLEMENT_WRONG_BUYER'
    DENIAL_REASON_SUBSCRIPTION_LAPSED = 'DENIAL_REASON_SUBSCRIPTION_LAPSED'
    DENIAL_REASON_ENTITLEMENT_NOT_GRANTED = 'DENIAL_REASON_ENTITLEMENT_NOT_GRANTED'
    DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION = (
        'DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION'
    )


class DiscoveryMethod(Enum):
    DISCOVERY_METHOD_EXCHANGE = 'DISCOVERY_METHOD_EXCHANGE'
    DISCOVERY_METHOD_SEARCH = 'DISCOVERY_METHOD_SEARCH'
    DISCOVERY_METHOD_RECOMMENDATION = 'DISCOVERY_METHOD_RECOMMENDATION'
    DISCOVERY_METHOD_SYNDICATION = 'DISCOVERY_METHOD_SYNDICATION'


class DisputeFailureReason(Enum):
    DISPUTE_FAILURE_REASON_TRANSACTION_NOT_FOUND = (
        'DISPUTE_FAILURE_REASON_TRANSACTION_NOT_FOUND'
    )
    DISPUTE_FAILURE_REASON_REPORT_NOT_FILED = 'DISPUTE_FAILURE_REASON_REPORT_NOT_FILED'
    DISPUTE_FAILURE_REASON_WINDOW_EXPIRED = 'DISPUTE_FAILURE_REASON_WINDOW_EXPIRED'
    DISPUTE_FAILURE_REASON_DUPLICATE = 'DISPUTE_FAILURE_REASON_DUPLICATE'
    DISPUTE_FAILURE_REASON_INELIGIBLE = 'DISPUTE_FAILURE_REASON_INELIGIBLE'


class DisputeReason(Enum):
    DISPUTE_REASON_CONTENT_MISMATCH = 'DISPUTE_REASON_CONTENT_MISMATCH'
    DISPUTE_REASON_DELIVERY_FAILED = 'DISPUTE_REASON_DELIVERY_FAILED'
    DISPUTE_REASON_WRONG_CONTENT = 'DISPUTE_REASON_WRONG_CONTENT'
    DISPUTE_REASON_EXPIRED_BEFORE_FETCH = 'DISPUTE_REASON_EXPIRED_BEFORE_FETCH'
    DISPUTE_REASON_INCOMPLETE_CONTENT = 'DISPUTE_REASON_INCOMPLETE_CONTENT'


class DisputeRequest(WireModel):
    billingId: str | None = Field(
        '', description='Billing reference from the transaction.'
    )
    description: str | None = Field(
        None, description='Human-readable description of the issue.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    idempotencyKey: constr(min_length=1, max_length=255) = Field(
        ...,
        description="Idempotency key (REQUIRED). The server MUST dedupe on this so a replayed\n filing does not open a duplicate case. The dispute's durable identity is the\n Exchange-assigned dispute_id in DisputeResponse.\n Uniqueness is scoped to the verified RFC 9421 signer: the server dedupes per\n (authenticated caller, key), never globally, so a key chosen by one caller\n cannot collide with another's cached result.",
    )
    reason: DisputeReason = Field(..., description='Reason for the dispute.')
    receivedContentHash: str | None = Field(
        None,
        description='Evidence: content hash of what was actually received.\n Exchange compares against the hash promised in ResourceIdentity.',
    )
    receivedHashMethod: str | None = Field(
        None, description='Hash algorithm the agent used'
    )
    reportId: str | None = Field(
        '',
        description='Must reference a filed UsageReport. The agent MUST file a UsageReport\n (via ReportUsage RPC) and receive a report_id BEFORE filing a dispute.\n This prevents fire-and-forget disputes and ensures the Exchange has\n the complete evidence chain: what was offered, what was transacted,\n what the agent reported using, and what the agent disputes.\n The dispute chain: Transaction → UsageReport → Dispute.',
    )
    transactionId: str | None = Field('', description='Transaction being disputed.')
    ver: str | None = Field('', description='Protocol version')


class DisputeStatus(Enum):
    DISPUTE_STATUS_FILED = 'DISPUTE_STATUS_FILED'
    DISPUTE_STATUS_AUTO_RESOLVED = 'DISPUTE_STATUS_AUTO_RESOLVED'
    DISPUTE_STATUS_EVIDENCE_NEEDED = 'DISPUTE_STATUS_EVIDENCE_NEEDED'
    DISPUTE_STATUS_UNDER_REVIEW = 'DISPUTE_STATUS_UNDER_REVIEW'
    DISPUTE_STATUS_ESCALATED = 'DISPUTE_STATUS_ESCALATED'
    DISPUTE_STATUS_RESOLVED = 'DISPUTE_STATUS_RESOLVED'
    DISPUTE_STATUS_APPEALED = 'DISPUTE_STATUS_APPEALED'
    DISPUTE_STATUS_SETTLED = 'DISPUTE_STATUS_SETTLED'
    DISPUTE_STATUS_FINAL = 'DISPUTE_STATUS_FINAL'


class DomainVerificationChallenge(WireModel):
    expiresAt: AwareDatetime | None = Field(
        None,
        description='When this challenge expires. Provider must confirm before this time.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    token: str | None = Field(
        '',
        description='Opaque challenge token. Provider must serve this at:\n https://{domain}/.well-known/ramp-verify/{token}',
    )
    ver: str | None = Field('', description='Protocol version')
    verificationUrl: str | None = Field(
        '', description='The exact URL the Exchange will fetch to verify.'
    )


class DomainVerificationConfirmation(WireModel):
    cdnType: str | None = Field(None, description='CDN type this key is for.')
    domain: str | None = Field('', description='The domain being verified.')
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    signingKey: str | None = Field(
        None,
        description='Optional: signing key to register upon successful verification.\n If present, the key is registered atomically with verification.\n Key format depends on CDN type (PEM for CloudFront, hex for HMAC).',
    )
    token: str | None = Field(
        '', description='The challenge token (echoed from DomainVerificationChallenge).'
    )
    ver: str | None = Field('', description='Protocol version')


class DomainVerificationFailureReason(Enum):
    DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND = (
        'DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND'
    )
    DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_MISMATCH = (
        'DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_MISMATCH'
    )
    DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_EXPIRED = (
        'DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_EXPIRED'
    )
    DOMAIN_VERIFICATION_FAILURE_REASON_FETCH_FAILED = (
        'DOMAIN_VERIFICATION_FAILURE_REASON_FETCH_FAILED'
    )
    DOMAIN_VERIFICATION_FAILURE_REASON_EXCHANGE_NOT_AUTHORIZED = (
        'DOMAIN_VERIFICATION_FAILURE_REASON_EXCHANGE_NOT_AUTHORIZED'
    )
    DOMAIN_VERIFICATION_FAILURE_REASON_KEY_REGISTRATION_FAILED = (
        'DOMAIN_VERIFICATION_FAILURE_REASON_KEY_REGISTRATION_FAILED'
    )


class DomainVerificationRequest(WireModel):
    callerId: str | None = Field(
        None, description='Caller identity (registered with the Exchange).'
    )
    domain: str | None = Field(
        '', description='The provider domain to verify (e.g., "techcrunch.com").'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    ver: str | None = Field('', description='Protocol version')


class DomainVerificationResult(WireModel):
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    keyId: str | None = Field(
        None,
        description='If signing_key was provided: confirmation of key registration.',
    )
    validUntil: AwareDatetime | None = Field(
        None,
        description='Verification is valid until this time. Provider must re-verify periodically.',
    )
    ver: str | None = Field('', description='Protocol version')


class IngestionSource(Enum):
    INGESTION_SOURCE_RAMP_SITEMAP = 'INGESTION_SOURCE_RAMP_SITEMAP'
    INGESTION_SOURCE_RSL = 'INGESTION_SOURCE_RSL'
    INGESTION_SOURCE_SITEMAP = 'INGESTION_SOURCE_SITEMAP'
    INGESTION_SOURCE_HTML_CRAWL = 'INGESTION_SOURCE_HTML_CRAWL'
    INGESTION_SOURCE_CMS_API = 'INGESTION_SOURCE_CMS_API'
    INGESTION_SOURCE_MANUAL = 'INGESTION_SOURCE_MANUAL'
    INGESTION_SOURCE_CATALOG_API = 'INGESTION_SOURCE_CATALOG_API'


class JsonWebKey(WireModel):
    alg: str | None = Field(
        '', description='Signing algorithm. RAMP v1.0: MUST be "EdDSA".'
    )
    crv: str | None = Field('', description='Curve. RAMP v1.0: MUST be "Ed25519".')
    kty: str | None = Field('', description='Key type. RAMP v1.0: MUST be "OKP".')
    notAfter: str | None = Field(
        '',
        description='RFC3339 timestamp. Key is invalid at and after this instant\n (strict upper bound).',
    )
    notBefore: str | None = Field(
        '', description='RFC3339 timestamp. Key is invalid before this instant.'
    )
    use: str | None = Field(
        '', description='Intended key use. RAMP v1.0: MUST be "sig".'
    )
    x: str | None = Field(
        '', description='base64url-encoded 32-byte Ed25519 public key.'
    )


class KeyRevocationList(WireModel):
    asOf: AwareDatetime | None = Field(
        None,
        description="Server's response time (RFC3339, UTC). Consumers use this to detect\n clock skew.",
    )
    revoked: list[str] | None = Field(
        None,
        description='Complete list of revoked key thumbprints (RFC 7638, base64url-no-pad) at\n `as_of`.',
    )


class License(WireModel):
    id: str | None = Field(
        None,
        description='Stable short identifier: SPDX short-id ("GPL-3.0-only"), TollBit cuid,\n or catalog doc-id. Used by agents and the vocab linter for known-license\n lookup; SHARE_ALIKE derivatives default their scope_license to this.',
    )
    immutable: bool | None = Field(
        None,
        description='Data-labels TDL: the document at uri is versioned and will not change.',
    )
    name: str | None = Field(
        None, description='Human-readable name (licenseType, schema.org node name).'
    )
    uri: str | None = Field(
        None,
        description='"MUST NOT URL-validate" means do not REJECT non-URL schemes — it does NOT\n mean fetch blindly. A consumer that dereferences this URI MUST apply the\n SSRF countermeasures in the security threat model (T-LIC-1): scheme\n allowlist, block loopback/private/metadata addresses (resolve-then-check),\n fetch via an egress proxy, and treat the response as untrusted content.\n Verify the fetched bytes against `uri_digest` before use.',
    )
    uriDigest: (
        constr(
            pattern=r'^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$'
        )
        | None
    ) = Field(
        None,
        description='The method MUST be a collision-resistant hash — sha256, sha384, or sha512.\n Legacy md5/sha1 are rejected on the wire: a forgeable digest would defeat\n the swap-protection this field exists for. The CEL is STRUCTURE ONLY\n (allowlisted prefix + matching hex length); presence (digest-when-uri) is\n enforced at ingest.',
    )


class ObligationKind(Enum):
    OBLIGATION_KIND_ATTRIBUTION = 'OBLIGATION_KIND_ATTRIBUTION'
    OBLIGATION_KIND_CONTRIBUTION = 'OBLIGATION_KIND_CONTRIBUTION'
    OBLIGATION_KIND_SHARE_ALIKE = 'OBLIGATION_KIND_SHARE_ALIKE'
    OBLIGATION_KIND_NETWORK_COPYLEFT = 'OBLIGATION_KIND_NETWORK_COPYLEFT'
    OBLIGATION_KIND_NOTICE = 'OBLIGATION_KIND_NOTICE'
    OBLIGATION_KIND_OTHER = 'OBLIGATION_KIND_OTHER'


class ObligationTrigger(Enum):
    OBLIGATION_TRIGGER_ON_USE = 'OBLIGATION_TRIGGER_ON_USE'
    OBLIGATION_TRIGGER_ON_DISTRIBUTION = 'OBLIGATION_TRIGGER_ON_DISTRIBUTION'
    OBLIGATION_TRIGGER_ON_NETWORK_SERVICE = 'OBLIGATION_TRIGGER_ON_NETWORK_SERVICE'
    OBLIGATION_TRIGGER_ON_DERIVATIVE = 'OBLIGATION_TRIGGER_ON_DERIVATIVE'


class OfferAbsenceReason(Enum):
    OFFER_ABSENCE_REASON_NOT_IN_CATALOG = 'OFFER_ABSENCE_REASON_NOT_IN_CATALOG'
    OFFER_ABSENCE_REASON_CONTENT_BLOCKED = 'OFFER_ABSENCE_REASON_CONTENT_BLOCKED'
    OFFER_ABSENCE_REASON_RESTRICTION_FILTERED = (
        'OFFER_ABSENCE_REASON_RESTRICTION_FILTERED'
    )
    OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE = (
        'OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE'
    )
    OFFER_ABSENCE_REASON_NOT_AUTHORIZED = 'OFFER_ABSENCE_REASON_NOT_AUTHORIZED'
    OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT = 'OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT'
    OFFER_ABSENCE_REASON_UNKNOWN_CRITICAL_EXTENSION = (
        'OFFER_ABSENCE_REASON_UNKNOWN_CRITICAL_EXTENSION'
    )
    OFFER_ABSENCE_REASON_BUDGET_EXCEEDED = 'OFFER_ABSENCE_REASON_BUDGET_EXCEEDED'


class Preview(WireModel):
    duration: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Duration in seconds (for audio and video clips).'
    )
    height: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Height in pixels (images and video)'
    )
    mediaType: str | None = Field(
        '',
        description='MIME type of the preview.\n Examples: "image/jpeg", "image/webp", "audio/mpeg", "video/mp4",\n           "text/plain", "application/json"',
    )
    size: str | None = Field(
        None,
        description='Size category hint. Agents use this to select the right preview\n without fetching all of them.\n Standard values:\n   "thumbnail"  — smallest useful preview (100–150px or 5–10s)\n   "preview"    — mid-size for evaluation (300–500px or 15–30s)\n   "sample"     — larger / more detailed (for data: 1–3 sample records)',
    )
    url: str | None = Field(
        '',
        description="URL to a preview asset (thumbnail, clip, snippet, sample).\n Served by the provider's CDN, not by the Exchange.",
    )
    width: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Dimensions in pixels (for images and video).'
    )


class PricingMetering(Enum):
    PRICING_METERING_ONLINE = 'PRICING_METERING_ONLINE'
    PRICING_METERING_NONE = 'PRICING_METERING_NONE'
    PRICING_METERING_OFFLINE_SELF_REPORTED = 'PRICING_METERING_OFFLINE_SELF_REPORTED'


class PricingModel(Enum):
    PRICING_MODEL_FREE = 'PRICING_MODEL_FREE'
    PRICING_MODEL_PER_UNIT = 'PRICING_MODEL_PER_UNIT'
    PRICING_MODEL_FLAT = 'PRICING_MODEL_FLAT'


class ProviderRelationship(Enum):
    PROVIDER_RELATIONSHIP_DIRECT = 'PROVIDER_RELATIONSHIP_DIRECT'
    PROVIDER_RELATIONSHIP_RESELLER = 'PROVIDER_RELATIONSHIP_RESELLER'


class PushResourcesResponse(WireModel):
    accepted: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Number of entries accepted'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    rejected: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Number of entries rejected'
    )
    ver: str | None = Field('', description='Protocol version')
    warnings: list[str] | None = Field(
        None,
        description='Non-fatal issues encountered during ingestion.\n Examples: unrecognized vocab token in a Restriction (term accepted but flagged),\n           REFERENCE_ONLY term missing License.uri (informational).\n Warnings do not cause rejection — they are surfaced so publishers can fix\n their feeds without a hard failure.',
    )


class QuotaWindow(Enum):
    QUOTA_WINDOW_HOURLY = 'QUOTA_WINDOW_HOURLY'
    QUOTA_WINDOW_DAILY = 'QUOTA_WINDOW_DAILY'
    QUOTA_WINDOW_MONTHLY = 'QUOTA_WINDOW_MONTHLY'
    QUOTA_WINDOW_TOTAL = 'QUOTA_WINDOW_TOTAL'


class RateLimitInfo(WireModel):
    limit: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Maximum requests allowed in the current window.'
    )
    remaining: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Requests remaining in the current window.'
    )
    resetAt: AwareDatetime | None = Field(
        None,
        description='When the current window resets (UTC). After this time, `remaining` resets to `limit`.',
    )
    window: str | None = Field(
        None,
        description='Duration of the rate limit window (e.g. 60s = per-minute limit).',
    )


class RefreshCatalogRequest(WireModel):
    tenantId: str | None = Field('', description='Tenant identifier')
    ver: str | None = Field('', description='Protocol version')


class RefreshCatalogResponse(WireModel):
    started: bool | None = Field(False, description='Whether the refresh was started')
    ver: str | None = Field('', description='Protocol version')


class RegistrationFailureReason(Enum):
    REGISTRATION_FAILURE_REASON_DOMAIN_NOT_VERIFIED = (
        'REGISTRATION_FAILURE_REASON_DOMAIN_NOT_VERIFIED'
    )
    REGISTRATION_FAILURE_REASON_INVALID_KEY = 'REGISTRATION_FAILURE_REASON_INVALID_KEY'
    REGISTRATION_FAILURE_REASON_SIGNATURE_INVALID = (
        'REGISTRATION_FAILURE_REASON_SIGNATURE_INVALID'
    )
    REGISTRATION_FAILURE_REASON_ALREADY_REGISTERED = (
        'REGISTRATION_FAILURE_REASON_ALREADY_REGISTERED'
    )
    REGISTRATION_FAILURE_REASON_QUOTA_EXCEEDED = (
        'REGISTRATION_FAILURE_REASON_QUOTA_EXCEEDED'
    )


class RemoveResourcesRequest(WireModel):
    paths: list[str] | None = Field(None, description='Paths to remove')
    tenantId: str | None = Field('', description='Tenant identifier')
    ver: str | None = Field('', description='Protocol version')


class RemoveResourcesResponse(WireModel):
    removed: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Number of entries removed'
    )
    ver: str | None = Field('', description='Protocol version')


class ReportingObligation(WireModel):
    endpoint: str | None = Field(
        None,
        description='URL to submit the usage report to (if different from Exchange).',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    required: bool | None = Field(
        False, description='Whether post-usage reporting is required.'
    )
    requiredFields: list[str] | None = Field(
        None, description='Field names that must be present in the report.'
    )
    window: str | None = Field(
        None,
        description='Duration within which the report must be submitted (e.g. 24h).',
    )


class RequestConstraints(WireModel):
    budgetPeriod: str | None = Field(
        None,
        description='Budget period (e.g. 720h = 30 days). Resets at period boundary.',
    )
    budgetScope: str | None = Field(
        None,
        description='Budget scope identifier for per-period tracking.\n E.g. "user:u-12345" for per-user budgets, "team:eng" for per-team.\n The Broker tracks cumulative spend per scope across sessions.',
    )
    deliveryPreference: list[DeliveryMethod] | None = Field(
        None, description='Preferred delivery methods, in order of preference.'
    )
    exchanges: list[str] | None = Field(
        None, description='Authorized Exchange domains. Broker queries only these.'
    )
    maxDataAge: str | None = Field(
        None,
        description='Only relevant for DYNAMIC resources. Ignored for STATIC (content is\n immutable) and LIVE (content doesn\'t exist yet).\n\n Examples:\n   7 days   — "credit report updated within the last week"\n   1 hour   — "stock snapshot from the last hour"\n   30 days  — "drug interaction database updated this month"',
    )
    maxHops: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description="Maximum forwarding hops the agent will allow (Agent → Broker → … →\n Exchange), counted as the number of RFC 9421 HTTP Message Signatures on the\n request. Caps chain depth so a request is not relayed through more brokers\n than the agent is willing to trust or pay. A Broker MUST NOT forward a\n request whose signature count would exceed this. Absent = agent imposes no\n cap (the Exchange's max_intermediary_hops still applies).",
    )
    maxPrice: Cost | None = Field(
        None, description='Maximum price the agent is willing to pay.'
    )
    maxUnitCost: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$') | None = Field(
        None,
        description='Maximum effective cost per unit, as an exact decimal string (not a float).',
    )
    periodBudget: Cost | None = Field(
        None,
        description='Per-period budget limit. The Broker tracks spend against this\n for the budget_scope. Transactions that would exceed are denied.',
    )
    preferredExchanges: list[str] | None = Field(
        None,
        description='Exchanges the agent has existing relationships with (subscriptions,\n contracts). The Broker SHOULD prefer these when resource is\n available — subscription resource has zero marginal cost.',
    )
    reportingCapable: bool | None = Field(
        None, description='Whether the agent supports post-usage reporting.'
    )


class RequesterType(Enum):
    REQUESTER_TYPE_AGENT = 'REQUESTER_TYPE_AGENT'
    REQUESTER_TYPE_HUMAN_TOOL = 'REQUESTER_TYPE_HUMAN_TOOL'
    REQUESTER_TYPE_SERVICE = 'REQUESTER_TYPE_SERVICE'
    REQUESTER_TYPE_DELEGATED = 'REQUESTER_TYPE_DELEGATED'
    REQUESTER_TYPE_RESEARCH = 'REQUESTER_TYPE_RESEARCH'


class ResolutionType(Enum):
    RESOLUTION_TYPE_CREDIT = 'RESOLUTION_TYPE_CREDIT'
    RESOLUTION_TYPE_REDELIVERY = 'RESOLUTION_TYPE_REDELIVERY'
    RESOLUTION_TYPE_REJECTED = 'RESOLUTION_TYPE_REJECTED'
    RESOLUTION_TYPE_INVESTIGATION = 'RESOLUTION_TYPE_INVESTIGATION'


class ResourceAttestation(WireModel):
    attestedAt: AwareDatetime | None = Field(
        None,
        description='When this attestation was created. Agents use this to assess freshness\n (e.g., "I accept attestations up to N hours old for breaking news").',
    )
    claims: dict[str, Any] | None = Field(
        None,
        description='Signed claims about the resource (max 4KB). A JSON object containing\n whatever properties the attesting party can determine about the resource.\n Recommended claim names for interoperability:\n   estimated_quantity (integer): estimated consumption quantity (e.g., token count for text)\n   word_count (integer): word count (estimated_quantity ~ word_count * 1.32 for text)\n   language (string): ISO 639-1 language code\n   iab_categories (string[]): IAB Content Taxonomy 3.1 codes\n   content_hash (string): hash of content in "method:hexdigest" format\n   hash_method (string): algorithm used for content_hash\n Vendors MAY add vendor-specific claims (e.g., brand_safety, sentiment).\n The protocol does NOT define "quality score" — it is inherently subjective.\n If a vendor provides a proprietary score, the vendor defines what it means\n via their WellKnownManifest ext["ramp.attestation.claims_schema"].',
    )
    keyid: str | None = Field(
        '',
        description="RFC 7638 JWK Thumbprint (the RFC 9421 keyid) of the verifier's\n attestation-signing key, resolved against the verifier's WBA directory\n (WBAFile.keys). Identifies which Ed25519 key signed this attestation.\n Enables key rotation: new keys are published with overlapping validity,\n new attestations use the new key's thumbprint, old attestations remain\n verifiable while the old key is still published.",
    )
    signature: str | None = Field(
        '',
        description='Ed25519 signature over JCS-canonicalized (RFC 8785) representation of\n {verifier, keyid, attested_at, uri, claims}. JCS (JSON Canonicalization\n Scheme) produces deterministic UTF-8 bytes: lexicographic key sorting,\n ECMAScript number serialization, strict string escaping, no whitespace.\n Each attestation is self-contained — new claim fields do not invalidate\n old attestations because the signature covers the specific claims instance.',
    )
    uri: str | None = Field(
        '',
        description='The resource URI this attestation covers. Must match the URI in the\n Offer or ResourceEntry this attestation is attached to.',
    )
    verifier: str | None = Field(
        '',
        description='Canonical domain of the attesting party (e.g., "nytimes.com" for\n self-attestation, "doubleverify.com" for third-party attestation).\n Used to look up the verifier\'s attestation-signing keys in its WBA\n directory (WBAFile.keys) at\n   https://{verifier}/.well-known/http-message-signatures-directory',
    )


class ResourceMutability(Enum):
    RESOURCE_MUTABILITY_STATIC = 'RESOURCE_MUTABILITY_STATIC'
    RESOURCE_MUTABILITY_DYNAMIC = 'RESOURCE_MUTABILITY_DYNAMIC'
    RESOURCE_MUTABILITY_LIVE = 'RESOURCE_MUTABILITY_LIVE'


class RestrictionKind(Enum):
    RESTRICTION_KIND_FUNCTION = 'RESTRICTION_KIND_FUNCTION'
    RESTRICTION_KIND_GEOGRAPHY = 'RESTRICTION_KIND_GEOGRAPHY'
    RESTRICTION_KIND_USER_TYPE = 'RESTRICTION_KIND_USER_TYPE'
    RESTRICTION_KIND_OTHER = 'RESTRICTION_KIND_OTHER'


class RetrievalAuthFailureReason(Enum):
    RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED = (
        'RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING = (
        'RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING = (
        'RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH = (
        'RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_AGENT_KEY_MISSING = (
        'RETRIEVAL_AUTH_FAILURE_REASON_AGENT_KEY_MISSING'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_MISSING = (
        'RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_MISSING'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH = (
        'RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH = (
        'RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_CREATED_MISSING = (
        'RETRIEVAL_AUTH_FAILURE_REASON_PROOF_CREATED_MISSING'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRY_MISSING = (
        'RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRY_MISSING'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED = (
        'RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED'
    )
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_INVALID = (
        'RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_INVALID'
    )


class Role(Enum):
    ROLE_AGENT = 'ROLE_AGENT'
    ROLE_EXCHANGE = 'ROLE_EXCHANGE'
    ROLE_BROKER = 'ROLE_BROKER'
    ROLE_PUBLISHER = 'ROLE_PUBLISHER'


class SubscriptionQuotaInfo(WireModel):
    quotaLimit: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Total allowed in the current period.'
    )
    quotaRemaining: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Remaining in the current period.'
    )
    quotaUsed: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Used so far in the current period.'
    )
    resetsAt: AwareDatetime | None = Field(
        None, description='When the quota counter resets (UTC).'
    )
    subscriptionId: str | None = Field(
        '', description='Subscription this quota applies to.'
    )
    unit: str | None = Field(
        None,
        description='What is being metered. Distinguishes access count quotas from\n spend quotas from burst limits.\n Standard values: "accesses", "tokens", "spend_cents", "burst"',
    )


class TermSemantics(Enum):
    TERM_SEMANTICS_ENUMERATED = 'TERM_SEMANTICS_ENUMERATED'
    TERM_SEMANTICS_REFERENCE_ONLY = 'TERM_SEMANTICS_REFERENCE_ONLY'


class TransactionDenial(WireModel):
    offerId: str | None = Field(
        None, description='Batch mode: the offer this denial pertains to.'
    )
    reason: DenialReason = Field(
        ..., description='The denial reason (defined-only, non-zero)'
    )
    restrictionMismatches: list[RestrictionKind] | None = Field(
        None,
        description='When reason = RESTRICTION_NOT_SATISFIED, the failed axes (same\n RestrictionKind vocabulary the terms use).',
    )


class TransactionItem(WireModel):
    offerId: str | None = Field('', description='The offer_id from the selected Offer.')
    offerSignature: str | None = Field(
        '',
        description="The selected Offer's `signature` (informally, the exchange signature).",
    )


class TransactionResultItem(WireModel):
    billingId: str | None = Field('', description='Billing reference.')
    cost: Cost | None = Field(None, description='Cost for this item.')
    deliveryMethod: (
        constr(pattern=r'^DELIVERY_METHOD_UNSPECIFIED$')
        | DeliveryMethod
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(0, description='How resource is delivered for this item.')
    denialReason: DenialReason | None = Field(
        None, description='Set if this specific item was denied (others may succeed).'
    )
    expiresAt: AwareDatetime | None = Field(
        None, description='When retrieval_endpoint expires.'
    )
    offerId: str | None = Field('', description='The offer_id this result is for.')
    reportingObligation: ReportingObligation | None = Field(
        None, description='Reporting requirements for this item.'
    )
    resourceTitle: str | None = Field(
        None, description='Resource title echoed from the Offer.'
    )
    restrictionMismatches: list[RestrictionKind] | None = Field(
        None,
        description='When denial_reason = RESTRICTION_NOT_SATISFIED, the restriction axes the\n request failed, in the same RestrictionKind vocabulary the terms use.',
    )
    retrievalEndpoint: str | None = Field(
        None,
        description="Signed retrieval URL for this item. Bound to the requesting agent's identity\n via the parent TransactionResponse.agent_identity_hash (shared across all\n batch items); expires at expires_at. Absent if this item was denied or its\n delivery_method is not signed-URL-based.",
    )
    subscriptionId: str | None = Field(
        None, description='If under subscription, no per-request charge.'
    )
    subscriptionUnitValue: Cost | None = Field(
        None,
        description='Computed per-unit cost for financial attribution on subscription transactions.\n Even when cost.amount=0 (subscription), this field carries the value\n of the access for accounting purposes (e.g., ASC 606 prepaid drawdown).',
    )
    transactionId: str | None = Field(
        '', description='Exchange-assigned transaction identifier.'
    )


class UsageAsset(WireModel):
    packageId: str | None = Field(None, description='Package identifier')
    uri: str | None = Field('', description='Asset URI')


class UsageReportRejectionReason(Enum):
    USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND = (
        'USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND'
    )
    USAGE_REPORT_REJECTION_REASON_DUPLICATE = 'USAGE_REPORT_REJECTION_REASON_DUPLICATE'
    USAGE_REPORT_REJECTION_REASON_WINDOW_EXPIRED = (
        'USAGE_REPORT_REJECTION_REASON_WINDOW_EXPIRED'
    )
    USAGE_REPORT_REJECTION_REASON_MISSING_REQUIRED_FIELDS = (
        'USAGE_REPORT_REJECTION_REASON_MISSING_REQUIRED_FIELDS'
    )
    USAGE_REPORT_REJECTION_REASON_MALFORMED = 'USAGE_REPORT_REJECTION_REASON_MALFORMED'


class UsageReportResponse(WireModel):
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    reportId: str | None = Field(
        '',
        description='Exchange-assigned report identifier. Required for the dispute chain —\n the agent must reference this report_id in DisputeRequest to prove that\n a usage report was filed before disputing. The complete evidence chain:\n   Offer → Transaction (transaction_id, billing_id)\n        → UsageReport → UsageReportResponse (report_id)\n        → DisputeRequest (transaction_id + report_id)',
    )
    ver: str | None = Field('', description='Protocol version')


class WBAFile(WireModel):
    keys: list[JsonWebKey] | None = Field(
        None,
        description='RFC 7517 JWK Set "keys" member. RAMP v1: Ed25519 (OKP) keys, each with\n not_before/not_after RAMP extension members.',
    )
    revocationUrl: str | None = Field(
        None,
        description='Directory-level emergency revocation channel. One per directory; the list\n it points to enumerates revoked key thumbprints. Consumers poll on a 300s\n cadence (±10% jitter) and replace their local revoked set with the response.',
    )


class AcceptableRestriction(WireModel):
    axis: (
        constr(pattern=r'^RESTRICTION_KIND_UNSPECIFIED$')
        | RestrictionKind
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(
        0,
        description='Which axis (same enum as Restriction.kind): FUNCTION / GEOGRAPHY /\n USER_TYPE / OTHER.',
    )
    values: (
        list[constr(pattern=r'^[A-Za-z0-9._:*-]+$', min_length=1, max_length=64)] | None
    ) = Field(
        None,
        description='The values the query operates within on this axis — same token vocabulary\n as the terms (e.g. FUNCTION ["ai-train"], GEOGRAPHY ["US", "EU"]).',
        max_length=64,
    )


class AttributionDetail(WireModel):
    displayedUrl: str | None = Field(
        None, description='URL displayed to the user as the attribution link.'
    )
    format: CitationFormat | None = Field(
        None, description='How the citation was presented.'
    )
    visibleToUser: bool | None = Field(
        None, description='Whether the attribution was visible to the end user.'
    )


class AuthorizedExchange(WireModel):
    domain: str | None = Field('', description='Canonical domain of the Exchange.')
    endpoint: str | None = Field('', description='RAMP ExchangeService endpoint URL.')
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    relationship: ProviderRelationship = Field(
        ..., description='Relationship type (mirrors ads.txt DIRECT/RESELLER).'
    )


class CatalogRejection(WireModel):
    reason: CatalogRejectionReason = Field(
        ..., description='The rejection reason (defined-only, non-zero)'
    )
    rejectedPaths: list[str] | None = Field(
        None,
        description='For partial-batch failures: the entry paths that were rejected.',
    )


class DisputeFailure(WireModel):
    reason: DisputeFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class DisputeResponse(WireModel):
    disputeId: str | None = Field(
        None, description='Exchange-assigned dispute case identifier.'
    )
    estimatedResolution: str | None = Field(
        None, description='Expected resolution timeline.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    resolution: ResolutionType | None = Field(
        None,
        description='Resolution outcome, populated when the dispute reaches a terminal\n state (RESOLVED, SETTLED, or FINAL). Absent while dispute is in\n progress (FILED, UNDER_REVIEW, ESCALATED, etc.).',
    )
    status: (
        constr(pattern=r'^DISPUTE_STATUS_UNSPECIFIED$')
        | DisputeStatus
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(
        0,
        description='Current lifecycle status of the dispute. Tracks progression through\n the three-tier resolution process:\n   Tier 1 (automated, <1s): FILED → AUTO_RESOLVED or EVIDENCE_NEEDED\n   Tier 2 (rule-based, <24h): UNDER_REVIEW → RESOLVED\n   Tier 3 (pattern investigation, async): ESCALATED → SETTLED → FINAL\n Losing party may appeal: RESOLVED → APPEALED → back to UNDER_REVIEW.',
    )
    ver: str | None = Field('', description='Protocol version')


class DomainVerificationFailure(WireModel):
    reason: DomainVerificationFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class Obligation(WireModel):
    detail: str | None = Field(
        None,
        description='Free-form detail: attribution string, notice file URI, etc.\n OBLIGATION_KIND_OTHER without it → lint warning.',
    )
    kind: ObligationKind = Field(..., description='What the agent must do.')
    scopeLicense: License | None = Field(
        None,
        description="The license that derivatives must be released under. REQUIRED for\n SHARE_ALIKE (rejected if absent), where it MUST identify a license — set\n `id` (SPDX short-id, the common copyleft case, often the term's own\n License.id) and/or `uri`. Because it is a License, a referenced `uri`\n inherits the uri_digest swap-protection rule: a uri without a digest is\n rejected, exactly as for any other license reference.",
    )
    trigger: ObligationTrigger = Field(
        ..., description='When the obligation activates.'
    )


class Pricing(WireModel):
    currency: str | None = Field(
        '', description='ISO 4217 currency code (e.g. "USD", "EUR").'
    )
    estimatedQuantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Estimated quantity in the metering unit.\n For text: token count. For video: duration in seconds.\n For documents: page count. For data: record count.',
    )
    licenseDurationMonths: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='License duration in months. How long the granted access remains valid.',
    )
    metering: PricingMetering | None = Field(
        None,
        description='How usage is tracked for billing reconciliation.\n Absent = PRICING_METERING_ONLINE (default real-time tracking).\n NONE = one-time perpetual sale; no ReportUsage required after ExecuteTransaction.\n OFFLINE_SELF_REPORTED = agent self-reports physical-world consumption.',
    )
    model: PricingModel = Field(..., description="Provider's pricing model.")
    rate: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$') | None = Field(
        '',
        description='Price in the provider\'s model, as an exact decimal string — e.g. "0.05" =\n $0.05 per article. NOT a float: money is decimal to avoid binary rounding and\n to allow arbitrary sub-cent precision (e.g. "0.0001234"). Denominated in `currency`.',
    )
    unit: (
        constr(
            pattern=r'^([a-z0-9-]+|[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)?$', max_length=64
        )
        | None
    ) = Field(
        None,
        description='The (ramp.v1.vocab) entries below are the SOLE authored source of the\n registered bare tokens. A buf plugin reads them structurally and emits the\n pricingunits constants + IsRegistered; ingest enforces membership from\n those. The CEL is STRUCTURE ONLY (empty / bare-form / vendor:namespaced) —\n it never lists the tokens, so it cannot drift from the registry.',
    )
    unitCost: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$') | None = Field(
        None,
        description="Normalized cost per unit — the universal comparison metric, exact decimal string.\n For text: cost per token. For video: cost per second.\n For data: cost per record. For APIs: cost per call.\n Denominated in the Exchange's base_currency (from its WellKnownManifest).",
    )


class Quota(WireModel):
    limit: conint(ge=1) = Field(
        ...,
        description='Maximum allowed value in the given window. A quota of 0 grants\n nothing — express "no access" by omitting the term, not a zero quota.',
    )
    metric: constr(
        pattern=r'^([a-z0-9-]+|[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)$', max_length=64
    ) = Field(
        ...,
        description='The (ramp.v1.vocab) entries below are the SOLE authored source of the\n registered bare metric tokens. A buf plugin reads them structurally and\n emits the quotametrics constants + IsRegistered; ingest enforces membership\n from those. The CEL is STRUCTURE ONLY (non-empty bare token or\n vendor:namespaced) — it never lists the tokens, so it cannot drift.\n\n Token meanings:\n   display-words      Words of content text rendered to an end user.\n   impressions        Times the content is displayed to an end user.\n   tokens             LLM output tokens generated using this content.\n   input-tokens       LLM input tokens consumed from this content.\n   units-manufactured Physical units manufactured from this design/pattern.\n   accesses           Distinct content access / retrieval events.\n   copies             Digital or physical copies produced.\n   seats              Distinct named users licensed to access the content.',
    )
    window: QuotaWindow = Field(
        ..., description='Time window over which the limit accumulates.'
    )


class RegistrationFailure(WireModel):
    reason: RegistrationFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class Requester(WireModel):
    billingRef: str | None = Field(
        None,
        description="Opaque billing reference linking this requester to the Exchange's (and,\n through the Exchange, the publisher's) billing/accounting systems — e.g. a\n billing account, PO number, or cost center. NOT an entitlement or\n subscription credential: access is governed by scopes and delegation, and\n identity by the request signature. The Exchange uses it only for invoicing\n and cost attribution.",
    )
    delegation: Delegation | None = Field(
        None,
        description='Optional delegation — present when the requester acts on behalf of\n another entity (user, organization, upstream agent).',
    )
    domain: str | None = Field(
        '',
        description='Domain the requester belongs to — used for public key lookup.\n Keys published at {domain}/.well-known/ramp.json (WellKnownManifest, role=ROLE_AGENT).',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    id: str | None = Field(
        '', description='Unique requester identifier (e.g., "agent-research-bot-001").'
    )
    name: str | None = Field(
        None, description='Human-readable name (e.g., "Acme Research Assistant").'
    )
    scopes: list[str] | None = Field(
        None,
        description='The Exchange filters its catalog to resources matching these scopes.\n Resources outside the scopes are not returned — the requester never\n learns they exist. This is the enforcement mechanism for both enterprise\n RBAC and open-market subscription entitlements.\n\n Scope format: colon-separated segments, "{domain}:{permission}" or\n "{profile}:{permission}", optionally multi-segment ("dist:US:CA");\n matching is segment-wise per the rule below (no implicit hierarchy).\n Examples:\n   "credit:read"                — can access credit reports\n   "subscription:marketdata-2026" — has active MarketData subscription\n   "academic:*"                 — full access to academic resources\n   "internal:reports"           — can access internal reports\n   "*"                         — unrestricted (public Exchange default)\n\n Matching is SEGMENT-WISE (":" separated). A granted scope G covers a\n required scope R iff, segment by segment, each G segment equals the\n corresponding R segment or is "*"; a terminal "*" matches all remaining\n segments. There is NO implicit prefix match, and a grant NARROWER than\n the requirement does not cover it (G must be equal-to-or-broader than R).\n Examples: "dist:*" covers "dist:US" and "dist:US:CA"; "dist:US:*" covers\n "dist:US:CA" but not "dist:EU"; bare "dist" covers only "dist"; granted\n "dist:US:CA" does NOT cover required "dist:US"; "*" covers everything.\n This same rule governs LicenseTerm.scopes — one algorithm protocol-wide.\n\n When empty, Exchange applies its default access policy (typically\n returns all publicly available resources).',
        max_length=64,
    )
    type: RequesterType = Field(
        ..., description='What kind of entity is making this request.'
    )


class ResourceIdentity(WireModel):
    c2paManifest: str | None = Field(
        None,
        description='Formats:\n   Sidecar: HTTPS URI to a .c2pa manifest file\n   Embedded: same URI as canonical_url (manifest is inside the asset)\n   Content Credentials Cloud: https://contentcredentials.org/verify?uri=...',
    )
    c2paStatus: C2PAStatus | None = Field(
        None,
        description='The full C2PA validation details (signer identity, trust list,\n action history, training/mining status) are carried in a\n ResourceAttestation with c2pa.* claims — see ramp-c2pa-v1 profile.',
    )
    canonicalUrl: str | None = Field(
        None,
        description='Provider\'s authoritative URL for this resource (rel="canonical").\n Always available. Different per provider for syndicated content.',
    )
    contentHash: str | None = Field(
        None,
        description='Level 1 (SimHash): computed by Exchange from extracted text.\n   Agent verifies that fetched content is "substantially similar."\n   Tolerates dynamic page elements.\n\n Level 2 (SHA-256): computed by provider from deterministic payload.\n   Agent verifies exact match. Requires provider to serve consistent\n   content (e.g., API endpoint, static HTML, structured JSON).\n   Mismatch = dispute. Commands premium pricing.',
    )
    doi: str | None = Field(
        None, description='Digital Object Identifier — persistent, never changes.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    hashMethod: str | None = Field(
        None,
        description='Hash algorithm and verification level.\n Examples: "simhash-v1", "minhash-v1", "sha256", "sha384"',
    )
    iptcGuid: str | None = Field(
        None,
        description='IPTC NewsML-G2 globally unique identifier.\n Present when resource flows through news wire syndication (AP, Reuters).',
    )
    isni: str | None = Field(
        None, description='International Standard Name Identifier for the creator.'
    )
    resourceMutability: ResourceMutability = Field(
        ...,
        description='Drives hash verification behavior:\n   STATIC:  content_hash is stable. Agent SHOULD verify delivered content matches.\n   DYNAMIC: content changes between offer and fetch (credit reports, drug databases).\n            content_hash reflects state at offer generation time. Hash mismatch is\n            expected and MUST NOT trigger automatic dispute.\n   LIVE:    content does not exist at offer time (streaming feeds, live broadcasts).\n            content_hash is not applicable. The "resource" is the stream endpoint.\n\n Validated across 18 use cases: static content (articles, patents, legislation),\n dynamic data (credit reports, drug interactions, stock snapshots), and live\n streams (MarketData quotes, NPR broadcast, news monitoring feeds).',
    )
    softBinding: str | None = Field(
        None,
        description='Algorithm specified in soft_binding_method. Values are algorithm-specific\n (e.g., perceptual hash hex string, watermark identifier).',
    )
    softBindingMethod: str | None = Field(
        None,
        description='Algorithm used for soft_binding.\n Examples: "phash-v1" (perceptual hash), "c2pa-watermark" (C2PA invisible\n watermark), "chromaprint" (audio fingerprint).',
    )


class ResourceQuery(WireModel):
    acceptableRestrictions: list[AcceptableRestriction] | None = Field(
        None,
        description='The limits this query operates within, per restriction axis (function,\n geography, user-type, …) — see AcceptableRestriction. Advisory selection\n inputs the Exchange/Broker MAY pre-select offers against (convenience, not\n enforcement); the agent self-selects and bears compliance.',
    )
    deadline: str | None = Field(
        None,
        description='Maximum time the caller will wait for a response.\n Exchange SHOULD prioritize speed over completeness when tight.\n Absent = 500ms default.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    requester: Requester | None = Field(
        None,
        description='Requester identity — who is making this request, what scopes they have,\n and optional delegation chain.',
    )
    supportedProfiles: list[str] | None = Field(
        None,
        description='Declares which ext field vocabularies the caller can parse and act on.\n The Exchange SHOULD include profile-specific ext fields in Offers\n when the caller declares support. The Exchange MAY skip expensive\n metadata computation (e.g., retraction checking, consolidation\n verification) when the caller does not declare the relevant profile.\n\n Absence means "send all available metadata" — Exchange MUST NOT\n withhold ext fields solely because the caller omitted this field.\n\n Values match the Exchange\'s WellKnownManifest.supported_profiles entries.\n Examples: ["ramp-news-v1", "ramp-academic-v1", "ramp-legal-v1"]',
    )
    uris: list[str] | None = Field(
        None, description='Resource URIs being queried.', max_length=256
    )
    ver: str | None = Field('', description='RAMP protocol version.')


class Restriction(WireModel):
    advisory: bool | None = Field(
        False,
        description='Fail-closed by default. When false (the default), this restriction is\n BINDING: an agent that cannot evaluate every token in it — including an\n unknown vendor token — MUST decline the term. Set advisory = true to\n downgrade an unverifiable restriction to non-blocking. This deliberately\n inverts the COSE-`crit` opt-in default: a license restriction a consumer\n does not understand should stop it, not be silently ignored.',
    )
    kind: RestrictionKind = Field(
        ..., description='Which dimension this restriction applies to.'
    )
    permitted: (
        list[constr(pattern=r'^[A-Za-z0-9._:*-]+$', min_length=1, max_length=64)] | None
    ) = Field(
        None,
        description='Tokens allowed on this axis. Empty = all permitted.\n For FUNCTION: "ai-input", "ai-train", "search", "editorial", "commercial", …\n For GEOGRAPHY: "US", "DE", "EU", "EEA", "*", …\n For USER_TYPE: "individual", "academic", "commercial_entity", …',
        max_length=64,
    )
    prohibited: (
        list[constr(pattern=r'^[A-Za-z0-9._:*-]+$', min_length=1, max_length=64)] | None
    ) = Field(
        None,
        description='Tokens blocked on this axis. Takes precedence over permitted[].',
        max_length=64,
    )


class RetrievalAuthFailure(WireModel):
    reason: RetrievalAuthFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class TransactionRequest(WireModel):
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    idempotencyKey: constr(min_length=1, max_length=255) = Field(
        ...,
        description="Idempotency key (REQUIRED). The server MUST dedupe on this: a replay returns\n the original result rather than re-executing. The transaction's durable\n identity is the Exchange-assigned transaction_id in the response.\n Uniqueness is scoped to the verified RFC 9421 signer: the server dedupes per\n (authenticated caller, key), never globally, so a key chosen by one caller\n cannot collide with another's cached result.",
    )
    items: list[TransactionItem] | None = Field(
        None,
        description='Batch mode: commit to multiple offers in one request.\n When populated, `offer_id` and `offer_signature` SHOULD be empty.',
    )
    offerId: str | None = Field(
        None,
        description='Single-offer mode. Use `items` for batch mode; `offer_id` +\n `offer_signature` for single.',
    )
    offerSignature: str | None = Field(None, description='Single-offer signature.')
    requester: Requester | None = Field(
        None, description='Requester identity — forwarded for authorization and audit.'
    )
    ver: str | None = Field('', description='Protocol version')


class TransactionResponse(WireModel):
    agentIdentityHash: str | None = Field(
        '',
        description='Identity that retrieval_endpoint is bound to: the RFC 7638 JWK Thumbprint of\n the agent\'s Ed25519 request-signing key (see "Retrieval-URL identity binding"\n above). Empty string when absent; non-empty iff a signed retrieval_endpoint\n is present. Delivery-endpoint enforcement of the binding is OPTIONAL.',
    )
    billingId: str | None = Field(None, description='Billing reference')
    cost: Cost | None = Field(None, description='Transaction cost')
    deliveryMethod: (
        constr(pattern=r'^DELIVERY_METHOD_UNSPECIFIED$')
        | DeliveryMethod
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(0, description='How resource is delivered in this transaction.')
    expiresAt: AwareDatetime | None = Field(
        None, description='When retrieval_endpoint expires.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    items: list[TransactionResultItem] | None = Field(
        None, description='Batch mode: per-offer results.'
    )
    reportingObligation: ReportingObligation | None = Field(
        None, description='Reporting requirements attached to this delivery.'
    )
    resourceTitle: str | None = Field(
        None, description='Resource title echoed from the Offer (for logging/display).'
    )
    retrievalEndpoint: str | None = Field(
        None,
        description='Signed retrieval URL the agent uses to fetch the purchased resource.\n Bound to agent_identity_hash; expires at expires_at. Absent on denial\n and on transactions whose delivery_method is not signed-URL-based.',
    )
    subscriptionId: str | None = Field(
        None,
        description='If set, this transaction was fulfilled under a subscription/deal.\n No per-request charge — usage tracked against subscription quota.',
    )
    subscriptionQuota: list[SubscriptionQuotaInfo] | None = Field(
        None,
        description='Post-transaction quota state. Tells the agent how much quota remains\n after this transaction. Enables proactive throttling ("1 access left").\n Multiple entries for multi-dimensional quotas.',
    )
    subscriptionUnitValue: Cost | None = Field(
        None,
        description='Computed per-unit cost for financial attribution on subscription transactions.\n Even when cost.amount=0 (subscription), this field carries the value\n of the access for accounting purposes (e.g., ASC 606 prepaid drawdown).',
    )
    totalCost: Cost | None = Field(
        None, description='Batch mode: aggregate cost across all items.'
    )
    transactionId: str | None = Field(
        None,
        description='Single-offer result.\n For batch mode, these may be empty — check `items` instead.',
    )
    ver: str | None = Field('', description='Protocol version')


class Usage(WireModel):
    attribution: list[AttributionDetail] | None = Field(
        None, description='Structured attribution details for each citation provided.'
    )
    citationIncluded: bool | None = Field(
        None,
        description='Whether citation was included as required by the offer terms.',
    )
    consumedQuantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description="REQUIRED. Actual quantity consumed, in the metering unit from the Offer's Pricing.\n For text: tokens consumed. For video: seconds watched. For data: records accessed.\n Exchange cross-references against Offer.pricing.estimated_quantity.",
    )
    consumedUnit: (
        constr(
            pattern=r'^([a-z0-9-]+|[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)?$', max_length=64
        )
        | None
    ) = Field(
        None,
        description='Metering unit for consumed_quantity. Must match the Offer\'s Pricing.unit.\n If omitted, defaults to "tokens". Same token format as Pricing.unit:\n a bare registered token or a vendor:namespaced token.',
    )
    displayedToUser: bool | None = Field(
        None, description='Whether resource/output was displayed to a human.'
    )
    function: list[str] | None = Field(
        None,
        description='How the resource was used. Standard values: "ai-train", "ai-input",\n "ai-index", "search", "display". Multiple allowed.\n CoMP-specific values available via ramp-comp-v1 extension profile.',
    )
    subfn: list[str] | None = Field(
        None,
        description='Sub-function detail. Standard values: "training", "rag", "grounding",\n "agent_view", "agent_actions".',
    )


class UsageReport(WireModel):
    assets: list[UsageAsset] | None = Field(
        None, description='Assets that were delivered and used.'
    )
    billingId: str | None = Field(
        '', description='Billing reference from the delivery.'
    )
    exchange: str | None = Field(None, description='Exchange this report is for.')
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    idempotencyKey: constr(min_length=1, max_length=255) = Field(
        ...,
        description="Idempotency key (REQUIRED). The server MUST dedupe on this so a replayed\n report does not double-count usage. The report's durable identity is the\n Exchange-assigned report_id in UsageReportResponse.\n Uniqueness is scoped to the verified RFC 9421 signer: the server dedupes per\n (authenticated caller, key), never globally, so a key chosen by one caller\n cannot collide with another's cached result.",
    )
    timestamp: AwareDatetime | None = Field(
        None, description='When the resource was used (ISO 8601).'
    )
    transactionId: str | None = Field(
        '', description='Transaction ID from the delivery.'
    )
    usage: Usage | None = Field(None, description='How the resource was actually used.')
    ver: str | None = Field('', description='Protocol version')


class UsageReportRejection(WireModel):
    reason: UsageReportRejectionReason = Field(
        ..., description='The rejection reason (defined-only, non-zero)'
    )


class WellKnownManifest(WireModel):
    acceptedVerifiers: list[str] | None = Field(
        None,
        description='Exchange-only. Trusted attestation verification vendors (domains).',
    )
    baseCurrency: str | None = Field(
        None,
        description='Exchange-only. Base currency for pricing (ISO 4217). All unit_cost\n values from this Exchange are denominated in this currency.',
    )
    catalogContributors: list[CatalogContributor] | None = Field(
        None,
        description='Publisher-only. Authorized third-party catalog contributors.\n MUST be empty for non-publisher roles.',
    )
    catalogEndpoint: str | None = Field(
        None, description='Exchange-only. CatalogService endpoint URL (if exposed).'
    )
    contact: str | None = Field(
        None, description='Contact email (licensing, integration, security).'
    )
    deliveryMethodsSupported: list[DeliveryMethod] | None = Field(
        None, description='Exchange-only. Supported delivery methods.'
    )
    domain: str | None = Field(
        '', description='Canonical domain serving this manifest.'
    )
    endpoint: str | None = Field(
        None, description='Exchange-only. ExchangeService endpoint URL.'
    )
    exchanges: list[AuthorizedExchange] | None = Field(
        None,
        description="Publisher-only. Authorized exchanges for this publisher's resources.\n Like ads.txt — declares who may sell. MUST be empty for non-publisher\n roles.",
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052). Lists keys\n within ext that the consumer MUST understand. Unknown values reject\n with UNKNOWN_CRITICAL_EXTENSION. Empty (default) → ignore-unknown.',
    )
    gnapGrantEndpoint: str | None = Field(
        None, description='Exchange-only. GNAP grant endpoint when GNAP is supported.'
    )
    hashMethodsSupported: list[str] | None = Field(
        None,
        description='Exchange-only. Accepted resource hash methods for attestation\n verification.',
    )
    healthEndpoint: str | None = Field(
        None, description='Exchange-only. Health check endpoint URL.'
    )
    maxIntermediaryHops: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Exchange-only. Maximum forwarding hops this Exchange tolerates on an inbound\n request (Agent → Broker → … → Exchange), counted as RFC 9421 HTTP Message\n Signatures. A request carrying more SHOULD be rejected. Lets Exchanges\n publish their chain-depth tolerance so Brokers prune before forwarding.\n Absent = no published limit (Exchange applies its own default policy).',
    )
    name: str | None = Field(
        None, description='Exchange-only. Human-readable Exchange name.'
    )
    oidcIssuer: str | None = Field(
        None,
        description='Exchange-only. OIDC Discovery URL when OAuth methods are supported.',
    )
    operator: str | None = Field(
        None, description='Exchange-only. Organization operating this Exchange.'
    )
    operatorDomain: str | None = Field(
        None,
        description="Exchange-only. Operator's corporate domain (may differ from domain).",
    )
    pricingModelsSupported: list[PricingModel] | None = Field(
        None, description='Exchange-only. Supported pricing models.'
    )
    privacyUri: str | None = Field(
        None, description='Exchange-only. Privacy policy URL.'
    )
    protocolVersionsSupported: list[str] | None = Field(
        None,
        description='Exchange-only. Supported RAMP protocol versions (e.g. ["1.0"]).',
    )
    role: Role = Field(..., description='Role this manifest describes.')
    supportedAuthMethods: list[AuthMethod] | None = Field(
        None,
        description='Exchange-only. Authorization methods this Exchange supports\n (ordered by preference).',
    )
    supportedProfiles: list[str] | None = Field(
        None,
        description='Exchange-only. Domain extension profiles this Exchange conforms to.\n See standards-layering docs.',
    )
    termsUri: str | None = Field(
        None, description='Exchange-only. Terms of service URL.'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version. MUST equal "1.0"; consumers REJECT\n unrecognised major versions.',
    )


class DiscoveryRequest(WireModel):
    acceptableRestrictions: list[AcceptableRestriction] | None = Field(
        None,
        description='The limits the agent will operate within, per restriction axis — see\n AcceptableRestriction. The Broker forwards these to Exchanges in\n ResourceQuery.acceptable_restrictions. Advisory selection inputs, not\n enforcement.',
    )
    constraints: RequestConstraints | None = Field(
        None, description='Constraints for exchange filtering and offer selection.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    query: str | None = Field(
        None,
        description="Search query for Broker-side resource discovery.\n Used when the agent doesn't know specific URIs but wants the Broker\n to find matching resources across Exchanges.\n When present, the Broker interprets the query and discovers resources\n across Exchanges on the agent's behalf. Results returned as Offers\n in DiscoveryResponse, same as for specific URI requests.\n Can be used alongside uris (specific URIs + search in one request).",
    )
    requester: Requester | None = Field(
        None,
        description='Requester identity — who is making this request, what scopes they have.\n The Broker forwards this to Exchanges in ResourceQuery.requester.',
    )
    searchFilters: dict[str, Any] | None = Field(
        None,
        description='Structured search filters (optional, alongside or instead of query).\n Keys are profile-specific: "academic.topic", "news.category",\n "legal.jurisdiction", etc. The Broker maps these to Exchange-specific\n query parameters.',
    )
    supportedProfiles: list[str] | None = Field(
        None,
        description='The Broker uses this to:\n   1. Route queries to Exchanges that support these profiles\n   2. Forward the profiles in ResourceQuery.supported_profiles\n   3. Include profile-specific ext fields when returning results\n\n Examples: ["ramp-academic-v1"] — agent working on literature review',
    )
    uris: list[str] | None = Field(
        None,
        description='Resource URIs the agent wants. The Broker forwards these to Exchanges in\n ResourceQuery.uris. Optional when `query` / `search_filters` drive\n Broker-side discovery instead.',
        max_length=256,
    )
    ver: str | None = Field('', description='RAMP protocol version')


class ErrorDetail(WireModel):
    catalogRejection: CatalogRejection | None = Field(
        None, description='`reason` oneof — CatalogService rejection'
    )
    disputeFailure: DisputeFailure | None = Field(
        None, description='`reason` oneof — DisputeTransaction filing refused'
    )
    domain: str | None = Field(
        '',
        description='Stable grouping for the failing surface, e.g. "ramp.v1.ExchangeService".\n Mirrors google.rpc.ErrorInfo.domain so generic tooling can group errors.',
    )
    domainVerificationFailure: DomainVerificationFailure | None = Field(
        None, description='`reason` oneof — domain verification failed'
    )
    message: str | None = Field(
        '',
        description='Developer-facing, NON-authoritative human message. Clients MUST branch on\n the typed reason below, never on this text. Servers SHOULD NOT place secrets,\n PII, or existence/authorization detail here that the closed typed reason\n deliberately withholds: unlike the enum, this free text is unbounded and\n easily becomes an existence oracle or leak channel (see `metadata`).',
    )
    metadata: dict[str, str] | None = Field(
        None,
        description='Dynamic key/value context that also appears in `message` (ids, limits,\n axes). Mirrors google.rpc.ErrorInfo.metadata. Strongly-typed context rides\n in the per-domain reason block below instead. Same leakage rule as `message`:\n servers SHOULD NOT put secrets, PII, or withheld existence/authorization\n detail here — it is the same potential side channel as the absence oracle.',
    )
    registrationFailure: RegistrationFailure | None = Field(
        None, description='`reason` oneof — agent/provider registration refused'
    )
    retrievalAuthFailure: RetrievalAuthFailure | None = Field(
        None,
        description='`reason` oneof — signed-URL / proof-of-possession check failed',
    )
    transactionDenial: TransactionDenial | None = Field(
        None, description='`reason` oneof — ExecuteTransaction denial'
    )
    usageReportRejection: UsageReportRejection | None = Field(
        None, description='`reason` oneof — ReportUsage filing rejected'
    )


class LicenseTerm(WireModel):
    license: License | None = Field(
        None,
        description='Governing license document. Authoritative for REFERENCE_ONLY terms, which\n MUST carry a License with a non-empty uri — a REFERENCE_ONLY term that\n references nothing is rejected at ingest.',
    )
    obligations: list[Obligation] | None = Field(
        None, description='Post-use behavioral requirements.'
    )
    partLabel: str | None = Field(
        None,
        description='Informational human-readable name for this sub-part (sub-part terms).',
    )
    pricing: Pricing = Field(
        ...,
        description='Pricing for this term. REQUIRED for every term regardless of semantics —\n an agent cannot act on a priceless term, so absent Pricing is a validation\n error at ingest. model = FREE must be stated explicitly (absent Pricing is\n not free). A REFERENCE_ONLY term states its price here too; its License\n governs the human-readable terms but does not replace the machine-readable\n price.',
    )
    quotas: list[Quota] | None = Field(
        None, description='Usage caps. The agent must not exceed any individual Quota.'
    )
    restrictions: list[Restriction] | None = Field(
        None,
        description='Usage restrictions (function, geography, user-type).\n Multiple restrictions are AND-combined — the agent must satisfy all of them.',
    )
    scopes: list[str] | None = Field(
        None,
        description='Coverage uses the SAME matching rule as Requester/delegation scopes:\n segment-wise (":" separated), each granted segment must equal the\n corresponding required segment or be "*", a terminal "*" matches all\n remaining segments, and there is NO implicit prefix match (a grant\n narrower than the requirement does not cover it). "dist:*" covers\n "dist:US" and "dist:US:CA"; "dist" covers only "dist". There is exactly\n one scope-matching algorithm across the protocol.',
        max_length=64,
    )
    semantics: TermSemantics = Field(
        ..., description='How to interpret the machine fields.'
    )


class Offer(WireModel):
    attestations: list[ResourceAttestation] | None = Field(
        None,
        description='Three verification levels determine what is independently verifiable:\n   Level 0 (no attestations): Resource may carry identifiers (DOI, IPTC GUID)\n     for identification, but nothing is cryptographically verifiable.\n     Only CDN delivery failure is auto-disputable.\n   Level 1 (self-attested): Provider signs own claims with Ed25519 key.\n     Agent can independently verify content hash and token count.\n     CDN delivery failure + content hash mismatch are auto-disputable.\n   Level 2 (third-party attested): Independent verification vendor crawled\n     the resource and attested to its properties. Agent trusts the attestation\n     (does not re-verify hash). Token count discrepancy is auto-disputable\n     when corroborated by CDN response size.\n\n Multiple attestations may be present (e.g., provider self-attestation\n plus a third-party verification). Agents choose which to trust.',
    )
    dataAsOf: AwareDatetime | None = Field(
        None,
        description="Not set for STATIC resources (content doesn't change) or LIVE\n resources (content doesn't exist yet).\n\n The Broker compares this against RequestConstraints.max_data_age\n to filter stale offers. Example: agent requests max_data_age = 7 days,\n Broker drops offers where now() - data_as_of > 7 days.",
    )
    deliveryMethod: (
        constr(pattern=r'^DELIVERY_METHOD_UNSPECIFIED$')
        | DeliveryMethod
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(0, description='How resource will be delivered.')
    exchange: str | None = Field(
        '',
        description='Canonical domain of the Exchange that issued this offer (e.g.\n "exchange.example.com"). This is the execute-routing target: the agent (or\n a relaying Broker) sends the ExecuteTransaction call for this offer to this\n Exchange. Because it is an ordinary Offer field it falls inside the signed\n bytes (see `signature` below — the signature covers every field except\n `signature` / `signature_algorithm`), so an intermediary cannot redirect\n the execute call to a different Exchange without invalidating the offer.',
    )
    expiresAt: AwareDatetime | None = Field(
        None, description='When this offer expires (ISO 8601).'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    iabCategories: list[str] | None = Field(
        None,
        description='IAB Content Taxonomy category codes.\n Enables agents to filter offers by topic (e.g., "only finance resources").\n Uses IAB Content Taxonomy 3.1 codes.',
    )
    identity: ResourceIdentity | None = Field(
        None,
        description='Resource identity for cross-exchange deduplication.\n Enables Brokers to recognize the same resource offered by\n different Exchanges and compare pricing.',
    )
    offerId: str | None = Field(
        '', description='Unique identifier for this offer, assigned by the Exchange.'
    )
    previews: list[Preview] | None = Field(
        None,
        description='Per content type:\n   Image:  watermarked thumbnail (150–450px JPEG)\n   Video:  short clip (10–30s MP4, watermarked)\n   Audio:  short clip (15–30s MP3, low-bitrate or watermarked)\n   Text:   snippet or abstract (first 200 words as text/plain)\n   Data:   sample records (1–3 rows as application/json)\n   Stream: optional frame capture or none (streams are priced by time)\n\n Modeled after Shutterstock (multi-size thumbnail URLs),\n Spotify (preview_url to 30s clip), IIIF (parameterized image URLs),\n and OpenRTB native (img.url + dimensions).',
    )
    pricing: Pricing | None = Field(
        None,
        description='Pricing for this offer. An offer represents a single licensing\n arrangement: each projected LicenseTerm yields its own offer, so this is\n that term\'s pricing (the authoritative copy lives in `terms[].pricing`).\n Used for cross-exchange comparison and Broker ranking. A resource with\n multiple alternative terms (e.g. dual-licensed) produces multiple separate\n offers, one per term — never one offer with a "headline" picked among them.',
    )
    reporting: ReportingObligation | None = Field(
        None, description='Post-usage reporting requirements for this offer.'
    )
    signature: str | None = Field(
        '',
        description="Because the signature covers `terms`, `pricing`, `expires_at`, and\n `exchange`, an intermediary (Broker) cannot tamper with price, restrictions,\n quotas, obligations, the expiry, the execute-routing target, or any\n licensing term without invalidating it.\n Agent SHOULD verify the signature (RFC 2119) against the Exchange's public\n key, and MUST reject an offer whose `expires_at` is in the past.",
    )
    signatureAlgorithm: str | None = Field(
        '',
        description="JWS algorithm. Always 'EdDSA' for Ed25519 via JWS Compact Serialization.",
    )
    subscriptionId: str | None = Field(
        None,
        description='If set, this offer is available under an existing subscription/deal.\n No per-request billing — usage tracked against subscription quota.\n Pricing.rate = 0 for subscription offers (zero marginal cost).\n The Broker SHOULD prefer subscription offers when available.',
    )
    subscriptionQuota: list[SubscriptionQuotaInfo] | None = Field(
        None,
        description='Subscription quota state, when this offer is under a subscription.\n Enables the agent to see remaining quota before committing.\n Multiple entries when the subscription has independent quotas\n (e.g., access count + spend cap).',
    )
    terms: list[LicenseTerm] | None = Field(
        None,
        description="Licensing terms for this offer, sourced from the publisher's ResourceEntry.\n Multiple terms when the resource has different arrangements by use case.\n See: Universal Licensing Core section.",
    )


class OfferGroup(WireModel):
    absenceReason: OfferAbsenceReason | None = Field(
        None,
        description='Why no offers are available for this URI.\n Present when `offers` is empty. Enables agents/Brokers to distinguish\n "resource not in catalog" from "resource blocked for your use case" without\n trial-and-error transactions. Analogous to OpenRTB nbr codes and\n Shutterstock per-item error metadata in batch responses.',
    )
    discoveryMethod: DiscoveryMethod | None = Field(
        None,
        description="How this URI was discovered by the Broker (v2 extension point).\n v1: always DISCOVERY_METHOD_EXCHANGE (Broker queried an Exchange).\n v2: may include DISCOVERY_METHOD_SEARCH (URI found via search engine like Exa),\n     DISCOVERY_METHOD_RECOMMENDATION, etc. The Broker discovers URIs\n     through any source, then routes through Exchange for pricing/transaction.\n     The discovery method does not affect the transaction flow — it's metadata\n     for the agent to understand how the resource was found.",
    )
    offers: list[Offer] | None = Field(
        None,
        description='Zero or more offers for this URI. Empty = resource not available.',
    )
    restrictionFilters: list[RestrictionKind] | None = Field(
        None,
        description="When absence_reason = RESTRICTION_FILTERED, the restriction axes that drove\n the convenience pre-filter, in the same RestrictionKind vocabulary the terms\n use (e.g. [GEOGRAPHY] when the requester's stated geography matched no term).\n Advisory diagnostics, not an enforcement verdict.",
    )
    uri: str | None = Field(
        '',
        description='The URI this group of offers is for (echoed from ResourceQuery.uris).',
    )


class ResourceEntry(WireModel):
    attestations: list[ResourceAttestation] | None = Field(
        None,
        description="Signed attestations about this resource entry.\n Same semantics as Offer.attestations — see ResourceAttestation message\n for verification levels and claim vocabulary. Attestations pushed via\n CatalogService are verified at push time: the Exchange checks that\n the attestation verifier is authorized to push for this provider\n (via catalog_contributors in the provider's WellKnownManifest) and validates the\n attestation signature against the verifier's public key from their\n /.well-known/ramp.json endpoint (WellKnownManifest, role determined\n by the verifier's operator).",
    )
    contentHash: str | None = Field(None, description='Content hash')
    contentId: str | None = Field(None, description='Content identifier')
    domain: str | None = Field('', description='Provider domain')
    estimatedQuantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Estimated quantity in the metering unit'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    hashMethod: str | None = Field(None, description='Hash algorithm')
    path: str | None = Field('', description='Content path')
    provenanceSource: str | None = Field(
        None,
        description='Who provided this resource metadata. Creates audit trail for\n "where did this catalog entry come from?"',
    )
    provenanceTimestamp: AwareDatetime | None = Field(
        None, description='When this metadata was collected/generated.'
    )
    source: IngestionSource | None = Field(
        None, description='How the entry was discovered'
    )
    terms: list[LicenseTerm] | None = Field(
        None,
        description='Publisher-declared licensing terms for this resource.\n See LicenseTerm for the full model. For ENUMERATED terms, Pricing MUST\n be present. For REFERENCE_ONLY terms, License.uri is authoritative.\n The Exchange validates ENUMERATED terms at push time and surfaces them\n in Offer.terms on discovery.',
    )
    wordCount: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Word count'
    )


class ResourceResponse(WireModel):
    exchange: str | None = Field(
        '', description='Canonical domain of the responding Exchange.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    offerGroups: list[OfferGroup] | None = Field(
        None,
        description='Offers grouped by requested URI (for multi-URI batch queries).\n When populated, `offers` SHOULD be empty to avoid ambiguity.',
    )
    offers: list[Offer] | None = Field(
        None, description='Flat list of offers (for single-URI queries).'
    )
    rateLimit: RateLimitInfo | None = Field(
        None,
        description='Rate limit status for this caller.\n Present when the Exchange enforces per-caller rate limits on discovery.\n Enables agents/Brokers to throttle proactively rather than hitting\n hard limits. Particularly important when a Broker fans out the\n same batch query to multiple Exchanges — mid-batch rate limiting\n can cause partial results if not signaled early.',
    )
    ver: str | None = Field('', description='Protocol version')


class DiscoveryResponse(WireModel):
    absenceReason: OfferAbsenceReason | None = Field(
        None,
        description='Existence-oracle note: an authorization-flavored reason (SCOPE_INSUFFICIENT,\n NOT_AUTHORIZED, NOT_IN_CATALOG, CONTENT_BLOCKED) confirms a resource exists\n and why access was refused. Resolve surfaces the same oracle at the broker\n that OfferGroup.absence_reason does at the Exchange, so the same mitigation\n applies: where existence itself must stay hidden, the Broker MAY omit the\n reason (leave this unset) rather than reveal it. See the threat model.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    offerGroups: list[OfferGroup] | None = Field(
        None,
        description='Offers grouped by requested URI — the sole offer representation in this\n response. One OfferGroup per URI the agent asked for (echoed in\n OfferGroup.uri); a group with no offers carries OfferGroup.absence_reason\n explaining why. Each contained Offer is the full signed Offer the Exchange\n issued (including Offer.exchange, the execute-routing target), forwarded by\n the Broker unchanged so the agent can verify the signature end to end.',
    )
    ver: str | None = ''


class PushResourcesRequest(WireModel):
    callerId: str | None = Field(
        '',
        description='Identity of the caller (who is pushing this data).\n The Exchange verifies this matches a registered CatalogService client.',
    )
    entries: list[ResourceEntry] | None = Field(
        None, description='Content entries to push'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    extCritical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    tenantId: str | None = Field('', description='Tenant identifier')
    ver: str | None = Field('', description='Protocol version')
