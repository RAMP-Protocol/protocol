# Code generated from the RAMP proto (via JSON Schema). DO NOT EDIT.
# Regenerate: scripts/gen-sdk-types.sh   Base class / extension seam: wire/base.py

from __future__ import annotations

from typing import Any
from pydantic import AwareDatetime, Field, RootModel, confloat, conint, constr
from wire.base import WireModel
from enum import Enum



class AccountRegistration(WireModel):
    data_schema: dict[str, Any] | None = Field(
        None,
        description="JSON Schema (draft 2020-12) describing the RegisterRequest.registration_data\n object this Exchange expects. This field is the single home of the\n enforce/pass-through contract, and publishing it IS the enforcement switch.\n Present: this Exchange validates registration_data against the schema and\n refuses a non-conforming payload with\n REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA, naming the offending\n members in RegistrationFailure.field_errors. Absent: registration_data is\n passed through to the system of record uninspected, so an Exchange that\n publishes no schema needs no change to stay conformant. Safety rules,\n because a consumer reads this schema out of a third party's manifest: it\n MUST be self-contained, and a consumer MUST NOT resolve a remote $ref out of\n it — doing so turns every reader into an SSRF vector aimed at a URL the\n schema's author chose. A consumer SHOULD bound validation time and recursion\n depth; draft 2020-12 `pattern` admits regexes with catastrophic\n backtracking. Size is capped at 16KB, measured as the UTF-8 bytes of this\n member as served in ramp.json; a consumer SHOULD reject an oversized schema\n and skip its local pre-check rather than truncate it, which leaves the\n Exchange's own enforcement the deciding check exactly as when no schema is\n published.",
    )


class AgentAcceptance(WireModel):
    signature: constr(pattern=r'^[0-9A-Fa-f]{128}$') = Field(
        ...,
        description='The pattern replaced a bare min_len: 1, which it subsumes: a 128-character\n string cannot be empty. Nothing conformant is refused that was accepted\n before — a signature outside this shape could never hex-decode into 64\n bytes and so could never verify, so it failed at the verify step instead,\n later and with a worse error.',
    )
    signature_algorithm: str | None = Field(
        '', description='Signature algorithm; "EdDSA" for Ed25519.'
    )


class AgentAcceptancePayload(WireModel):
    idempotency_key: str | None = Field(
        '',
        description="The transaction's idempotency key — binds the acceptance to a single\n execute so it cannot be replayed under a different transaction.",
    )
    offer_sig: str | None = Field(
        '',
        description="The accepted Offer's signature (Offer.signature). Anchors the whole signed\n offer without re-serializing its terms/pricing/expiry.",
    )
    requester_domain: str | None = Field(
        '',
        description='Requester domain (Requester.domain) the acceptance is bound to.',
    )
    requester_id: str | None = Field(
        '', description='Requester identity (Requester.id) the acceptance is bound to.'
    )


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
    CATALOG_REJECTION_REASON_TERMS_LIMIT_EXCEEDED = (
        'CATALOG_REJECTION_REASON_TERMS_LIMIT_EXCEEDED'
    )
    CATALOG_REJECTION_REASON_URI_UNAVAILABLE = (
        'CATALOG_REJECTION_REASON_URI_UNAVAILABLE'
    )


class CitationFormat(Enum):
    CITATION_FORMAT_LINK = 'CITATION_FORMAT_LINK'
    CITATION_FORMAT_FOOTNOTE = 'CITATION_FORMAT_FOOTNOTE'
    CITATION_FORMAT_INLINE = 'CITATION_FORMAT_INLINE'


class Cost(WireModel):
    amount: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$', max_length=32) | None = Field(
        '',
        description='Exact decimal string (not a float), e.g. "19.99". Denominated in `currency`.',
    )
    currency: str | None = ''
    unit_cost: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$', max_length=32) | None = None


class Delegation(WireModel):
    expires_at: AwareDatetime | None = Field(
        None,
        description='When this delegation expires. Exchange MUST reject expired tokens.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    issuer: str | None = Field(
        None,
        description='Token issuer. OIDC issuer URL or GNAP grant server URL.\n Exchange uses this for JWT validation (OIDC discovery → JWKS)\n or GNAP token introspection.',
    )
    max_accesses: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Maximum number of accesses allowed under this delegation.\n Exchange tracks cumulative access count against this cap.\n Deny with DENIAL_REASON_QUOTA_EXCEEDED when count >= limit.\n For subscriptions with "10,000 accesses/month", this carries the ceiling.',
    )
    max_spend_cents: int | None = Field(
        None,
        description='Maximum spend in currency minor units (e.g., cents for USD).\n Exchange tracks cumulative spend against this cap.',
    )
    principal_domain: str | None = Field(
        '', description='Who granted this delegation (domain for public key lookup).'
    )
    principal_id: str | None = Field(
        '',
        description='Principal\'s identifier (e.g., "user@acme.com", "marketdata.example.com").',
    )
    quota_period: str | None = Field(
        None,
        description='Quota reset period. How often the access/spend counters reset.\n Example: 30 days for monthly subscriptions — "2592000s" on the wire\n (proto-JSON encodes Duration as seconds; "720h" is not accepted).\n When absent, the quota is lifetime (bounded only by expires_at).',
    )
    revocation_uri: str | None = Field(
        None,
        description='Optional: URI for real-time revocation checking.\n Exchange MAY check this for high-value transactions.\n Not checked for routine low-value access (performance tradeoff).',
    )
    scopes: list[str] | None = Field(
        None,
        description="Scopes granted by this delegation. MUST be a subset of the\n principal's own scopes (attenuation — can only narrow, not widen).",
    )
    token: constr(pattern=r'^[A-Za-z0-9+/]*={0,2}$') | None = Field(
        '', description='Token bytes. A JWT (base64url-encoded JWS).'
    )
    token_format: str | None = Field(
        '',
        description='Token format: "jwt" (default). Empty is treated as "jwt". The field stays\n open for a future format.',
    )


class DeliveryMethod(Enum):
    DELIVERY_METHOD_DIRECT = 'DELIVERY_METHOD_DIRECT'
    DELIVERY_METHOD_INSTRUCTIONS = 'DELIVERY_METHOD_INSTRUCTIONS'
    DELIVERY_METHOD_STREAMING = 'DELIVERY_METHOD_STREAMING'


class DenialReason(Enum):
    DENIAL_REASON_ACCOUNT_INACTIVE = 'DENIAL_REASON_ACCOUNT_INACTIVE'
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
    DENIAL_REASON_ACCOUNT_NOT_REGISTERED = 'DENIAL_REASON_ACCOUNT_NOT_REGISTERED'


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
    billing_id: str | None = Field(
        '',
        description='Billing record identifier from the disputed transaction\n (TransactionResultItem.billing_id).',
    )
    description: str | None = Field(
        None, description='Human-readable description of the issue.'
    )
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. The dispute\'s subject identifiers above cannot stand in for\n it: transaction_id, billing_id and report_id are opaque and Exchange-scoped,\n so verifying one means a database lookup, while the recipient check must run\n before any lookup happens.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    idempotency_key: constr(min_length=1, max_length=255) = Field(
        ...,
        description="DEDUPE SCOPE. The invariant is the one stated on\n TransactionRequest.idempotency_key, and the namespace is the same as\n UsageReport's and for the same reason: this message carries no acceptance\n payload, so the namespace is the TRANSACTION being disputed and the server\n dedupes per (transaction_id, key).",
    )
    reason: DisputeReason = Field(..., description='Reason for the dispute.')
    received_content_hash: str | None = Field(
        None,
        description='Evidence: content hash of what was actually received.\n Exchange compares against the hash promised in ResourceIdentity.',
    )
    received_hash_method: str | None = Field(
        None, description='Hash algorithm the agent used'
    )
    report_id: str | None = Field(
        '',
        description='Must reference a filed UsageReport. The agent MUST file a UsageReport\n (via ReportUsage RPC) and receive a report_id BEFORE filing a dispute.\n This prevents fire-and-forget disputes and ensures the Exchange has\n the complete evidence chain: what was offered, what was transacted,\n what the agent reported using, and what the agent disputes.\n The dispute chain: Transaction → UsageReport → Dispute.',
    )
    transaction_id: constr(min_length=1) = Field(
        ...,
        description='Transaction being disputed. MUST be non-empty. It is also the dedupe\n namespace for `idempotency_key` above, so a filing that names no\n transaction has no namespace to dedupe within — the rule below is what\n makes that namespace exist, not a shape preference. Same rule as\n ramp.v1.UsageReport.transaction_id, for the same reason.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


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
    expires_at: AwareDatetime | None = Field(
        None,
        description='When this challenge expires. Provider must confirm before this time.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    token: str | None = Field(
        '',
        description='Opaque challenge token. Provider must serve this at:\n https://{domain}/.well-known/ramp-verify/{token}',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )
    verification_url: str | None = Field(
        '', description='The exact URL the Exchange will fetch to verify.'
    )


class DomainVerificationConfirmation(WireModel):
    cdn_type: str | None = Field(None, description='CDN type this key is for.')
    domain: str | None = Field('', description='The domain being verified.')
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. Distinct from `domain` above, which is the provider domain\n being verified — the subject of the request, not its recipient.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    signing_key: str | None = Field(
        None,
        description='Optional: signing key to register upon successful verification.\n If present, the key is registered atomically with verification.\n Key format depends on CDN type (PEM for CloudFront, hex for HMAC).',
    )
    token: str | None = Field(
        '', description='The challenge token (echoed from DomainVerificationChallenge).'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


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
    caller_id: str | None = Field(
        None, description='Caller identity (registered with the Exchange).'
    )
    domain: str | None = Field(
        '', description='The provider domain to verify (e.g., "techcrunch.com").'
    )
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. Distinct from `domain` above, which is the provider domain\n being verified — the subject of the request, not its recipient.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class DomainVerificationResult(WireModel):
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    key_id: str | None = Field(
        None,
        description='If signing_key was provided: confirmation of key registration.',
    )
    valid_until: AwareDatetime | None = Field(
        None,
        description='Verification is valid until this time. Provider must re-verify periodically.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class GetAccountStatusRequest(WireModel):
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. Accounts are per-Exchange, so "which Exchange am I asking\n about" is not derivable from anything else in this message.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class GetAccountStatusResponse(WireModel):
    active: bool | None = Field(
        False, description='Whether the account is currently active.'
    )
    billing_ref: str | None = Field(
        '',
        description='The account handle minted at registration (see RegisterResponse.billing_ref).\n Empty when the calling agent has no account yet.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class GetTransactionEvidenceRequest(WireModel):
    tenant_id: constr(min_length=1, max_length=255) = Field(
        ...,
        description='The tenant the transaction must belong to — the second half of the\n selector, matched against TransactionEvidence.tenant_id. Required:\n counterparty agents legitimately hold transaction ids, so the id alone\n must not be enough to read the row, and naming the tenant here is what\n makes a per-tenant ACL possible on this plane. A mismatch is NOT_FOUND,\n byte-identical to an unknown transaction_id, so existence under another\n tenant is not revealed. Same rule as\n ramp.admin.v1.TenantFeeRate.tenant_id (drift-gated).',
    )
    transaction_id: constr(min_length=1, max_length=255) = Field(
        ...,
        description='The transaction whose evidence row to fetch. Same rule as\n ramp.admin.v1.TransactionEvidence.transaction_id (drift-gated) — the row\n identity this request selects by.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in ramp.proto.',
    )


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
    not_after: str | None = Field(
        '',
        description='RFC3339 timestamp. Key is invalid at and after this instant\n (strict upper bound).',
    )
    not_before: str | None = Field(
        '', description='RFC3339 timestamp. Key is invalid before this instant.'
    )
    use: str | None = Field(
        '', description='Intended key use. RAMP v1.0: MUST be "sig".'
    )
    x: str | None = Field(
        '', description='base64url-encoded 32-byte Ed25519 public key.'
    )


class KeyRevocationList(WireModel):
    as_of: AwareDatetime | None = Field(
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
    uri_digest: (
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


class ObligationState(Enum):
    OBLIGATION_STATE_PENDING = 'OBLIGATION_STATE_PENDING'
    OBLIGATION_STATE_FULFILLED = 'OBLIGATION_STATE_FULFILLED'
    OBLIGATION_STATE_EXPIRED = 'OBLIGATION_STATE_EXPIRED'
    OBLIGATION_STATE_WAIVED = 'OBLIGATION_STATE_WAIVED'
    OBLIGATION_STATE_BLOCKED = 'OBLIGATION_STATE_BLOCKED'


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
    media_type: str | None = Field(
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
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    rejected: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Number of entries rejected'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )
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
    reset_at: AwareDatetime | None = Field(
        None,
        description='When the current window resets (UTC). After this time, `remaining` resets to `limit`.',
    )
    window: str | None = Field(
        None,
        description='Duration of the rate limit window (e.g. 60s = per-minute limit).',
    )


class RefreshCatalogRequest(WireModel):
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. Distinct from `tenant_id` above, which names a publisher\n tenant WITHIN an Exchange, not the Exchange itself.',
    )
    tenant_id: str | None = Field('', description='Tenant identifier')
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class RefreshCatalogResponse(WireModel):
    started: bool | None = Field(False, description='Whether the refresh was started')
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class RegisterRequest(WireModel):
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. It matters most here: the caller reaches this endpoint by\n resolving a fetched, cached manifest, so the RFC 9421 signature covers only\n the URL that was dialled — this field is what lets the genuine Exchange\n refuse a registration that was meant for a different one.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    registration_data: dict[str, Any] | None = Field(
        None,
        description="Business-registration data about the operator behind this agent — the\n details an Exchange needs to open a commercial account (legal entity,\n address, jurisdiction, tax identifiers and the like). The specific members\n are operator-defined and not fixed in the wire contract; whether the\n Exchange inspects them follows its manifest — see\n AccountRegistration.data_schema. This is NOT an identity claim: the caller's\n identity is taken from the verified request signature, never from this\n payload, so nothing here is trusted as authentication.",
    )
    terms_digest: (
        constr(
            pattern=r'^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$'
        )
        | None
    ) = Field(
        None,
        description="Echo of WellKnownManifest.terms_digest, stating WHICH terms document the\n operator accepted. The request signature covers this statement, so it is the\n durable record a later dispute asks for; the Exchange stores the accepted\n value with the account. Four cases, all defined: the Exchange publishes a\n digest and this matches — registration proceeds; it publishes one and this\n differs — refused with REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE; it\n publishes one and this is absent — refused with the SAME reason, because the\n caller's remedy is identical (read the manifest, echo, retry) and a second\n reason would split one fix in two; it publishes none and this is present —\n the Exchange MUST ignore the value and MUST NOT record it as an acceptance,\n since it publishes no digest and therefore cannot verify what document the\n value refers to, and storing it would put an unverifiable claim exactly\n where this field exists to hold a verified one. A registering client MUST\n read the digest from a FRESHLY fetched manifest rather than a cached copy —\n a cached endpoint is fine, a cached digest is not, because a client cannot\n detect staleness locally and a warm cache would otherwise make it retry a\n refused value until the cache expired. Registration happens once per\n Exchange, so the extra fetch is cheap.",
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class RegisterResponse(WireModel):
    active: bool | None = Field(
        False,
        description='Whether the account is currently active. Accounts may start inactive\n and be activated out-of-band by the Exchange operator.',
    )
    billing_ref: str | None = Field(
        '',
        description='Opaque, long-lived, per-Exchange account handle minted by the Exchange.\n Means nothing on its own and is never accepted as caller input. A repeat\n Register for the same agent returns the same value.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


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
    REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA = (
        'REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA'
    )
    REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE = (
        'REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE'
    )


class RegistrationFieldError(WireModel):
    error: constr(min_length=1, max_length=255) = Field(
        ...,
        description='Developer-facing, NON-authoritative description of what failed\n (e.g. "required", "must match ^[A-Z]{2}[0-9]+$"). Wording is\n validator-defined and not stable across Exchanges; clients branch on\n `reason`, never on this text. States the constraint, NEVER the submitted\n value — the ErrorDetail leakage rule applies here too.',
    )
    path: constr(max_length=255) | None = Field(
        '',
        description='RFC 6901 JSON Pointer to the offending member, relative to\n registration_data (e.g. "/vat_id", "/address/postal_code"). The empty\n string addresses registration_data itself, for whole-object failures\n (oneOf, minProperties) that belong to no single member.',
    )


class RemoveResourcesRequest(WireModel):
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. Distinct from `tenant_id` above, which names a publisher\n tenant WITHIN an Exchange, not the Exchange itself.',
    )
    paths: list[str] | None = Field(None, description='Paths to remove')
    tenant_id: str | None = Field('', description='Tenant identifier')
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class RemoveResourcesResponse(WireModel):
    removed: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Number of entries removed'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class ReportingObligation(WireModel):
    endpoint: str | None = Field(
        None,
        description='URL to submit the usage report to (if different from Exchange).',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    required: bool | None = Field(
        False, description='Whether post-usage reporting is required.'
    )
    required_fields: list[str] | None = Field(
        None, description='Field names that must be present in the report.'
    )
    window: str | None = Field(
        None,
        description='Duration within which the report must be submitted (e.g. "86400s" = 24\n hours; proto-JSON encodes Duration as seconds).',
    )


class ReportingObligationState(WireModel):
    consumed_quantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Reported consumed quantity, in the metering unit from the Offer\'s\n Pricing — the value the accepted usage report carried. Mirrors\n ramp.v1.Usage.consumed_quantity\'s wire type (int32, unconstrained)\n exactly: this view must be able to state whatever the report stated,\n and a decimal-string shape here could express values (e.g. "3.5") no\n report can produce. Absent until a usage report has been accepted.',
    )
    created_at: AwareDatetime = Field(
        ..., description="When the obligation was minted (the store's CreatedAt)."
    )
    fulfilled_at: AwareDatetime | None = Field(
        None,
        description='When a usage report was ACCEPTED (the store\'s FulfilledAt) — the same\n event that moves state to OBLIGATION_STATE_FULFILLED. Not "when a report\n arrived": a report that arrived and was rejected leaves this absent, and\n the obligation still expires on window_end.',
    )
    state: ObligationState = Field(
        ...,
        description='Lifecycle state. Always a real persisted state, never UNSPECIFIED.\n Server-output enum: {defined_only, not_in: [0]} — a reader must never\n see a number its schema cannot name. Same rule as\n ramp.v1.TransactionDenial.reason (drift-gated) — the discipline the\n ErrorDetail reason discriminators establish for server-output enums.',
    )
    window_end: AwareDatetime = Field(
        ...,
        description="When the usage report is due (the store's WindowEnd). An absolute\n instant, not the ramp.v1.ReportingObligation.window Duration it was\n derived from: this record states what the store holds, and the store\n resolved the window against created_at when it minted the obligation.",
    )


class ReportingPolicy(WireModel):
    quantity_tolerance: confloat(ge=0.0, le=1.0) | None = Field(
        None,
        description="Accepted relative deviation between estimated and reported quantity, as a\n fraction: 0 requires an exact match, 1 accepts any deviation. Omitted: the\n receiving Exchange's default tolerance applies.",
    )
    required_fields: (
        list[constr(pattern=r'^[A-Za-z0-9._:*-]+$', min_length=1, max_length=64)] | None
    ) = Field(
        None,
        description='Report field names the usage-report validator requires. The wire constrains\n only the token shape; which names are meaningful is defined by the receiving\n Exchange and may change without a contract change. Names are a set: repeats\n are rejected. Empty means no required fields.',
        max_length=32,
    )
    tenant_id: constr(min_length=1, max_length=255) = Field(
        ...,
        description='The tenant whose reporting policy is being replaced. Same rule as\n ramp.admin.v1.TenantFeeRate.tenant_id (drift-gated).',
    )
    window_seconds: conint(le=31536000, gt=0) | None = Field(
        None,
        description="Reporting window in seconds. Applies to obligations minted after this call;\n obligations already issued keep the window they were minted with. Capped at\n one year. Omitted: the receiving Exchange's default applies.",
    )


class RequestConstraints(WireModel):
    budget_period: str | None = Field(
        None,
        description='Budget period (e.g. "2592000s" = 30 days; proto-JSON encodes Duration\n as seconds). Resets at period boundary.',
    )
    budget_scope: str | None = Field(
        None,
        description='Budget scope identifier for per-period tracking.\n E.g. "user:u-12345" for per-user budgets, "team:eng" for per-team.\n The Broker tracks cumulative spend per scope across sessions.',
    )
    delivery_preference: list[DeliveryMethod] | None = Field(
        None, description='Preferred delivery methods, in order of preference.'
    )
    exchanges: (
        list[
            constr(
                pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
                max_length=260,
            )
        ]
        | None
    ) = Field(
        None,
        description='Authorized Exchange domains, in the shape "Request recipient" defines in the\n file header. Broker queries only these. This is a FILTER over third parties,\n not an address — the recipient of the request carrying it is a separate\n question.',
    )
    max_data_age: str | None = Field(
        None,
        description='Only relevant for DYNAMIC resources. Ignored for STATIC (content is\n immutable) and LIVE (content doesn\'t exist yet).\n\n Examples:\n   7 days   — "credit report updated within the last week"\n   1 hour   — "stock snapshot from the last hour"\n   30 days  — "drug interaction database updated this month"',
    )
    max_hops: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description="Maximum forwarding hops the agent will allow (Agent → Broker → … →\n Exchange), counted as the number of RFC 9421 HTTP Message Signatures on the\n request. Caps chain depth so a request is not relayed through more brokers\n than the agent is willing to trust or pay. A Broker MUST NOT forward a\n request whose signature count would exceed this. Absent = agent imposes no\n cap (the Exchange's max_intermediary_hops still applies).",
    )
    max_price: Cost | None = Field(
        None, description='Maximum price the agent is willing to pay.'
    )
    max_unit_cost: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$', max_length=32) | None = (
        Field(
            None,
            description='Maximum effective cost per unit, as an exact decimal string (not a float).',
        )
    )
    period_budget: Cost | None = Field(
        None,
        description='Per-period budget limit. The Broker tracks spend against this\n for the budget_scope. Transactions that would exceed are denied.',
    )
    preferred_exchanges: (
        list[
            constr(
                pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
                max_length=260,
            )
        ]
        | None
    ) = Field(
        None,
        description='Exchanges the agent has existing relationships with (subscriptions,\n contracts). The Broker SHOULD prefer these when resource is\n available — subscription resource has zero marginal cost.',
    )
    reporting_capable: bool | None = Field(
        None, description='Whether the agent supports post-usage reporting.'
    )


class RequestCorrelation(WireModel):
    minted: bool | None = Field(
        False,
        description='Provenance: true = the id is SERVER-DERIVED, false = propagated verbatim\n from a caller-supplied header. True covers both ways a server derives\n one — the header was absent, or it was present but nonconforming and was\n replaced — because the property this flag exists for is INFLUENCE, not\n origin story: false means a caller chose these characters, true means no\n caller did. The two are byte-indistinguishable in request_id alone, so a\n forensic read needs this flag to tell a server-derived correlation key\n from an attacker-influenceable one.',
    )
    request_id: constr(pattern=r'^[!-~]+$', min_length=1, max_length=255) = Field(
        ...,
        description="The correlation id as persisted. GOVERNING INVARIANT, established on the\n WRITE path: a persisted request_id always conforms to the rules below —\n printable ASCII, 1..255 — so a present value has already passed the check\n on the way in, and these rules are not a read-side filter over a laxer\n stored value. HOW a server reaches that invariant is its own choice, and\n two mechanisms both conform: reject the nonconforming header and record a\n server-derived id in its place (minted = true), or record no correlation\n at all (the wrapping message stays absent). The first keeps a correlation\n key for a request whose header was bad, the second states that nothing\n trustworthy arrived; neither can put a nonconforming value in the store,\n which is the only property this contract needs. A server that accepts a\n narrower charset than the rules below still satisfies the invariant.\n Background, for a reader tracing where the value comes from: a propagated\n id is caller-influenceable. The SDK's request-id middleware propagates\n any non-empty caller-supplied X-Request-ID verbatim and mints a random\n 128-bit hex token when the header is absent; it performs no conformance\n check of its own, so the check is the Exchange's, at the boundary where\n it decides what to persist.",
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
    attested_at: AwareDatetime | None = Field(
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


class SetReportingPolicyRequest(WireModel):
    policy: ReportingPolicy = Field(
        ...,
        description='The reporting policy to apply. Required — an absent payload would otherwise\n skip validation of its fields.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in ramp.proto.',
    )


class SetReportingPolicyResponse(WireModel):
    policy: ReportingPolicy = Field(
        ..., description='The reporting policy as persisted.'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in ramp.proto.',
    )


class SubscriptionQuotaInfo(WireModel):
    quota_limit: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Total allowed in the current period.'
    )
    quota_remaining: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Remaining in the current period.'
    )
    quota_used: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Used so far in the current period.'
    )
    resets_at: AwareDatetime | None = Field(
        None, description='When the quota counter resets (UTC).'
    )
    subscription_id: str | None = Field(
        '', description='Subscription this quota applies to.'
    )
    unit: str | None = Field(
        None,
        description='What is being metered. Distinguishes access count quotas from\n spend quotas from burst limits.\n Standard values: "accesses", "tokens", "spend_cents", "burst"',
    )


class TenantFeeRate(WireModel):
    fee_rate_bps: conint(ge=0, lt=10000) | None = Field(
        None,
        description='Fee rate in basis points of gross: fee = floor(gross * bps / 10000).\n Below 10000 keeps the fee strictly under 100%; integer basis points avoid\n float drift when aggregating many charges. 0 is a legitimate explicit\n value ("no fee"), not an unset sentinel.',
    )
    notes: constr(max_length=1024) | None = Field(
        None,
        description='Operator commentary on the rate (why it was set, by whom, ticket link).\n Omitted clears any existing note.',
    )
    tenant_id: constr(min_length=1, max_length=255) = Field(
        ..., description='The tenant whose fee rate is being set.'
    )


class TermSemantics(Enum):
    TERM_SEMANTICS_ENUMERATED = 'TERM_SEMANTICS_ENUMERATED'
    TERM_SEMANTICS_REFERENCE_ONLY = 'TERM_SEMANTICS_REFERENCE_ONLY'


class TransactionDenial(WireModel):
    exchange: (
        constr(
            pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
            max_length=260,
        )
        | None
    ) = Field(
        None,
        description='Bare host of the Exchange that PRODUCED this denial, in the form "Request\n recipient" defines in the file header. Not an echo of what the caller sent:\n on a relayed or fanned-out execute the request went to a Broker, so the\n Exchange that refused may not be one the agent named. Carrying it here is\n what lets ACCOUNT_NOT_REGISTERED be actionable — the agent learns where to\n call Register without fetching a manifest to work it out. NOTHING SIGNS THIS\n VALUE: it rides in a response, and on a relayed path the response passed\n through an intermediary, so this field is exactly the unsigned addressing\n the request-side `exchange` field exists to refuse. Treat it as a HINT, not\n an instruction. Before acting on it — and registering is a consequential act,\n handing an operator\'s business data and a signed acceptance of that\n Exchange\'s terms to whoever answers — a caller MUST check the value against\n a domain it already trusts for this transaction: the signed `offer.exchange`\n of the denied item, or its own RequestConstraints.exchanges set. A value\n matching neither is reported to the caller and never dialled, because a\n hostile intermediary that could choose it would be choosing where an\n unattended agent registers.',
    )
    offer_id: str | None = Field(
        None, description='Batch mode: the offer this denial pertains to.'
    )
    reason: DenialReason = Field(
        ..., description='The denial reason (defined-only, non-zero)'
    )
    restriction_mismatches: list[RestrictionKind] | None = Field(
        None,
        description='When reason = RESTRICTION_NOT_SATISFIED, the failed axes (same\n RestrictionKind vocabulary the terms use).',
    )


class AgentAcceptanceSignatureAlgorithm(Enum):
    EdDSA = 'EdDSA'


class OfferSigAlgorithm(Enum):
    EdDSA = 'EdDSA'


class TransactionEvidence(WireModel):
    agent_acceptance_canonical_bytes: constr(
        pattern=r'^(?:[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*|[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]{4})*(?:==)?|[A-Za-z0-9+/]{3}(?:[A-Za-z0-9+/]{4})*=?|[A-Za-z0-9_-]{4}(?:[A-Za-z0-9_-]{4})*|[A-Za-z0-9_-]{2}(?:[A-Za-z0-9_-]{4})*(?:==)?|[A-Za-z0-9_-]{3}(?:[A-Za-z0-9_-]{4})*=?)$',
        min_length=2,
    ) = Field(
        ...,
        description='Verbatim JCS bytes of the AgentAcceptancePayload the agent signed.\n Unbounded for the same reason as offer_canonical_bytes. Same rule as\n ramp.admin.v1.TransactionEvidence.offer_canonical_bytes (drift-gated).',
    )
    agent_acceptance_signature: constr(pattern=r'^[0-9A-Fa-f]{128}$') = Field(
        ...,
        description='Both directives here point UPSTREAM into ramp.v1, which they did not\n always do. This pattern was pinned on the read plane first, while the\n agent plane still described the hex shape in prose and enforced nothing;\n the anchors sat inside this package because there was no upstream rule to\n point at. ramp.v1 now carries the rule on both signature fields, so the\n gate compares the two planes against each other and a future tightening\n on one side can no longer leave the other silently behind.',
    )
    agent_acceptance_signature_algorithm: AgentAcceptanceSignatureAlgorithm = Field(
        ...,
        description='Signing-algorithm label, server-derived (see offer_sig_algorithm).\n Pinned to "EdDSA". Same rule as\n ramp.admin.v1.TransactionEvidence.offer_sig_algorithm (drift-gated).',
    )
    agent_directory_url: (
        constr(
            pattern=r'^$|^https://[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?/[!-~]*$',
            max_length=512,
        )
        | None
    ) = Field(
        '',
        description='PROVENANCE, NOT AUTHORITY. This field is covered by neither signature and\n is written by the same party as the rest of the row, so it can never\n establish that agent_public_key is authentic — see TRUST BOUNDARY above,\n which says where the agent anchor must come from instead. Verification\n tooling MUST NOT treat this value as a fetch target it can trust: the row\n author chose it, so following it hands them the choice of what the\n "independent" copy says.\n\n The rules below bound the damage from tooling that follows the field\n anyway; they do not make following it safe. The value must be \'\' or an\n https URL whose host uses the same recipient-host grammar as\n ramp.v1.Offer.exchange, with an optional port and an ASCII-printable path,\n within 512 bytes. Stated precisely, because a rule that sounds stronger\n than it is would be worse than none: this refuses a plaintext or non-http\n scheme, embedded userinfo or whitespace, and anything that is not a\n host-plus-path shape. It does NOT refuse an IPv4-literal host — the\n recipient-host grammar admits all-numeric labels, so https://169.254.169.254/\n matches. Blocking link-local and private address space is the fetching\n tool\'s job, and it is one more reason this field is not a fetch target.\n\n Named directory, not discovery: ramp.v1 uses "discovery" for RESOURCE\n discovery (DiscoveryRequest, OfferGroup.discovery_method), a different\n thing entirely. This is the agent\'s well-known directory document, which\n is what every sentence describing the field already calls it.',
    )
    agent_public_key: constr(
        pattern=r'^(?:[A-Za-z0-9+/]{43}=?|[A-Za-z0-9_-]{43}=?)$',
        min_length=43,
        max_length=44,
    ) = Field(
        ...,
        description='The registry-pinned agent verifying key (raw 32-byte Ed25519) the\n acceptance verified against. This is the ACCEPTANCE key, which is the\n agent identity for the transaction — ramp.v1.AgentAcceptance defines that\n normatively under "Agent identity", and this row stores the key that\n definition names. It is deliberately NOT the transport signer: a Broker\n may author a re-packaged execute as sender, so the RFC 9421 signer on that\n leg is the broker, and a row anchored on it would name the wrong party.\n Same rule as\n ramp.admin.v1.TransactionEvidence.exchange_signing_public_key\n (drift-gated).',
    )
    created_at: AwareDatetime = Field(
        ..., description='When the Exchange wrote this row (server clock).'
    )
    exchange_signing_public_key: constr(
        pattern=r'^(?:[A-Za-z0-9+/]{43}=?|[A-Za-z0-9_-]{43}=?)$',
        min_length=43,
        max_length=44,
    ) = Field(
        ...,
        description='The Exchange verifying key itself (raw 32-byte Ed25519), not a key id.',
    )
    offer_canonical_bytes: constr(
        pattern=r'^(?:[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*|[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]{4})*(?:==)?|[A-Za-z0-9+/]{3}(?:[A-Za-z0-9+/]{4})*=?|[A-Za-z0-9_-]{4}(?:[A-Za-z0-9_-]{4})*|[A-Za-z0-9_-]{2}(?:[A-Za-z0-9_-]{4})*(?:==)?|[A-Za-z0-9_-]{3}(?:[A-Za-z0-9_-]{4})*=?)$',
        min_length=2,
    ) = Field(
        ...,
        description="Verbatim JCS bytes the Exchange's signature was computed over (the offer\n with its signature fields cleared). min_len only, no ceiling: same\n rationale as offer_json — the bytes under the signature are whatever size\n the signed offer was, and a bound could invalidate a legitimate row.",
    )
    offer_id: constr(min_length=1) = Field(
        ...,
        description='The signed Offer.offer_id (which IS the catalog resource_id). Duplicated\n from the offer JSON so the row reads standalone, without parsing it.',
    )
    offer_json: constr(min_length=1) = Field(
        ...,
        description="The signed offer as a raw JSON string, for query and human audit.\n Deliberately NOT a Struct: a Struct re-normalizes, and the canonical\n bytes below remain the arbiter of what was signed. No upper bound, unlike\n this file's 255-capped ids: upstream ramp.v1 places no size bound on an\n offer, and the row must state whatever the parties actually signed — a\n cap here could make the row fail its own validation for a transaction\n that legitimately executed (the requester_id rationale).",
    )
    offer_sig: constr(pattern=r'^[0-9A-Fa-f]{128}$') = Field(
        ...,
        description="The Exchange's Ed25519 signature over offer_canonical_bytes, hex-encoded\n in the verbatim wire form (either case — hex decoding accepts both, and a\n dispute should read the same characters a request log holds). Named after\n ramp.v1.AgentAcceptancePayload.offer_sig: it is the same value, the one\n the agent's acceptance binds to. Same rule as ramp.v1.Offer.signature\n (drift-gated) — the field this row stores a copy of.",
    )
    offer_sig_algorithm: OfferSigAlgorithm = Field(
        ...,
        description='Spelled sig_algorithm, not signature_algorithm, which is how ramp.v1 and\n the sibling agent_acceptance_signature_algorithm spell it. The short form\n is INHERITED, not chosen: this label names the neighbouring offer_sig, and\n that field copies an upstream field name verbatim\n (ramp.v1.AgentAcceptancePayload.offer_sig). A label that renamed the field\n it describes would be the worse inconsistency.\n\n The long spelling is also not available: ramp.v1 retired a scalar\n offer-signature field (the execute request now reflects the\n full signed Offer instead), and scripts/check-doc-conformance.sh bans that\n identifier across the protos and the docs so the removed name cannot be\n read as live anywhere. A field named after it here would either fail that\n gate or force it open.',
    )
    request_correlation: RequestCorrelation | None = Field(
        None,
        description='Correlation id joining this row outward to whatever else recorded the\n same X-Request-ID for this execute call, with its provenance. One\n message, not two\n sibling fields: presence of the message is the pairing — id and\n provenance flag arrive together or not at all, a constraint two\n optional siblings could not express without message-level CEL (which\n this file forbids). Absent when the Exchange recorded no correlation id.',
    )
    request_idempotency_key: constr(min_length=1, max_length=255) = Field(
        ...,
        description='The REQUEST-level idempotency key the acceptance signs — NOT the derived\n per-item key that TransactionState.idempotency_key carries. Same rule as\n ramp.v1.TransactionRequest.idempotency_key (drift-gated).',
    )
    requester_domain: str | None = Field(
        '',
        description="The signed Requester.domain, verbatim. Unbounded HERE even though the\n agent plane bounds it — ramp.v1.Requester.domain carries max_len 260 and\n the bare-host pattern. Those rules govern what an Exchange may ACCEPT on\n the way in; they do not govern what this row may STATE after the fact. The\n row's job is to reproduce the bytes the acceptance actually signed, so a\n rule here could make the row fail its own validation for a transaction\n that legitimately executed — one accepted under an earlier rule set, or\n signed by a party that spelled the value some other way. Same conclusion\n as requester_id, reached differently: Requester.id genuinely carries no\n wire rule at all.",
    )
    requester_id: str | None = Field(
        '',
        description='requester_id is the signed Requester.id VERBATIM — the bytes under the\n agent\'s signature, never rewritten. It NAMES the same agent as the\n Exchange\'s canonical agent identity but is not byte-equal to it: a signer\n may spell its directory any way it likes (the deployed identity service\n signs "scheme://host"), so the forensic join goes through directory-host\n normalization, not plain equality. No wire rule: the agent plane does not\n constrain Requester.id, and this row states what was signed.',
    )
    tenant_id: constr(min_length=1, max_length=255) = Field(
        ...,
        description='The tenant the transaction executed under. The admin plane is\n deployment-scoped (cross-tenant), so the row states its tenant. Same rule\n as ramp.admin.v1.TenantFeeRate.tenant_id (drift-gated).',
    )
    transaction_id: constr(min_length=1, max_length=255) = Field(
        ...,
        description='The evidenced transaction (Exchange-minted transaction identity). The\n format is implementation-defined, exactly as in ramp.v1 (the documented\n storage model mints a 26-char ULID). The 255 bound is NEW to this plane —\n ramp.v1 leaves transaction ids unconstrained — and is safe here because\n the Exchange mints the id itself, far below that bound; it exists so the\n selector stays storable and indexable.',
    )


class TransactionResultItem(WireModel):
    billing_id: str | None = Field(
        '',
        description="Billing record identifier minted by the Exchange's billing adapter for\n this transaction (not the account handle — see RegisterResponse.billing_ref).",
    )
    cost: Cost | None = Field(None, description='Cost for this item.')
    delivery_method: (
        constr(pattern=r'^DELIVERY_METHOD_UNSPECIFIED$')
        | DeliveryMethod
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(0, description='How resource is delivered for this item.')
    denial_reason: DenialReason | None = Field(
        None, description='Set if this specific item was denied (others may succeed).'
    )
    expires_at: AwareDatetime | None = Field(
        None, description='When retrieval_endpoint expires.'
    )
    offer_id: str | None = Field('', description='The offer_id this result is for.')
    reporting_obligation: ReportingObligation | None = Field(
        None, description='Reporting requirements for this item.'
    )
    resource_title: str | None = Field(
        None, description='Resource title echoed from the Offer.'
    )
    restriction_mismatches: list[RestrictionKind] | None = Field(
        None,
        description='When denial_reason = RESTRICTION_NOT_SATISFIED, the restriction axes the\n request failed, in the same RestrictionKind vocabulary the terms use.',
    )
    retrieval_endpoint: str | None = Field(
        None,
        description="Signed retrieval URL for this item. Bound to the requesting agent's identity\n via the parent TransactionResponse.agent_identity_hash (shared across all\n batch items); expires at expires_at. Absent if this item was denied or its\n delivery_method is not signed-URL-based.",
    )
    subscription_id: str | None = Field(
        None, description='If under subscription, no per-request charge.'
    )
    subscription_unit_value: Cost | None = Field(
        None,
        description='Computed per-unit cost for financial attribution on subscription transactions.\n Even when cost.amount="0" (subscription), this field carries the value\n of the access for accounting purposes (e.g., ASC 606 prepaid drawdown).',
    )
    transaction_id: str | None = Field(
        '',
        description='ENTROPY. RAMP places no entropy requirement on this value. An implementer\n choosing a sequential id should know precisely what that does and does not\n cost, because the protection here is narrower than "unguessable ids are\n unnecessary".\n\n WHAT IS GUARANTEED. The admin plane\'s evidence read\n (ramp.admin.v1.GetTransactionEvidence) selects by the\n (tenant_id, transaction_id) PAIR, so a transaction id ALONE is never a\n bearer capability for the forensic row. Counterparty agents legitimately\n hold the ids of their own transactions, and that pairing is what stops one\n of those ids from reading the row on its own. That is the whole guarantee,\n and a conformance guard fails if the selector stops being a pair.\n\n WHAT IS NOT GUARANTEED: resistance to ENUMERATION. The tenant half of the\n pair is not a secret. Deployments use human brand slugs, and the slug is\n handed to every agent that holds an offer from that tenant — it prefixes\n the offer id inside the signed offer. So a caller who can reach the admin\n plane at all, and who has done business with a tenant, already knows one\n valid tenant value and can walk sequential transaction ids against it.\n What bounds that is the network-layer reachability restriction on the\n admin plane (see the ramp.admin.v1 file header): that plane must not be\n exposed on the public agent-facing listener, and it is the outer control\n an operator must not relax. An Exchange that wants enumeration resistance\n in depth should mint unguessable ids; RAMP does not require it, and no\n agent-plane behavior depends on this format either way.',
    )


class TransactionState(WireModel):
    broker: str | None = Field(
        '',
        description='The broker that routed the acceptance, as the transaction log recorded\n it. \'\' when the acceptance arrived direct — the log\'s broker column is\n optional-empty, and an append-once view states a value for every\n column, so \'\' is a stated fact, not a gap. A ledger renders its\n "broker routed" row from this. No wire rule: this states whatever the\n log holds, and nothing upstream constrains the broker label.',
    )
    idempotency_key: constr(min_length=1) = Field(
        ...,
        description='The transaction\'s per-item idempotency key as logged. The Exchange\n derives it as TransactionEvidence.request_idempotency_key + ":" +\n offer_id — unconditionally, single-item requests included — so distinct\n items of a batch dedupe independently, and this value is NEVER byte-equal\n to the request-level key. A ledger joining this row against a log export\n matches on this derived form, not on the bare request key, and it reaches\n the TRANSACTION-side events only: a usage-report event stores the report\'s\n own idempotency key, because a report addresses a whole transaction and\n has no offer id to derive with. Join a usage report on transaction_id\n instead. No upper\n bound: the derivation appends an id whose length nothing constrains.',
    )
    signed_url_expiry: AwareDatetime | None = Field(
        None,
        description="Absent when the transaction minted no signed URL: DELIVERY_METHOD_DIRECT\n returns the resource inline or from the Exchange's own endpoint, so there\n is nothing to expire. DELIVERY_METHOD_INSTRUCTIONS and\n DELIVERY_METHOD_STREAMING both mint one and always carry this field.\n Absence is a stated fact about the delivery method, not missing data —\n unlike broker below, whose log column is optional-empty and whose '' is\n itself the value, a direct delivery has no value to state here.",
    )
    signed_url_hash: (
        constr(
            pattern=r'^(?:[A-Za-z0-9+/]{43}=?|[A-Za-z0-9_-]{43}=?)$',
            min_length=43,
            max_length=44,
        )
        | None
    ) = Field(
        None,
        description="sha256 of the signed retrieval URL — the join key against the transaction\n log's signed_url_hash column, which holds the same digest as 32 raw bytes.\n The join is byte-to-byte; nothing needs normalizing. Text only appears\n when a store is rendered — protojson base64s this field, and a log export\n picks its own spelling — so it is exports, not stores, that a join has to\n reconcile. Hash-only by design: the full URL is a live\n bearer capability until expiry and is deliberately absent from this\n plane (see TransactionEvidence's delivery section). Absent exactly when\n signed_url_expiry is, and for the same reason: no signed URL, nothing to\n hash. The\n `optional` keyword is load-bearing — it gives this scalar explicit\n presence, so protovalidate skips the length rule on an unset value, while\n a PRESENT hash must still be exactly 32 bytes.",
    )


class UsageAsset(WireModel):
    package_id: str | None = Field(None, description='Package identifier')
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
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    report_id: str | None = Field(
        '',
        description='Exchange-assigned report identifier. Required for the dispute chain —\n the agent must reference this report_id in DisputeRequest to prove that\n a usage report was filed before disputing. The complete evidence chain:\n   Offer → Transaction (transaction_id, billing_id)\n        → UsageReport → UsageReportResponse (report_id)\n        → DisputeRequest (transaction_id + report_id)',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class WBAFile(WireModel):
    keys: list[JsonWebKey] | None = Field(
        None,
        description='RFC 7517 JWK Set "keys" member. RAMP v1: Ed25519 (OKP) keys, each with\n not_before/not_after RAMP extension members.',
    )
    revocation_url: str | None = Field(
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
    displayed_url: str | None = Field(
        None, description='URL displayed to the user as the attribution link.'
    )
    format: CitationFormat | None = Field(
        None, description='How the citation was presented.'
    )
    visible_to_user: bool | None = Field(
        None, description='Whether the attribution was visible to the end user.'
    )


class AuthorizedExchange(WireModel):
    domain: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='Canonical domain of the Exchange, in the shape "Request recipient" defines\n in the file header.',
    )
    endpoint: str | None = Field('', description='RAMP ExchangeService endpoint URL.')
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
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
    rejected_paths: list[str] | None = Field(
        None,
        description='For partial-batch failures: the entry paths that were rejected.',
    )


class DisputeFailure(WireModel):
    reason: DisputeFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class DisputeResponse(WireModel):
    dispute_id: str | None = Field(
        None, description='Exchange-assigned dispute case identifier.'
    )
    estimated_resolution: str | None = Field(
        None, description='Expected resolution timeline.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
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
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class DomainVerificationFailure(WireModel):
    reason: DomainVerificationFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class GetTransactionEvidenceResponse(WireModel):
    evidence: TransactionEvidence = Field(
        ...,
        description='The append-once evidence row. Required: it exists 1:1 for every found\n transaction — an unknown transaction_id is NOT_FOUND, never an empty\n response.',
    )
    obligation_state: ReportingObligationState | None = Field(
        None,
        description='The transaction\'s reporting obligation record, as persisted. The store\n keeps ONE obligation per transaction (keyed on the transaction id,\n transitioning in place — see the storage model), so this is the record\n the Exchange\'s own reporting path acts on, not a "latest of several".\n Absent when the transaction minted none.',
    )
    transaction_state: TransactionState = Field(
        ...,
        description='The transaction-log facts next to it. Required for the same 1:1 reason.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in ramp.proto.',
    )


class Obligation(WireModel):
    detail: str | None = Field(
        None,
        description='Free-form detail: attribution string, notice file URI, etc.\n OBLIGATION_KIND_OTHER without it → lint warning.',
    )
    kind: ObligationKind = Field(..., description='What the agent must do.')
    scope_license: License | None = Field(
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
    estimated_quantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Estimated quantity in the metering unit.\n For text: token count. For video: duration in seconds.\n For documents: page count. For data: record count.',
    )
    license_duration_months: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='License duration in months. How long the granted access remains valid.',
    )
    metering: PricingMetering | None = Field(
        None,
        description='How usage is tracked for billing reconciliation.\n Absent = PRICING_METERING_ONLINE (default real-time tracking).\n NONE = one-time perpetual sale; no ReportUsage required after ExecuteTransaction.\n OFFLINE_SELF_REPORTED = agent self-reports physical-world consumption.',
    )
    model: PricingModel = Field(..., description="Provider's pricing model.")
    rate: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$', max_length=32) | None = Field(
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
    unit_cost: constr(pattern=r'^([0-9]+([.][0-9]+)?)?$', max_length=32) | None = Field(
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
    field_errors: list[RegistrationFieldError] | None = Field(
        None,
        description='When reason = INVALID_REGISTRATION_DATA: the registration_data members\n that are missing or do not conform. Empty for every other reason — enforced\n by the message rule above, not left to prose.',
        max_length=64,
    )
    reason: RegistrationFailureReason = Field(
        ..., description='The failure reason (defined-only, non-zero)'
    )


class Requester(WireModel):
    delegation: Delegation | None = Field(
        None,
        description='Optional delegation — present when the requester acts on behalf of\n another entity (user, organization, upstream agent).',
    )
    domain: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='Domain the requester belongs to — used for public key lookup, so the value\n is concatenated into a URL the verifier fetches ({domain}/.well-known/ramp.json,\n WellKnownManifest with role=ROLE_AGENT). It carries the same bare-host shape\n "Request recipient" defines in the file header, for the same structural\n reason: a scheme, path or query smuggled in here would choose what gets\n fetched, not merely from where.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
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
    c2pa_manifest: str | None = Field(
        None,
        description='Formats:\n   Sidecar: HTTPS URI to a .c2pa manifest file\n   Embedded: same URI as canonical_url (manifest is inside the asset)\n   Content Credentials Cloud: https://contentcredentials.org/verify?uri=...',
    )
    c2pa_status: C2PAStatus | None = Field(
        None,
        description='The full C2PA validation details (signer identity, trust list,\n action history, training/mining status) are carried in a\n ResourceAttestation with c2pa.* claims — see ramp-c2pa-v1 profile.',
    )
    canonical_url: str | None = Field(
        None,
        description='Provider\'s authoritative URL for this resource (rel="canonical").\n Always available. Different per provider for syndicated content.',
    )
    content_hash: str | None = Field(
        None,
        description='Level 1 (SimHash): computed by Exchange from extracted text.\n   Agent verifies that fetched content is "substantially similar."\n   Tolerates dynamic page elements.\n\n Level 2 (SHA-256): computed by provider from deterministic payload.\n   Agent verifies exact match. Requires provider to serve consistent\n   content (e.g., API endpoint, static HTML, structured JSON).\n   Mismatch = dispute. Commands premium pricing.',
    )
    doi: str | None = Field(
        None, description='Digital Object Identifier — persistent, never changes.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    hash_method: str | None = Field(
        None,
        description='Hash algorithm and verification level.\n Examples: "simhash-v1", "minhash-v1", "sha256", "sha384"',
    )
    iptc_guid: str | None = Field(
        None,
        description='IPTC NewsML-G2 globally unique identifier.\n Present when resource flows through news wire syndication (AP, Reuters).',
    )
    isni: str | None = Field(
        None, description='International Standard Name Identifier for the creator.'
    )
    resource_mutability: ResourceMutability = Field(
        ...,
        description='Drives hash verification behavior:\n   STATIC:  content_hash is stable. Agent SHOULD verify delivered content matches.\n   DYNAMIC: content changes between offer and fetch (credit reports, drug databases).\n            content_hash reflects state at offer generation time. Hash mismatch is\n            expected and MUST NOT trigger automatic dispute.\n   LIVE:    content does not exist at offer time (streaming feeds, live broadcasts).\n            content_hash is not applicable. The "resource" is the stream endpoint.\n\n Validated across 18 use cases: static content (articles, patents, legislation),\n dynamic data (credit reports, drug interactions, stock snapshots), and live\n streams (MarketData quotes, NPR broadcast, news monitoring feeds).',
    )
    soft_binding: str | None = Field(
        None,
        description='Algorithm specified in soft_binding_method. Values are algorithm-specific\n (e.g., perceptual hash hex string, watermark identifier).',
    )
    soft_binding_method: str | None = Field(
        None,
        description='Algorithm used for soft_binding.\n Examples: "phash-v1" (perceptual hash), "c2pa-watermark" (C2PA invisible\n watermark), "chromaprint" (audio fingerprint).',
    )


class ResourceQuery(WireModel):
    acceptable_restrictions: list[AcceptableRestriction] | None = Field(
        None,
        description='The limits this query operates within, per restriction axis (function,\n geography, user-type, …) — see AcceptableRestriction. Advisory selection\n inputs the Exchange/Broker MAY pre-select offers against (convenience, not\n enforcement); the agent self-selects and bears compliance.',
    )
    deadline: str | None = Field(
        None,
        description='Maximum time the caller will wait for a response.\n Exchange SHOULD prioritize speed over completeness when tight.\n Absent = "0.5s" default (proto-JSON encodes Duration as seconds).',
    )
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header for the full contract, including the recipient\'s duty to\n reject a request that names someone else.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    requester: Requester | None = Field(
        None,
        description='Requester identity — who is making this request, what scopes they have,\n and optional delegation chain.',
    )
    supported_profiles: list[str] | None = Field(
        None,
        description='Declares which ext field vocabularies the caller can parse and act on.\n The Exchange SHOULD include profile-specific ext fields in Offers\n when the caller declares support. The Exchange MAY skip expensive\n metadata computation (e.g., retraction checking, consolidation\n verification) when the caller does not declare the relevant profile.\n\n Absence means "send all available metadata" — Exchange MUST NOT\n withhold ext fields solely because the caller omitted this field.\n\n Values match the Exchange\'s WellKnownManifest.supported_profiles entries.\n Examples: ["ramp-news-v1", "ramp-academic-v1", "ramp-legal-v1"]',
    )
    uris: list[str] | None = Field(
        None, description='Resource URIs being queried.', max_length=256
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


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


class SetTenantFeeRateRequest(WireModel):
    rate: TenantFeeRate = Field(
        ...,
        description='The fee rate to apply. Required — an absent payload would otherwise skip\n validation of its fields.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in ramp.proto.',
    )


class SetTenantFeeRateResponse(WireModel):
    rate: TenantFeeRate = Field(..., description='The fee rate as persisted.')
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in ramp.proto.',
    )


class TransactionResponse(WireModel):
    agent_identity_hash: str | None = Field(
        '',
        description='Identity that a delivered retrieval_endpoint is bound to: the RFC 7638 JWK\n Thumbprint of the agent\'s Ed25519 key, as "Agent identity" on\n AgentAcceptance defines it — the acceptance key, not the transport signer,\n which may be a Broker. See "Retrieval-URL identity binding" in the file\n header for how a delivery endpoint checks the binding. Shared across the\n request; set once, which is why every acceptance in one request must be\n signed by the same key.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    items: list[TransactionResultItem] | None = Field(
        None,
        description='Per-offer results (one entry per committed item, in original order).',
    )
    subscription_quota: list[SubscriptionQuotaInfo] | None = Field(
        None,
        description='Post-transaction quota state. Tells the agent how much quota remains\n after this transaction. Enables proactive throttling ("1 access left").\n Multiple entries for multi-dimensional quotas.',
    )
    total_cost: Cost | None = Field(
        None, description='Aggregate cost across all items.'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class Usage(WireModel):
    attribution: list[AttributionDetail] | None = Field(
        None, description='Structured attribution details for each citation provided.'
    )
    citation_included: bool | None = Field(
        None,
        description='Whether citation was included as required by the offer terms.',
    )
    consumed_quantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description="REQUIRED. Actual quantity consumed, in the metering unit from the Offer's Pricing.\n For text: tokens consumed. For video: seconds watched. For data: records accessed.\n Exchange cross-references against Offer.pricing.estimated_quantity.",
    )
    consumed_unit: (
        constr(
            pattern=r'^([a-z0-9-]+|[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)?$', max_length=64
        )
        | None
    ) = Field(
        None,
        description='Metering unit for consumed_quantity. Must match the Offer\'s Pricing.unit.\n If omitted, defaults to "tokens". Same token format as Pricing.unit:\n a bare registered token or a vendor:namespaced token.',
    )
    displayed_to_user: bool | None = Field(
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
    billing_id: str | None = Field(
        '',
        description='Billing record identifier from the delivery (TransactionResultItem.billing_id).',
    )
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this report is addressed to (e.g.\n "exchange.example" or "exchange.example:8081") — the Exchange that issued\n the offer and therefore holds the reporting obligation. See "Request\n recipient" in the file header for the full contract. Promoted from optional:\n an absent or empty value used to skip the recipient check entirely, which\n made the check opt-in for the caller.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    idempotency_key: constr(min_length=1, max_length=255) = Field(
        ...,
        description='DEDUPE SCOPE. The invariant is the one stated on\n TransactionRequest.idempotency_key. This message carries no acceptance\n payload, so there is no in-body agent signature to anchor on; the namespace\n is instead the TRANSACTION the report addresses, and the server dedupes per\n (transaction_id, key). That satisfies the invariant without depending on\n the transport signer: the transaction was bound to exactly one agent by its\n acceptance at execute time, so two agents relayed by the same Broker report\n against different transactions and never share a namespace.',
    )
    timestamp: AwareDatetime | None = Field(
        None, description='When the resource was used (ISO 8601).'
    )
    transaction_id: constr(min_length=1) = Field(
        ...,
        description='Transaction ID from the delivery. MUST be non-empty. It is also the dedupe\n namespace for `idempotency_key` above, so a report that names no\n transaction has no namespace to dedupe within — the rule below is what\n makes that namespace exist, not a shape preference. No upper bound: the\n Exchange assigns this id and nothing upstream constrains its length.',
    )
    usage: Usage | None = Field(None, description='How the resource was actually used.')
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class UsageReportRejection(WireModel):
    reason: UsageReportRejectionReason = Field(
        ..., description='The rejection reason (defined-only, non-zero)'
    )


class WellKnownManifest(WireModel):
    accepted_verifiers: list[str] | None = Field(
        None,
        description='Exchange-only. Trusted attestation verification vendors (domains).',
    )
    account_registration: AccountRegistration | None = Field(
        None,
        description='Exchange-only. How to open an account here — see AccountRegistration, which\n owns the contract. Absent: registration_data is accepted uninspected,\n exactly as before this field existed.',
    )
    base_currency: str | None = Field(
        None,
        description='Exchange-only. Base currency for pricing (ISO 4217). All unit_cost\n values from this Exchange are denominated in this currency.',
    )
    catalog_contributors: list[CatalogContributor] | None = Field(
        None,
        description='Publisher-only. Authorized third-party catalog contributors.\n MUST be empty for non-publisher roles.',
    )
    catalog_endpoint: str | None = Field(
        None, description='Exchange-only. CatalogService endpoint URL (if exposed).'
    )
    contact: str | None = Field(
        None, description='Contact email (licensing, integration, security).'
    )
    delivery_methods_supported: list[DeliveryMethod] | None = Field(
        None, description='Exchange-only. Supported delivery methods.'
    )
    domain: str | None = Field(
        '', description='Canonical domain serving this manifest.'
    )
    endpoint: str | None = Field(
        None,
        description="Exchange-only. ExchangeService endpoint URL. MUST be on the same host AND\n PORT that serve this manifest, or on a subdomain of that host on that port,\n and MUST NOT carry userinfo. A consumer refuses an endpoint anywhere else:\n this document is only as trustworthy as the host that served it, so an\n endpoint naming an unrelated host would let whoever answers for the manifest\n redirect a signed call to a party the signature never covered, and another\n port is another service the publisher of the manifest need not control. The\n host match is on a full dot-delimited label boundary, so evil-a.com is not a\n subdomain of a.com. A port equal to the scheme's default and an omitted port\n are the SAME port, so https://x, https://x:443 and x all match. An Exchange\n reachable on a non-default port names that port on both sides. (One\n paragraph deliberately: a blank line here routes the first paragraph into\n the generated types' JSON-Schema title, which the Pydantic/Zod export drops.)",
    )
    exchanges: list[AuthorizedExchange] | None = Field(
        None,
        description="Publisher-only. Authorized exchanges for this publisher's resources.\n Like ads.txt — declares who may sell. MUST be empty for non-publisher\n roles.",
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052). Lists keys\n within ext that the consumer MUST understand. Unknown values reject\n with UNKNOWN_CRITICAL_EXTENSION. Empty (default) → ignore-unknown.',
    )
    gnap_grant_endpoint: str | None = Field(
        None, description='Exchange-only. GNAP grant endpoint when GNAP is supported.'
    )
    hash_methods_supported: list[str] | None = Field(
        None,
        description='Exchange-only. Accepted resource hash methods for attestation\n verification.',
    )
    health_endpoint: str | None = Field(
        None, description='Exchange-only. Health check endpoint URL.'
    )
    max_intermediary_hops: conint(ge=-2147483648, le=2147483647) | None = Field(
        None,
        description='Exchange-only. Maximum forwarding hops this Exchange tolerates on an inbound\n request (Agent → Broker → … → Exchange), counted as RFC 9421 HTTP Message\n Signatures. A request carrying more SHOULD be rejected. Lets Exchanges\n publish their chain-depth tolerance so Brokers prune before forwarding.\n Absent = no published limit (Exchange applies its own default policy).',
    )
    name: str | None = Field(
        None, description='Exchange-only. Human-readable Exchange name.'
    )
    oidc_issuer: str | None = Field(
        None,
        description='Exchange-only. OIDC Discovery URL when OAuth methods are supported.',
    )
    operator: str | None = Field(
        None, description='Exchange-only. Organization operating this Exchange.'
    )
    operator_domain: str | None = Field(
        None,
        description="Exchange-only. Operator's corporate domain (may differ from domain).",
    )
    pricing_models_supported: list[PricingModel] | None = Field(
        None, description='Exchange-only. Supported pricing models.'
    )
    privacy_uri: str | None = Field(
        None, description='Exchange-only. Privacy policy URL.'
    )
    protocol_versions_supported: list[str] | None = Field(
        None,
        description='Exchange-only. Supported RAMP protocol versions (e.g. ["1.0"]).',
    )
    role: Role = Field(..., description='Role this manifest describes.')
    supported_auth_methods: list[AuthMethod] | None = Field(
        None,
        description='Exchange-only. Authorization methods this Exchange supports\n (ordered by preference).',
    )
    supported_profiles: list[str] | None = Field(
        None,
        description='Exchange-only. Domain extension profiles this Exchange conforms to.\n See standards-layering docs.',
    )
    terms_digest: (
        constr(
            pattern=r'^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$'
        )
        | None
    ) = Field(
        None,
        description='Exchange-only. Digest of the document served at `terms_uri`, in\n "method:hexdigest" form (e.g. "sha256:9f86d081..."), pinning WHICH terms\n document this manifest is currently offering. `terms_uri` alone cannot\n answer that: it is a URL, and its content changes, so after the first\n revision every earlier registration points at a document that no longer says\n what was agreed. RegisterRequest.terms_digest echoes this value, the request\n signature covers that echo, and the Exchange records the accepted digest\n with the account — which is what makes "which terms did this operator\n accept" answerable later. Because a digest identifies a document only while\n a copy of it still exists, keeping the historical terms documents\n retrievable is the Exchange\'s obligation. It sits at the top level rather\n than inside account_registration on purpose: an Exchange with pass-through\n registration publishes no block yet still needs to pin its terms version,\n and coupling "I enforce a schema" to "I version my terms" would tie together\n two independent decisions. Operator note: publishing this field for the\n first time refuses every client that does not yet echo it, so it is a\n coordinated change rather than a safe addition.',
    )
    terms_uri: str | None = Field(
        None, description='Exchange-only. Terms of service URL.'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version of THIS MANIFEST DOCUMENT\'s schema — a namespace\n separate from the RPC envelope `ver`, deliberately not coupled to it.\n MUST equal "1.0"; consumers REJECT unrecognised major versions.',
    )


class DiscoveryRequest(WireModel):
    acceptable_restrictions: list[AcceptableRestriction] | None = Field(
        None,
        description='The limits the agent will operate within, per restriction axis — see\n AcceptableRestriction. The Broker forwards these to Exchanges in\n ResourceQuery.acceptable_restrictions. Advisory selection inputs, not\n enforcement.',
    )
    constraints: RequestConstraints | None = Field(
        None, description='Constraints for exchange filtering and offer selection.'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
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
    search_filters: dict[str, Any] | None = Field(
        None,
        description='Structured search filters (optional, alongside or instead of query).\n Keys are profile-specific: "academic.topic", "news.category",\n "legal.jurisdiction", etc. The Broker maps these to Exchange-specific\n query parameters.',
    )
    supported_profiles: list[str] | None = Field(
        None,
        description='The Broker uses this to:\n   1. Route queries to Exchanges that support these profiles\n   2. Forward the profiles in ResourceQuery.supported_profiles\n   3. Include profile-specific ext fields when returning results\n\n Examples: ["ramp-academic-v1"] — agent working on literature review',
    )
    uris: list[str] | None = Field(
        None,
        description='Resource URIs the agent wants. The Broker forwards these to Exchanges in\n ResourceQuery.uris. Optional when `query` / `search_filters` drive\n Broker-side discovery instead.',
        max_length=256,
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class ErrorDetail(WireModel):
    catalog_rejection: CatalogRejection | None = Field(
        None, description='`reason` oneof — CatalogService rejection'
    )
    dispute_failure: DisputeFailure | None = Field(
        None, description='`reason` oneof — DisputeTransaction filing refused'
    )
    domain: str | None = Field(
        '',
        description='Stable grouping for the failing surface, e.g. "ramp.v1.ExchangeService".\n Mirrors google.rpc.ErrorInfo.domain so generic tooling can group errors.',
    )
    domain_verification_failure: DomainVerificationFailure | None = Field(
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
    registration_failure: RegistrationFailure | None = Field(
        None, description='`reason` oneof — agent/provider registration refused'
    )
    retrieval_auth_failure: RetrievalAuthFailure | None = Field(
        None,
        description='`reason` oneof — signed-URL / proof-of-possession check failed',
    )
    transaction_denial: TransactionDenial | None = Field(
        None, description='`reason` oneof — ExecuteTransaction denial'
    )
    usage_report_rejection: UsageReportRejection | None = Field(
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
    part_label: str | None = Field(
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
    data_as_of: AwareDatetime | None = Field(
        None,
        description="Not set for STATIC resources (content doesn't change) or LIVE\n resources (content doesn't exist yet).\n\n The Broker compares this against RequestConstraints.max_data_age\n to filter stale offers. Example: agent requests max_data_age = 7 days,\n Broker drops offers where now() - data_as_of > 7 days.",
    )
    delivery_method: (
        constr(pattern=r'^DELIVERY_METHOD_UNSPECIFIED$')
        | DeliveryMethod
        | conint(ge=-2147483648, le=2147483647)
        | None
    ) = Field(0, description='How resource will be delivered.')
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the Exchange that issued this offer (e.g.\n "exchange.example" or "exchange.example:8081"), in the form "Request\n recipient" defines in the file header. This is the execute-routing target:\n the agent, or a relaying Broker, sends the ExecuteTransaction call for this\n offer to this Exchange, and a Broker relaying a mixed batch groups the items\n by this value. Because it is an ordinary Offer field it falls inside the\n signed bytes (see `signature` below — the signature covers every field\n except `signature` / `signature_algorithm`), so an intermediary cannot\n redirect the execute call to a different Exchange without invalidating the\n offer, and it is what retires the X-RAMP-Exchange-Endpoint transport header.\n It is also the audience statement of an ExecuteTransaction, which is why\n TransactionRequest carries no top-level `exchange`: on receipt, an Exchange\n MUST reject the request unless EVERY item\'s offer.exchange names its own\n domain. Presence is enforced because an empty value is unroutable — a\n relaying Broker has nothing to group or dial on, and the swap-protection\n above is vacuous when the signed bytes carry no recipient at all.',
    )
    expires_at: AwareDatetime | None = Field(
        None, description='When this offer expires (ISO 8601).'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    iab_categories: list[str] | None = Field(
        None,
        description='IAB Content Taxonomy category codes.\n Enables agents to filter offers by topic (e.g., "only finance resources").\n Uses IAB Content Taxonomy 3.1 codes.',
    )
    identity: ResourceIdentity | None = Field(
        None,
        description='Resource identity for cross-exchange deduplication.\n Enables Brokers to recognize the same resource offered by\n different Exchanges and compare pricing.',
    )
    offer_id: str | None = Field(
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
    signature: constr(pattern=r'^[0-9A-Fa-f]{128}$') = Field(
        ...,
        description="The signature covers every field, including `pricing`, `terms` (the full\n licensing payload), `expires_at`, and `exchange`. Only `signature` and\n `signature_algorithm` are excluded from the signed bytes. `expires_at` is\n signed so the offer's validity window is integrity-protected: a relaying\n Broker cannot extend (or shorten) the TTL of a signed offer to replay it\n outside the window the Exchange intended.\n\n CANONICAL SIGNING (RFC 8785 JCS over canonical proto-JSON). The signed bytes\n are:\n\n     signed_payload = JCS( protojson(msg with signature +\n                                      signature_algorithm cleared) )\n\n i.e. render the message to canonical proto-JSON with the PINNED option set\n below, then apply RFC 8785 (JSON Canonicalization Scheme). Deterministic\n protobuf BINARY marshaling is explicitly NOT canonical across languages and\n versions (protobuf's own caveat), so it cannot be a cross-language signing\n primitive; JCS over proto-JSON can be reproduced by ANY language (Go, TS,\n Python) without a protobuf binary codec, so a broker/exchange/client in any\n language signs and verifies byte-identically. This same definition applies to\n the agent offer-acceptance signature (AgentAcceptance.signature).\n\n PINNED proto-JSON option set (the arbiter is the Go-emitted golden vector —\n whatever these options render MUST be byte-identical across all languages):\n   - enum values as NAME strings (not numbers);\n   - int64 / uint64 / fixed64 as decimal STRINGS;\n   - bytes as standard (padded) base64;\n   - google.protobuf.Timestamp / Duration per the proto-JSON WKT rules\n     (RFC 3339 string for Timestamp);\n   - unpopulated fields are OMITTED (never emitted as defaults);\n   - field naming is snake_case (the proto field name, UseProtoNames=true),\n     the naming every SDK target shares — wire, corpus, and signed form are all\n     snake_case;\n   - google.protobuf.Struct (`ext`) → a plain JSON object; JCS then sorts its\n     keys recursively, so the Struct case needs no special handling.\n\n UNKNOWN FIELDS. A canonicalizer either OMITS content it has no schema for or\n PRESERVES it, and the rule follows from which:\n\n   - OMITTING (e.g. proto-JSON, which emits only schema-defined fields): such a\n     canonicalizer CANNOT reproduce the signed bytes of a message carrying\n     unknown fields — what it renders silently drops part of what the signer\n     covered. It MUST refuse the message rather than emit the reduced bytes,\n     and a verifier built on it MUST reject rather than verify over them. The\n     refusal binds at EVERY depth: a nested message and each element of a\n     repeated or map field carries its own unknown-field set.\n   - PRESERVING (a canonicalizer that carries unrecognized members through):\n     it reproduces the signed bytes faithfully, so there is nothing to refuse.\n\n Either way an APPENDED field cannot pass: an omitting canonicalizer refuses\n the message, and a preserving one renders the appended member into bytes the\n signer never covered, so the signature fails. Without the refusal the omitting\n case would fail OPEN — an intermediary could add unknown fields to an\n already-signed message and leave its signature verifying, smuggling\n unauthenticated content through a message the recipient treats as verified.\n\n Extensions therefore ride in `ext` / `ext_critical`, which are defined fields\n and inside the signed bytes — never as undeclared field numbers.\n\n Because the signature covers `terms`, `pricing`, `expires_at`, and\n `exchange`, an intermediary (Broker) cannot tamper with price, restrictions,\n quotas, obligations, the expiry, the execute-routing target, or any\n licensing term without invalidating it.\n Agent SHOULD verify the signature (RFC 2119) against the Exchange's public\n key, and MUST reject an offer whose `expires_at` is in the past.\n\n The rule is the hex shape this comment already describes: 128 characters,\n either case, which is one Ed25519 signature (64 bytes) hex-encoded. Either\n case is accepted because hex decoding accepts both and a dispute should\n read the same characters a request log holds; every SDK in this repo emits\n lowercase. The pattern also makes the field mandatory in practice — the\n empty string does not match it — which restates what this message already\n requires: an unsigned Offer is not an Offer, since the signature is what\n makes its terms, pricing and expiry non-repudiable.",
    )
    signature_algorithm: str | None = Field(
        '',
        description="Signature algorithm. Always 'EdDSA' — the JOSE algorithm identifier for\n Ed25519 (RFC 8032). Only the identifier is borrowed from JOSE: `signature`\n is a detached hex signature, not a JWS.",
    )
    subscription_id: str | None = Field(
        None,
        description='If set, this offer is available under an existing subscription/deal.\n No per-request billing — usage tracked against subscription quota.\n Pricing.rate = "0" for subscription offers (zero marginal cost).\n The Broker SHOULD prefer subscription offers when available.',
    )
    subscription_quota: list[SubscriptionQuotaInfo] | None = Field(
        None,
        description='Subscription quota state, when this offer is under a subscription.\n Enables the agent to see remaining quota before committing.\n Multiple entries when the subscription has independent quotas\n (e.g., access count + spend cap).',
    )
    terms: list[LicenseTerm] | None = Field(
        None,
        description="Licensing terms for this offer, sourced from the publisher's ResourceEntry.\n Multiple terms when the resource has different arrangements by use case.\n See: Universal Licensing Core section.",
    )


class OfferGroup(WireModel):
    absence_reason: OfferAbsenceReason | None = Field(
        None,
        description='Why no offers are available for this URI.\n Present when `offers` is empty. Enables agents/Brokers to distinguish\n "resource not in catalog" from "resource blocked for your use case" without\n trial-and-error transactions. Analogous to OpenRTB nbr codes and\n Shutterstock per-item error metadata in batch responses.',
    )
    discovery_method: DiscoveryMethod | None = Field(
        None,
        description="How this URI was discovered by the Broker (v2 extension point).\n v1: always DISCOVERY_METHOD_EXCHANGE (Broker queried an Exchange).\n v2: may include DISCOVERY_METHOD_SEARCH (URI found via search engine like Exa),\n     DISCOVERY_METHOD_RECOMMENDATION, etc. The Broker discovers URIs\n     through any source, then routes through Exchange for pricing/transaction.\n     The discovery method does not affect the transaction flow — it's metadata\n     for the agent to understand how the resource was found.",
    )
    offers: list[Offer] | None = Field(
        None,
        description='Zero or more offers for this URI. Empty = resource not available.',
    )
    restriction_filters: list[RestrictionKind] | None = Field(
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
    content_hash: str | None = Field(None, description='Content hash')
    content_id: str | None = Field(None, description='Content identifier')
    domain: str | None = Field('', description='Provider domain')
    estimated_quantity: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Estimated quantity in the metering unit'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    hash_method: str | None = Field(None, description='Hash algorithm')
    path: str | None = Field('', description='Content path')
    provenance_source: str | None = Field(
        None,
        description='Who provided this resource metadata. Creates audit trail for\n "where did this catalog entry come from?"',
    )
    provenance_timestamp: AwareDatetime | None = Field(
        None, description='When this metadata was collected/generated.'
    )
    resource_mutability: ResourceMutability | None = Field(
        None,
        description='Optional mutability hint. When omitted, the Exchange applies the `STATIC`\n default at Offer build; an explicit `UNSPECIFIED` is rejected. A value in\n `ext` is not read — the typed field is authoritative, so an ext-only value\n is treated as omitted. Mirrors the required Offer-side\n `ResourceIdentity.resource_mutability`.',
    )
    source: IngestionSource | None = Field(
        None, description='How the entry was discovered'
    )
    terms: list[LicenseTerm] | None = Field(
        None,
        description='Publisher-declared licensing terms for this resource.\n See LicenseTerm for the full model. For ENUMERATED terms, Pricing MUST\n be present. For REFERENCE_ONLY terms, License.uri is authoritative.\n The Exchange validates ENUMERATED terms at push time and surfaces them\n in Offer.terms on discovery.',
    )
    word_count: conint(ge=-2147483648, le=2147483647) | None = Field(
        None, description='Word count'
    )


class ResourceResponse(WireModel):
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='Canonical domain of the responding Exchange, in the shape "Request\n recipient" defines in the file header. The response counterpart of the\n recipient field on the request: it names who answered.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    offer_groups: list[OfferGroup] | None = Field(
        None,
        description='Offers grouped by requested URI (for multi-URI batch queries).\n When populated, `offers` SHOULD be empty to avoid ambiguity.',
    )
    offers: list[Offer] | None = Field(
        None, description='Flat list of offers (for single-URI queries).'
    )
    rate_limit: RateLimitInfo | None = Field(
        None,
        description='Rate limit status for this caller.\n Present when the Exchange enforces per-caller rate limits on discovery.\n Enables agents/Brokers to throttle proactively rather than hitting\n hard limits. Particularly important when a Broker fans out the\n same batch query to multiple Exchanges — mid-batch rate limiting\n can cause partial results if not signaled early.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class TransactionItem(WireModel):
    agent_acceptance: AgentAcceptance | None = Field(
        None,
        description="The agent's detached acceptance signature over this item's `offer`.\n Optional on the wire; the Exchange enforces presence per\n item at the service layer for relayed batches. Signed bytes = the canonical\n AgentAcceptancePayload form, with requester_* and idempotency_key\n taken from the ENCLOSING TransactionRequest and offer_sig = offer.signature.",
    )
    offer: Offer = Field(
        ...,
        description='The FULL signed Offer for this batch entry, reflected back exactly as\n received at discovery. The Exchange verifies `offer.signature` over these\n presented bytes — stateless, no reconstruct-from-catalog. REQUIRED: every\n batch item carries its offer.',
    )


class TransactionRequest(WireModel):
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    idempotency_key: constr(min_length=1, max_length=255) = Field(
        ...,
        description='DEDUPE SCOPE — the invariant, stated here once and cited by every other RPC\n that carries an idempotency_key: a key chosen by one caller MUST NEVER\n collide with another caller\'s cached result. The server dedupes within a\n namespace, never globally. What that namespace IS differs per RPC, because\n the RPCs do not authenticate the same way; each states its own, and each\n namespace has to make the invariant true on its own terms.\n\n For this RPC the namespace is the ACCEPTANCE IDENTITY — the agent key\n defined under "Agent identity" on AgentAcceptance — never the transport\n sender, which may be a Broker relaying many agents behind one key. The\n server dedupes per (acceptance identity, key).',
    )
    items: list[TransactionItem] = Field(
        ...,
        description="The offers committed in this request (REQUIRED, min 1), each carrying its\n own reflected signed Offer + detached acceptance. A single offer is the\n degenerate 1-element list. The Exchange verifies each item's\n `offer.signature` (which covers pricing, terms, and expires_at) over the\n presented bytes against its own key — stateless, self-contained bearer\n tokens, with no reconstruct-from-catalog.",
        min_length=1,
    )
    requester: Requester | None = Field(
        None, description='Requester identity — forwarded for authorization and audit.'
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class DiscoveryResponse(WireModel):
    absence_reason: OfferAbsenceReason | None = Field(
        None,
        description='Existence-oracle note: an authorization-flavored reason (SCOPE_INSUFFICIENT,\n NOT_AUTHORIZED, NOT_IN_CATALOG, CONTENT_BLOCKED) confirms a resource exists\n and why access was refused. Resolve surfaces the same oracle at the broker\n that OfferGroup.absence_reason does at the Exchange, so the same mitigation\n applies: where existence itself must stay hidden, the Broker MAY omit the\n reason (leave this unset) rather than reveal it. See the threat model.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    offer_groups: list[OfferGroup] | None = Field(
        None,
        description='Offers grouped by requested URI — the sole offer representation in this\n response. One OfferGroup per URI the agent asked for (echoed in\n OfferGroup.uri); a group with no offers carries OfferGroup.absence_reason\n explaining why. Each contained Offer is the full signed Offer the Exchange\n issued (including Offer.exchange, the execute-routing target), forwarded by\n the Broker unchanged so the agent can verify the signature end to end.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )


class PushResourcesRequest(WireModel):
    caller_id: str | None = Field(
        '',
        description='Identity of the caller (who is pushing this data).\n The Exchange verifies this matches a registered CatalogService client.',
    )
    entries: list[ResourceEntry] | None = Field(
        None, description='Content entries to push'
    )
    exchange: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='REQUIRED. Bare host of the recipient this request is addressed to (e.g.\n "exchange.example" or "exchange.example:8081"). See "Request recipient" in\n the file header. Distinct from `tenant_id` above, which names a publisher\n tenant WITHIN an Exchange, not the Exchange itself.',
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    tenant_id: str | None = Field('', description='Tenant identifier')
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
    )
