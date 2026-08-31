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
        description='JSON Schema (draft 2020-12) describing the RegisterRequest.registration_data\n object this Exchange expects. This field is the single home of the\n enforce/pass-through contract, and publishing it IS the enforcement switch.\n Present: this Exchange validates registration_data against the schema and\n refuses a non-conforming payload with\n REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA, naming the offending\n members in RegistrationFailure.field_errors. Absent: registration_data is\n passed through to the system of record uninspected, so an Exchange that\n publishes no schema needs no change to stay conformant.\n\nThe gate above runs on ACCOUNT CREATION ONLY. A repeat registration, for an\n agent that already holds an account, is answered from the stored record and\n runs no schema check at all — it discards registration_data rather than\n validating it. That exception is stated here rather than left to the section\n above, because this field calls itself the single home of the contract and a\n reader who comes here for the whole rule would otherwise leave with the wrong\n one. See "Repeat registration" in the Agent Account Registration section for\n why, and for the other gates it applies to.\n\n Absent means the field carries no bytes, or only JSON whitespace — space, tab,\n carriage return and line feed, RFC 8259\'s four and no others. Nothing else\n counts, and the distinction is load-bearing rather than pedantic: this is the\n enforcement switch, so a byte sequence read as absent is one that turns\n validation OFF. A consumer that asked its own language what "blank" means got\n three different answers to the same document — U+00A0 and U+3000 are whitespace\n to some runtimes and not others, and a decoder that strips a byte order mark\n makes a mark followed by a space look like nothing at all. A document that is\n not empty and not JSON is malformed, which is a refusal; it is never silence.\n\n Safety rules, because a consumer reads this schema out of a THIRD PARTY\'s\n manifest and validates against it before any signature has been checked. A\n publisher MUST satisfy every rule below and a consumer MUST refuse a schema\n that does not. The bounds are stated here as numbers rather than left to each\n implementation on purpose: a schema is validated at both ends of the same\n registration, and a limit chosen privately by one side refuses payloads the\n other accepts.\n\n   Self-contained. Every $ref, $dynamicRef and $recursiveRef MUST be a\n   same-document reference — it begins with "#". A consumer MUST NOT resolve a\n   reference that leaves the document: doing so turns every reader into an\n   SSRF vector aimed at a URL the schema\'s author chose.\n\n   One dialect. $schema, wherever it appears in the document, MUST name\n   https://json-schema.org/draft/2020-12/schema (an empty fragment on the end\n   is the same value). A document declaring none is read as that dialect. An\n   older draft is refused rather than validated under semantics its author did\n   not intend.\n\n   Data is not schema. `const`, `enum`, `default` and `examples` hold arbitrary\n   JSON VALUES, and their contents are never read as keywords: a `const` whose\n   value happens to carry a "$ref" or "$schema" member states a value a payload\n   may equal, not a reference to resolve or a dialect to honour. Both rules\n   above therefore stop at those four keywords, and so does the pattern\n   alphabet. Their nesting still counts against the depth cap. Likewise the\n   child keys of `properties`, `patternProperties`, `$defs`, `definitions` and\n   `dependentSchemas` are NAMES rather than keywords, so a property called\n   "$ref" is a property.\n\n   Bounded size: 16KB, measured as the UTF-8 bytes of this member AS SERVED in\n   ramp.json.\n\n   One encoding. The bytes MUST be well-formed UTF-8 (RFC 8259 requires it for\n   interchange) and MUST NOT begin with a byte order mark. RFC 8259 forbids\n   ADDING a mark and lets a parser ignore one, so both policies conform and the\n   choice is made here rather than left to each implementation: parsers differ,\n   and one that strips a mark validates a different document — and counts three\n   bytes against the size cap that the schema does not contain. A consumer MUST\n   NOT repair ill-formed bytes either; substituting U+FFFD silently enforces a\n   schema nobody published. A mark is in any case only valid at the start of a\n   JSON text, and this is a member inside one.\n\n   Bounded depth: 32 nested JSON containers, counting the schema itself as the\n   first.\n\n   Bounded WORK: 10000 evaluations, counted statically over the SCHEMA — each\n   anyOf/oneOf/allOf branch and prefixItems entry costs its own subschema, and a\n   $ref costs its target. It is the cost of applying the schema at ONE location\n   in a payload, not of a whole payload: a subschema under `items` is counted\n   once here and evaluated once per element at runtime. The size and depth caps\n   do not bound it and are not a substitute for it: branches multiply along a\n   reference chain, so a 1.6KB schema five containers deep can cost tens of\n   millions of evaluations and tens of seconds against a two-member payload. A\n   definition nobody references costs nothing, so a document may carry a library\n   of them.\n\n   Bounded reference chains: 100 hops, counted as the longest path of $ref hops\n   rather than as the number of references the document contains. This is a\n   THIRD axis, and a flat chain of definitions shows why it has to be: each one\n   referring to the next is three JSON containers deep however long it is, so\n   the depth cap never sees it, and it costs one evaluation per link, so the\n   work cap does not either. What it does reach is the recursion a validator\n   performs while resolving the chain — a chain of a few hundred exhausted one\n   implementation\'s stack outright, on a document every other rule had passed.\n   A schema describing a business entity chains one or two references.\n\n   No reference cycles. A $ref chain MUST NOT return to a schema already on it.\n   The construct is legal JSON Schema and is how a recursive structure is\n   written, but its evaluation cost has no static bound and it is what makes a\n   validator recurse until it aborts. Registration data describes a business\n   entity, which is not a recursive shape.\n\n   A portable `pattern` alphabet, stated as what a pattern MAY contain rather\n   than as what it may not. A group MUST open with "(" or "(?:" and nothing\n   else; only the escapes \\$, \\(, \\), \\*, \\+, \\., \\/, \\?, \\D, \\W, \\[, \\\\, \\],\n   \\^, \\d, \\f, \\n, \\r, \\t, \\v, \\w, \\{, \\| and \\} MAY appear, together with \\xHH\n   carrying exactly two hexadecimal digits (spelled out rather than ranged, so a\n   conformance guard can check the set character by character); a counted repeat\n   MUST NOT exceed 1000 and MUST state its first bound, so "a{2,}" is admitted\n   and "a{,5}" is not; a "}" outside a bracket expression MUST close a counted\n   repeat, so a literal brace is written "\\}"; "[:" MUST NOT appear inside a\n   bracket expression; a bracket expression MUST close and MUST NOT open with\n   "]"; and a range endpoint MUST NOT be one of the shorthand classes ("[\\w-x]").\n\n   The two brace rules are there for the same reason as the bracket ones, and\n   were found the same way. "a{,5}" is five literal characters to RE2 and a\n   repeat of zero to five to Python, so both engines compile it and then\n   disagree about which payloads match — the silent kind. An unmatched "}" is a\n   literal to RE2 and to Python and a syntax error to ECMA-262 under the `u`\n   flag, which is the loud kind, and exactly what the unmatched "]" rule above\n   already refuses.\n\n   The direction of that rule is the rule. Draft 2020-12 patterns are ECMA-262,\n   but the engines implementations run do not agree on it, and the set they\n   disagree about has no end: it grows with every dialect and every library\n   version, so a list of forbidden escapes needs a new entry each time somebody\n   finds one, and until then the gap is open. The portable set is small and\n   closed, and an author who wants a construct outside it writes the characters\n   out instead.\n\n   Some of the disagreement is loud — RE2 refuses the lookaround, atomic groups\n   and backreferences ECMA allows, so a schema using them compiles for one\n   implementation and fails for another. The rest is SILENT, and is why this is\n   a MUST rather than a SHOULD: inline flags, Unicode property classes, text\n   anchors and POSIX bracket names are accepted by one engine and either refused\n   or read DIFFERENTLY by the next, so two conformant validators both compile\n   the pattern and then disagree about which payloads match it, with nothing\n   logged. `\\s` and `\\B` are the plainest examples — RE2 reads `\\s` as\n   [\\t\\n\\f\\r ], Python adds the vertical tab, and ECMA-262 adds that plus every\n   Unicode space separator; `\\B` finds no word boundary in the empty string for\n   RE2 and ECMA-262 and finds one for Python. An explicit character class says\n   what was meant and means it everywhere.\n\n   Where a pattern may appear. `pattern` states its regex as a value and\n   `patternProperties` states its regexes as KEYS; both are patterns and both\n   are held to the alphabet above. They are the only two keywords in the dialect\n   that carry one — `propertyNames` reaches the rule through the subschema it\n   applies.\n\n   No nested quantifiers. A quantified group MUST NOT have a body that can\n   itself repeat or branch: `(a+)+`, `(a|a)*` and `([a-z]+)*` are refused, while\n   `(?:ab)+` is admitted. This is the denial-of-service half of the pattern\n   rule, and it is deliberately SEPARATE from the alphabet above, because\n   excluding lookaround and backreferences does not cover it — catastrophic\n   backtracking needs neither. It has to be a publishing rule rather than a\n   runtime bound: a regex spin holds its interpreter, so a consumer cannot\n   reliably interrupt one it has already started.\n\n   Annotations stay annotations. A consumer MUST NOT assert format,\n   contentEncoding or contentMediaType. Libraries default differently on each,\n   and a schema whose verdict depends on which library read it has no single\n   answer.\n\n The value MUST be a JSON object. Draft 2020-12 also admits a bare boolean as a\n schema, but this field is a Struct and cannot carry one.\n\n A consumer that finds a schema breaking any of these MUST refuse it, and MUST\n then SKIP its local pre-check rather than repair or truncate the schema —\n leaving the Exchange\'s own enforcement the deciding check, exactly as when no\n schema is published. Refusing locally and declining to send would turn a rule\n about reading a third party\'s document into a denial of service against the\n consumer\'s own user. That is the CLIENT side. An Exchange that cannot compile\n its OWN configured schema is looking at a misconfiguration of its deployment,\n and MUST NOT advertise a schema it is not itself enforcing.',
    )


class AgentAcceptance(WireModel):
    signature: constr(min_length=1) = Field(
        ...,
        description='Hex-encoded detached Ed25519 signature over the canonical AgentAcceptancePayload\n bytes (see the canonical-signing definition on Offer.signature).',
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
        description="Idempotency key (REQUIRED). The server MUST dedupe on this so a replayed\n filing does not open a duplicate case. The dispute's durable identity is the\n Exchange-assigned dispute_id in DisputeResponse.\n Uniqueness is scoped to the verified RFC 9421 signer: the server dedupes per\n (authenticated caller, key), never globally, so a key chosen by one caller\n cannot collide with another's cached result.",
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
    transaction_id: str | None = Field('', description='Transaction being disputed.')
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
    terms_digest: (
        constr(
            pattern=r'^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$'
        )
        | None
    ) = Field(
        None,
        description='The terms document this account ACCEPTED: the "method:hexdigest" value the\n agent echoed in RegisterRequest.terms_digest, which the Exchange recorded\n with the account. This is the read side of that record. Without it the\n protocol required an Exchange to store the acceptance and named the question\n the record exists to answer — "which terms did this operator accept" — while\n giving no way to ask it, so the only party who could check what it had agreed\n to was the party holding the database.\n\nAn Exchange that holds a recorded digest for this account MUST return it\n here. Absence has exactly ONE meaning: no acceptance is recorded. Two\n situations produce it — the Exchange publishes no terms_digest, so nothing\n was ever accepted (and per RegisterRequest.terms_digest it MUST NOT record a\n presented value in that case), or the account was created before the operator\n began publishing one. It does NOT mean "this account has no terms", and an\n Exchange MUST NOT withhold a digest it holds: absence is already spoken for,\n so withholding would make the field state something untrue.\n\n The value is what was ACCEPTED, not what is published now. The two differ as\n soon as the operator revises its terms, and that difference is the point:\n comparing this against a freshly fetched WellKnownManifest.terms_digest is how\n an agent discovers that the terms moved under an account it already holds. A\n repeat Register will not tell it — a repeat is answered from the stored record\n and runs no gate at all.',
    )
    ver: str | None = Field(
        '',
        description='RAMP protocol version — "1.0". Stamped by the sender from a single\n constant; advisory on receive. See "Protocol version" in the file header.',
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
        description='Canonical identity of the license document (RFC 3986). MUST NOT be\n URL-validated — data-labels TDL identifiers use non-URL schemes.\n For REFERENCE_ONLY terms this is the authoritative specification.\n Examples:\n   "https://creativecommons.org/licenses/by/4.0/"\n   "https://techcrunch.com/licensing/ai-terms-2026"\n\n"MUST NOT URL-validate" means do not REJECT non-URL schemes — it does NOT\n mean fetch blindly. A consumer that dereferences this URI MUST apply the\n SSRF countermeasures in the security threat model (T-LIC-1): scheme\n allowlist, block loopback/private/metadata addresses (resolve-then-check),\n fetch via an egress proxy, and treat the response as untrusted content.\n Verify the fetched bytes against `uri_digest` before use.',
    )
    uri_digest: (
        constr(
            pattern=r'^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$'
        )
        | None
    ) = Field(
        None,
        description='Cryptographic digest of the document at `uri`, in "method:hexdigest" form\n (e.g. "sha256:9f86d081..."). Pins the referenced document so a consumer can\n verify the bytes it fetches match what was offered; covered by the offer\n signature, so it is tamper-evident end to end. REQUIRED whenever `uri` is\n non-empty — any semantics, mutable or not: without a pinned digest a MitM\n (or the publisher) can swap the document the agent reads. The Exchange pins\n it at ingestion (computing it over the safely-fetched document, or\n accepting a publisher-supplied value when uri is not HTTP-fetchable, e.g. a\n non-URL TDL scheme).\n\nThe method MUST be a collision-resistant hash — sha256, sha384, or sha512.\n Legacy md5/sha1 are rejected on the wire: a forgeable digest would defeat\n the swap-protection this field exists for. The CEL is STRUCTURE ONLY\n (allowlisted prefix + matching hex length); presence (digest-when-uri) is\n enforced at ingest.',
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
        description='Business-registration data about the operator behind this agent — the\n details an Exchange needs to open a commercial account (legal entity,\n address, jurisdiction, tax identifiers and the like). The specific members\n are operator-defined and not fixed in the wire contract; whether the\n Exchange inspects them follows its manifest — see\n AccountRegistration.data_schema. This is NOT an identity claim: the caller\'s\n identity is taken from the verified request signature, never from this\n payload, so nothing here is trusted as authentication.\n\nBounded, because a published data_schema is applied to THIS. The schema\'s own\n caps bound the schema; the cost of checking a payload against it is roughly\n that cost multiplied by the elements in the payload, and the multiplier was\n unbounded — a subschema under `items` is counted once by the schema\'s\n evaluation cap and evaluated once per element at runtime.\n\n   At most 64 members at the top level. Top level rather than every level:\n   nested bulk is already bounded by the byte cap below, and a recursive count\n   would refuse a small document that merely nests, which a business entity\n   legitimately does — an address is an object.\n\n   At most 32 nested JSON containers, counting this member itself as the first —\n   the same number and the same counting rule as the schema\'s own depth cap,\n   because it is the same question asked of the other document. It is bounded\n   for a reason the other two caps do not cover: a deeply nested payload is\n   small and has few top-level members, and canonicalising it walks it\n   RECURSIVELY, so without a stated bound the verdict was a property of the\n   reader\'s runtime rather than of the payload — one implementation refused\n   past roughly five hundred containers on one release of its language and\n   accepted nine hundred on the next, while two others accepted every depth\n   tried. Checked before the payload is canonicalised, so the bound precedes\n   the walk it exists to bound.\n\n   At most 16384 bytes, measured as this member\'s RFC 8785 (JCS) CANONICAL JSON\n   encoding. The unit is named on purpose and is the load-bearing half of the\n   rule: every other cap in this contract is over bytes a party actually served,\n   and this member is never served as bytes — it is a Struct, decoded before any\n   consumer sees it. "16KB" therefore means nothing until an encoding is chosen,\n   and two implementations choosing privately is the same both-ends disagreement\n   the schema rules exist to prevent. JCS also pins number formatting, which is\n   not a detail: a payload carrying 1e300 is seven bytes under one renderer and\n   three hundred under another.\n\n A payload with NO JSON REPRESENTATION at all is refused in the same class as\n the three bounds: it has no canonical encoding, so the byte cap above has\n nothing to measure. This member is a Struct, and a Struct can carry two such\n values — both of which the protobuf binary decoder accepts and proto-JSON\n refuses to render:\n\n   a NON-FINITE NUMBER. JSON can represent neither NaN nor an infinity, while\n   Struct\'s number_value is an IEEE-754 double that carries one perfectly well.\n\n   a VALUE WITH NO KIND SET. google.protobuf.Value holds its payload in a\n   oneof, and a oneof with no member set is well-formed on the wire. There is\n   no JSON value it denotes, so there is nothing to write.\n\n That check MUST read the decoded protobuf value, never a native map converted\n from it. This is stated because two conformant implementations already\n answered the same signed request differently, and because NEITHER value\n survives the conversion. Some runtimes render a non-finite double as the\n STRING "NaN", "Infinity" or "-Infinity", and once that has happened the\n payload cannot be told apart from one that legitimately carries that text —\n an operator legally named NaN is a valid string value that has to be\n accepted. A value with no kind set converts to the same empty result as a\n JSON null, which is a value the payload may legitimately carry. In both cases\n the conversion destroys the information, so the check has to precede it.\n\n ORDER. The four checks on this member run in this sequence, and the sequence\n is not free choice:\n\n   1. top-level member count\n   2. nesting depth\n   3. canonicalizability, which is where both no-JSON-form checks live\n   4. canonical byte size\n\n The first two are counts, and they bound the document the third then has to\n walk. The third precedes the fourth because the byte cap is DEFINED as the\n length of the canonical encoding: until that encoding exists there is no\n number to compare against, and answering "too large" for a payload that has\n no encoding at all would state something untrue about it.\n\n All four are checked BEFORE the schema runs, for the reason the schema\'s own\n size cap is checked before the document is parsed — a check that exists to\n stop work has to precede the work. A payload breaking any of them is a\n malformed request, NOT REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA:\n that reason names non-conformance to a published schema and applies only\n where one is published, while these four hold either way. The terms_digest\n gate sits between these four and the schema — see\n RegisterRequest.terms_digest for why that order is also fixed.',
    )
    terms_digest: (
        constr(
            pattern=r'^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})?$'
        )
        | None
    ) = Field(
        None,
        description='Echo of WellKnownManifest.terms_digest, stating WHICH terms document the\n operator accepted. The request signature covers this statement, so it is the\n durable record a later dispute asks for; the Exchange stores the accepted\n value with the account. Four cases, all defined: the Exchange publishes a\n digest and this matches — registration proceeds; it publishes one and this\n differs — refused with REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE; it\n publishes one and this is absent — refused with the SAME reason, because the\n caller\'s remedy is identical (read the manifest, echo, retry) and a second\n reason would split one fix in two; it publishes none and this is present —\n the Exchange MUST ignore the value and MUST NOT record it as an acceptance,\n since it publishes no digest and therefore cannot verify what document the\n value refers to, and storing it would put an unverifiable claim exactly\n where this field exists to hold a verified one. A registering client MUST\n read the digest from a FRESHLY fetched manifest rather than a cached copy —\n a cached endpoint is fine, a cached digest is not, because a client cannot\n detect staleness locally and a warm cache would otherwise make it retry a\n refused value until the cache expired. Registration happens once per\n Exchange, so the extra fetch is cheap.\n\nGATE ORDER. This gate runs AFTER the four registration_data checks (see\n RegisterRequest.registration_data) and BEFORE the published data_schema.\n Terms before schema is not arbitrary: the schema may itself have changed in\n the revision the caller has not read yet. Validating a stale-terms caller\n against the CURRENT schema hands back field errors describing a document it\n has never seen, so it fixes those members, re-fetches, and finds the\n requirements have moved. Terms first means a caller is always told to go read\n the current manifest before it is told anything about that manifest\'s\n contents. It also keeps one refusal to one remedy: TERMS_DIGEST_STALE says\n re-fetch and echo, INVALID_REGISTRATION_DATA says fix the payload, and a\n request that would earn both is given the one that has to be done first.\n The whole order applies only when an account is being CREATED: a repeat\n registration is answered from the stored record and runs no gate at all, so\n the four cases above are the four cases of a FIRST registration. See\n "Repeat registration" in the Agent Account Registration section header.',
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
    paths: (
        list[constr(pattern=r'^/[^?#\x00-\x20\x7f]*$', min_length=1, max_length=2048)]
        | None
    ) = Field(
        None,
        description='Paths to remove — the absolute-path shape ResourceEntry.path carries, at\n least one and at most 256, the same batch bound PushResourcesRequest.entries\n carries and for the same reason.',
        max_length=256,
        min_length=1,
    )
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
        ..., description='The tenant whose reporting policy is being replaced.'
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
        description='Maximum acceptable age of resource data. The Broker SHOULD\n exclude offers where (now - Offer.data_as_of) exceeds this duration.\n\nOnly relevant for DYNAMIC resources. Ignored for STATIC (content is\n immutable) and LIVE (content doesn\'t exist yet).\n\n Examples:\n   7 days   — "credit report updated within the last week"\n   1 hour   — "stock snapshot from the last hour"\n   30 days  — "drug interaction database updated this month"',
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
        '', description='Exchange-assigned transaction identifier.'
    )


class UsageAsset(WireModel):
    package_id: str | None = Field(None, description='Package identifier')
    title: str | None = Field(None, description='Asset title')
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
        description='The entry paths the refusal is about. A catalog push is all-or-nothing, so\n these name which entries failed inside a submission that persisted nothing —\n they are not a list of what was dropped from an otherwise applied batch.',
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
        description='Metering basis — the "per what" of PER_UNIT pricing. REQUIRED when\n model = PER_UNIT. Custom units namespace as "vendor:unit". Ignored for\n FREE / FLAT.\n\nThe (ramp.v1.vocab) entries below are the SOLE authored source of the\n registered bare tokens. A buf plugin reads them structurally and emits the\n pricingunits constants + IsRegistered; ingest enforces membership from\n those. The CEL is STRUCTURE ONLY (empty / bare-form / vendor:namespaced) —\n it never lists the tokens, so it cannot drift from the registry.',
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
        description='The unit being capped — an open vocabulary axis.\n\nThe (ramp.v1.vocab) entries below are the SOLE authored source of the\n registered bare metric tokens. A buf plugin reads them structurally and\n emits the quotametrics constants + IsRegistered; ingest enforces membership\n from those. The CEL is STRUCTURE ONLY (non-empty bare token or\n vendor:namespaced) — it never lists the tokens, so it cannot drift.\n\n Token meanings:\n   display-words      Words of content text rendered to an end user.\n   impressions        Times the content is displayed to an end user.\n   tokens             LLM output tokens generated using this content.\n   input-tokens       LLM input tokens consumed from this content.\n   units-manufactured Physical units manufactured from this design/pattern.\n   accesses           Distinct content access / retrieval events.\n   copies             Digital or physical copies produced.\n   seats              Distinct named users licensed to access the content.',
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
        description='Domain the requester belongs to. It carries the same bare-host shape\n "Request recipient" defines in the file header, for the same structural\n reason: a scheme, path or query smuggled in here would choose what gets\n fetched, not merely from where. It is NOT how a verifier finds this\n requester\'s keys: those live in the WBA directory, and verification resolves\n that directory from the COVERED `Signature-Agent` header, never from this\n self-asserted value.',
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
        description='Entitlement scopes. Declare what the requester can access.\n\nThe Exchange filters its catalog to resources matching these scopes.\n Resources outside the scopes are not returned — the requester never\n learns they exist. This is the enforcement mechanism for both enterprise\n RBAC and open-market subscription entitlements.\n\n Scope format: colon-separated segments, "{domain}:{permission}" or\n "{profile}:{permission}", optionally multi-segment ("dist:US:CA");\n matching is segment-wise per the rule below (no implicit hierarchy).\n Examples:\n   "credit:read"                — can access credit reports\n   "subscription:marketdata-2026" — has active MarketData subscription\n   "academic:*"                 — full access to academic resources\n   "internal:reports"           — can access internal reports\n   "*"                         — unrestricted (public Exchange default)\n\n Matching is SEGMENT-WISE (":" separated). A granted scope G covers a\n required scope R iff, segment by segment, each G segment equals the\n corresponding R segment or is "*"; a terminal "*" matches all remaining\n segments. There is NO implicit prefix match, and a grant NARROWER than\n the requirement does not cover it (G must be equal-to-or-broader than R).\n Examples: "dist:*" covers "dist:US" and "dist:US:CA"; "dist:US:*" covers\n "dist:US:CA" but not "dist:EU"; bare "dist" covers only "dist"; granted\n "dist:US:CA" does NOT cover required "dist:US"; "*" covers everything.\n This same rule governs LicenseTerm.scopes — one algorithm protocol-wide.\n\n When empty, Exchange applies its default access policy (typically\n returns all publicly available resources).',
        max_length=64,
    )
    type: RequesterType = Field(
        ..., description='What kind of entity is making this request.'
    )


class ResourceIdentity(WireModel):
    c2pa_manifest: str | None = Field(
        None,
        description='C2PA content credentials manifest URI.\n Points to a sidecar or embedded C2PA manifest for this resource.\n C2PA-aware agents MAY follow this URI to validate the full provenance\n chain (creator identity, transformation history, ingredient composition)\n using C2PA libraries (JUMBF/COSE Sign1). C2PA-unaware agents can rely\n on c2pa_status and c2pa-bridged attestation claims instead.\n\nFormats:\n   Sidecar: HTTPS URI to a .c2pa manifest file\n   Embedded: same URI as canonical_url (manifest is inside the asset)\n   Content Credentials Cloud: https://contentcredentials.org/verify?uri=...',
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
        description='Hash of the content. Interpretation depends on hash_method:\n   "simhash-v1" → locality-sensitive hash, for fuzzy dedup (Level 1)\n   "sha256"     → exact-match integrity hash (Level 2)\n\nLevel 1 (SimHash): computed by Exchange from extracted text.\n   Agent verifies that fetched content is "substantially similar."\n   Tolerates dynamic page elements.\n\n Level 2 (SHA-256): computed by provider from deterministic payload.\n   Agent verifies exact match. Requires provider to serve consistent\n   content (e.g., API endpoint, static HTML, structured JSON).\n   Mismatch = dispute. Commands premium pricing.',
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
        description='Soft binding hash — content-derived identifier that survives format\n transcoding (resolution changes, compression, PDF-to-text extraction).\n Extracted from C2PA soft binding assertion when present.\n Enables post-delivery verification when the hard binding hash breaks\n due to legitimate format conversion.\n\nAlgorithm specified in soft_binding_method. Values are algorithm-specific\n (e.g., perceptual hash hex string, watermark identifier).',
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
        description='Domain extension profiles the caller understands.\n\nDeclares which ext field vocabularies the caller can parse and act on.\n The Exchange SHOULD include profile-specific ext fields in Offers\n when the caller declares support. The Exchange MAY skip expensive\n metadata computation (e.g., retraction checking, consolidation\n verification) when the caller does not declare the relevant profile.\n\n Absence means "send all available metadata" — Exchange MUST NOT\n withhold ext fields solely because the caller omitted this field.\n\n Values match the Exchange\'s WellKnownManifest.supported_profiles entries.\n Examples: ["ramp-news-v1", "ramp-academic-v1", "ramp-legal-v1"]',
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
        ...,
        description="Which dimension this restriction applies to. Defined-only: the axis set is\n CLOSED, and a number outside it is refused rather than ignored. A custom\n axis is RESTRICTION_KIND_OTHER, whose meaning rides in permitted/prohibited,\n so a new number was never the extension mechanism — accepting one would\n admit a restriction no consumer can evaluate onto a term whose default is\n BINDING (see advisory below), which fails open on the axis a publisher most\n needs enforced. It also bounds the cost of the one-per-kind rule below: with\n the axes closed, a list longer than the axis set must repeat one, so that\n rule's all() short-circuits instead of comparing every pair.",
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
        description='Identity that a delivered retrieval_endpoint is bound to: the RFC 7638 JWK\n Thumbprint of the agent\'s Ed25519 request-signing key (see "Retrieval-URL\n identity binding" above). Shared across the request; set once.',
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
        description="Idempotency key (REQUIRED). The server MUST dedupe on this so a replayed\n report does not double-count usage. The report's durable identity is the\n Exchange-assigned report_id in UsageReportResponse.\n Uniqueness is scoped to the verified RFC 9421 signer: the server dedupes per\n (authenticated caller, key), never globally, so a key chosen by one caller\n cannot collide with another's cached result.",
    )
    timestamp: AwareDatetime | None = Field(
        None, description='When the resource was used (ISO 8601).'
    )
    transaction_id: str | None = Field(
        '', description='Transaction ID from the delivery.'
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
        None,
        description="Exchange-only. CatalogService endpoint URL (if exposed). It carries the\n same binding as endpoint: it MUST be on the same host AND PORT that serve\n this manifest, or on a subdomain of that host on that port, and MUST NOT\n carry userinfo. A consumer refuses a catalog endpoint anywhere else — a\n publisher's push is a signed call, and a manifest naming an unrelated host\n would redirect it to a party the signature never covered. The host match is\n on a full dot-delimited label boundary, and a port equal to the scheme's\n default and an omitted port are the SAME port. Absent means this Exchange\n does not expose CatalogService; a consumer does not fall back to endpoint.",
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
        description="Exchange-only. ExchangeService endpoint URL. MUST be on the same host AND\n PORT that serve this manifest, or on a subdomain of that host on that port,\n and MUST NOT carry userinfo. A consumer refuses an endpoint anywhere else:\n this document is only as trustworthy as the host that served it, so an\n endpoint naming an unrelated host would let whoever answers for the manifest\n redirect a signed call to a party the signature never covered, and another\n port is another service the publisher of the manifest need not control. The\n host match is on a full dot-delimited label boundary, so evil-a.com is not a\n subdomain of a.com. A port equal to the scheme's default and an omitted port\n are the SAME port, so https://x, https://x:443 and x all match. An Exchange\n reachable on a non-default port names that port on both sides.",
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
        description='Exchange-only. Digest of the document served at `terms_uri`, in\n "method:hexdigest" form (e.g. "sha256:9f86d081..."), pinning WHICH terms\n document this manifest is currently offering. `terms_uri` alone cannot\n answer that: it is a URL, and its content changes, so after the first\n revision every earlier registration points at a document that no longer says\n what was agreed. RegisterRequest.terms_digest echoes this value, the request\n signature covers that echo, and the Exchange records the accepted digest\n with the account — which is what makes "which terms did this operator\n accept" answerable later, through GetAccountStatusResponse.terms_digest, which\n is where the accepted value is read back. Because a digest identifies a\n document only while\n a copy of it still exists, keeping the historical terms documents\n retrievable is the Exchange\'s obligation. It sits at the top level rather\n than inside account_registration on purpose: an Exchange with pass-through\n registration publishes no block yet still needs to pin its terms version,\n and coupling "I enforce a schema" to "I version my terms" would tie together\n two independent decisions. Operator note: publishing this field for the\n first time refuses every client that does not yet echo it, so it is a\n coordinated change rather than a safe addition.',
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
        description='Domain extension profiles the agent understands.\n\nThe Broker uses this to:\n   1. Route queries to Exchanges that support these profiles\n   2. Forward the profiles in ResourceQuery.supported_profiles\n   3. Include profile-specific ext fields when returning results\n\n Examples: ["ramp-academic-v1"] — agent working on literature review',
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
        None,
        description='Post-use behavioral requirements.\n At most 64, for the reason quotas carries.',
        max_length=64,
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
        None,
        description='Usage caps. The agent must not exceed any individual Quota.\n At most 64, the bound every per-message list in this contract carries when\n no rule walks it more than once. It bounds what one term may carry, not the\n work of checking one — a validator walks every element it is handed before\n the cap is reported, so the cost of checking is bounded at the transport.',
        max_length=64,
    )
    restrictions: list[Restriction] | None = Field(
        None,
        description="Usage restrictions (function, geography, user-type).\n Multiple restrictions are AND-combined — the agent must satisfy all of them.\n At most 8, and this list is the one of the three that does NOT carry the\n contract's usual 64: only one restriction per axis is valid, the axis enum\n is defined-only, so four is the longest conformant list and eight leaves\n room for an axis this version does not have. The tighter bound is here\n because this is the list the message rules walk QUADRATICALLY — the\n one-per-kind rule below compares the list against itself, and each element's\n disjointness rule compares its two token lists pairwise. A cap on a list a\n rule walks twice bounds the rule; the caps on quotas and obligations bound\n only the document, which is why they differ.",
        max_length=8,
    )
    scopes: list[str] | None = Field(
        None,
        description='Delegation scope-gating: the Exchange returns this term to an agent iff the\n agent\'s delegation grant covers ALL of these scopes (AND-semantics).\n Empty = public. A subscription term is Pricing{model:FREE} +\n scopes:["subscription:..."].\n\nCoverage uses the SAME matching rule as Requester/delegation scopes:\n segment-wise (":" separated), each granted segment must equal the\n corresponding required segment or be "*", a terminal "*" matches all\n remaining segments, and there is NO implicit prefix match (a grant\n narrower than the requirement does not cover it). "dist:*" covers\n "dist:US" and "dist:US:CA"; "dist" covers only "dist". There is exactly\n one scope-matching algorithm across the protocol.',
        max_length=64,
    )
    semantics: TermSemantics = Field(
        ..., description='How to interpret the machine fields.'
    )


class Offer(WireModel):
    attestations: list[ResourceAttestation] | None = Field(
        None,
        description='Signed attestations about the resource at this URI.\n Attestations provide cryptographic proof of\n resource properties from trusted parties (providers or verification vendors).\n\nThree verification levels determine what is independently verifiable:\n   Level 0 (no attestations): Resource may carry identifiers (DOI, IPTC GUID)\n     for identification, but nothing is cryptographically verifiable.\n     Only CDN delivery failure is auto-disputable.\n   Level 1 (self-attested): Provider signs own claims with Ed25519 key.\n     Agent can independently verify content hash and token count.\n     CDN delivery failure + content hash mismatch are auto-disputable.\n   Level 2 (third-party attested): Independent verification vendor crawled\n     the resource and attested to its properties. Agent trusts the attestation\n     (does not re-verify hash). Token count discrepancy is auto-disputable\n     when corroborated by CDN response size.\n\n Multiple attestations may be present (e.g., provider self-attestation\n plus a third-party verification). Agents choose which to trust.',
    )
    data_as_of: AwareDatetime | None = Field(
        None,
        description='When the offered data was current. For dynamic resources\n (resource_mutability = DYNAMIC), this is the snapshot timestamp.\n Enables the Broker to evaluate freshness: "this credit report\n reflects data as of March 18" or "this drug database was updated today."\n\nNot set for STATIC resources (content doesn\'t change) or LIVE\n resources (content doesn\'t exist yet).\n\n The Broker compares this against RequestConstraints.max_data_age\n to filter stale offers. Example: agent requests max_data_age = 7 days,\n Broker drops offers where now() - data_as_of > 7 days.',
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
        description="Lightweight previews for offer evaluation.\n The Exchange holds URLs (50–200 bytes each); the provider's CDN serves\n the actual bytes. Agents fetch previews only when evaluating offers —\n not on every discovery query. Multiple previews at different sizes\n allow agents to pick the cheapest fetch for their evaluation needs.\n\nPer content type:\n   Image:  watermarked thumbnail (150–450px JPEG)\n   Video:  short clip (10–30s MP4, watermarked)\n   Audio:  short clip (15–30s MP3, low-bitrate or watermarked)\n   Text:   snippet or abstract (first 200 words as text/plain)\n   Data:   sample records (1–3 rows as application/json)\n   Stream: optional frame capture or none (streams are priced by time)\n\n Modeled after Shutterstock (multi-size thumbnail URLs),\n Spotify (preview_url to 30s clip), IIIF (parameterized image URLs),\n and OpenRTB native (img.url + dimensions).",
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
        description="REQUIRED. JWS (alg=EdDSA) over the canonical serialization of the ENTIRE\n Offer — every field, including `pricing`, `terms` (the full licensing\n payload), `expires_at`, and `exchange`. Only `signature` and\n `signature_algorithm` are excluded from the signed bytes. `expires_at` is\n signed so the offer's validity window is integrity-protected: a relaying\n Broker cannot extend (or shorten) the TTL of a signed offer to replay it\n outside the window the Exchange intended.\n\nCANONICAL SIGNING (RFC 8785 JCS over canonical proto-JSON). The signed bytes\n are:\n\n     signed_payload = JCS( protojson(msg with signature +\n                                      signature_algorithm cleared) )\n\n i.e. render the message to canonical proto-JSON with the PINNED option set\n below, then apply RFC 8785 (JSON Canonicalization Scheme). Deterministic\n protobuf BINARY marshaling is explicitly NOT canonical across languages and\n versions (protobuf's own caveat), so it cannot be a cross-language signing\n primitive; JCS over proto-JSON can be reproduced by ANY language (Go, TS,\n Python) without a protobuf binary codec, so a broker/exchange/client in any\n language signs and verifies byte-identically. This same definition applies to\n the agent offer-acceptance signature (AgentAcceptance.signature).\n\n PINNED proto-JSON option set (the arbiter is the Go-emitted golden vector —\n whatever these options render MUST be byte-identical across all languages):\n   - enum values as NAME strings (not numbers);\n   - int64 / uint64 / fixed64 as decimal STRINGS;\n   - bytes as standard (padded) base64;\n   - google.protobuf.Timestamp / Duration per the proto-JSON WKT rules\n     (RFC 3339 string for Timestamp);\n   - unpopulated fields are OMITTED (never emitted as defaults);\n   - field naming is snake_case (the proto field name, UseProtoNames=true),\n     the naming every SDK target shares — wire, corpus, and signed form are all\n     snake_case;\n   - google.protobuf.Struct (`ext`) → a plain JSON object; JCS then sorts its\n     keys recursively, so the Struct case needs no special handling.\n\n UNKNOWN FIELDS. A canonicalizer either OMITS content it has no schema for or\n PRESERVES it, and the rule follows from which:\n\n   - OMITTING (e.g. proto-JSON, which emits only schema-defined fields): such a\n     canonicalizer CANNOT reproduce the signed bytes of a message carrying\n     unknown fields — what it renders silently drops part of what the signer\n     covered. It MUST refuse the message rather than emit the reduced bytes,\n     and a verifier built on it MUST reject rather than verify over them. The\n     refusal binds at EVERY depth: a nested message and each element of a\n     repeated or map field carries its own unknown-field set.\n   - PRESERVING (a canonicalizer that carries unrecognized members through):\n     it reproduces the signed bytes faithfully, so there is nothing to refuse.\n\n Either way an APPENDED field cannot pass: an omitting canonicalizer refuses\n the message, and a preserving one renders the appended member into bytes the\n signer never covered, so the signature fails. Without the refusal the omitting\n case would fail OPEN — an intermediary could add unknown fields to an\n already-signed message and leave its signature verifying, smuggling\n unauthenticated content through a message the recipient treats as verified.\n\n Extensions therefore ride in `ext` / `ext_critical`, which are defined fields\n and inside the signed bytes — never as undeclared field numbers.\n\n Because the signature covers `terms`, `pricing`, `expires_at`, and\n `exchange`, an intermediary (Broker) cannot tamper with price, restrictions,\n quotas, obligations, the expiry, the execute-routing target, or any\n licensing term without invalidating it.\n Agent SHOULD verify the signature (RFC 2119) against the Exchange's public\n key, and MUST reject an offer whose `expires_at` is in the past.",
    )
    signature_algorithm: str | None = Field(
        '',
        description="JWS algorithm. Always 'EdDSA' for Ed25519 via JWS Compact Serialization.",
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
    title: str | None = Field(
        None, description='Resource title (human-readable, for display/logging).'
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
        description="Signed attestations about this resource entry.\n Same semantics as Offer.attestations — see ResourceAttestation message\n for verification levels and claim vocabulary. Attestations pushed via\n CatalogService are verified at push time: the Exchange checks that\n the attestation verifier is authorized to push for this provider\n (via catalog_contributors in the provider's WellKnownManifest) and validates the\n attestation signature against the verifier's public key from its WBA\n directory (the JWK Set at /.well-known/http-message-signatures-directory;\n the keyid is the key's RFC 7638 thumbprint). The verifier's ramp.json\n carries only its role, determined by the verifier's operator.",
        max_length=64,
    )
    content_hash: constr(max_length=255) | None = Field(
        None,
        description='Content hash, carried as the publisher computed it — a bare hex digest or a\n "method:hexdigest" form; bounded in length, never format-checked, because\n hash_method names the algorithm.',
    )
    content_id: constr(max_length=255) | None = Field(
        None, description='Content identifier'
    )
    domain: constr(
        pattern=r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$',
        max_length=260,
    ) = Field(
        ...,
        description='Provider domain — the bare host the resource lives on, in the shape\n "Request recipient" defines in the file header: a port is allowed, a\n scheme, path, query or userinfo is not. With path it forms the catalog URI\n by concatenation, so a value carrying anything but a host would choose the\n URI rather than merely name the host.',
    )
    estimated_quantity: conint(ge=0, lt=2147483648) | None = Field(
        None, description='Estimated quantity in the metering unit'
    )
    ext: dict[str, Any] | None = Field(None, description='Extension point')
    ext_critical: list[str] | None = Field(
        None,
        description='Critical extension keys (COSE crit pattern, RFC 9052).\n Lists keys within ext that the consumer MUST understand.\n Unknown keys in this list → reject with UNKNOWN_CRITICAL_EXTENSION.\n Empty (default) → all ext keys are safe to ignore.',
    )
    hash_method: constr(max_length=64) | None = Field(
        None, description='Hash algorithm'
    )
    path: constr(pattern=r'^/[^?#\x00-\x20\x7f]*$', min_length=1, max_length=2048) = (
        Field(
            ...,
            description='Content path — an absolute URL path such as "/premium/article-42.html":\n starts with "/", carries no query or fragment delimiter, no whitespace and\n no control character, and is at most 2048 characters. Characters, not bytes:\n protovalidate\'s max_len counts Unicode code points, and the pattern admits\n non-ASCII, so a conformant path can exceed 2048 bytes.',
        )
    )
    provenance_source: constr(max_length=260) | None = Field(
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
        description='Publisher-declared licensing terms for this resource.\n See LicenseTerm for the full model. For ENUMERATED terms, Pricing MUST\n be present. For REFERENCE_ONLY terms, License.uri is authoritative.\n The Exchange validates ENUMERATED terms at push time and surfaces them\n in Offer.terms on discovery. At most 32 terms per entry, stated on the wire\n so every implementation refuses the same size. An over-cap entry refuses the\n whole submission, as every catalog rejection does; what being a wire rule\n changes is WHEN — the refusal now happens at the boundary, before any\n per-entry classification runs, which is why the rejection reason that named\n this cap can no longer be produced for a push.',
        max_length=32,
    )
    title: constr(max_length=512) | None = Field(None, description='Content title')
    word_count: conint(ge=0, lt=2147483648) | None = Field(
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
        description="Idempotency key (REQUIRED). The server MUST dedupe on this: a replay returns\n the original result rather than re-executing. The transaction's durable\n identity is the Exchange-assigned transaction_id in the response.\n Uniqueness is scoped to the verified RFC 9421 signer: the server dedupes per\n (authenticated caller, key), never globally, so a key chosen by one caller\n cannot collide with another's cached result.",
    )
    items: list[TransactionItem] | None = Field(
        None,
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
        None,
        description='Content entries to push. At least one: an empty push asks for nothing and\n is refused rather than answered with zero counts. At most 256, the bound a\n caller-chosen batch carries elsewhere in this contract (see ResourceQuery.uris)\n — it bounds one submission, so a larger feed is pushed in several. The cap is\n over entries because a submission is stored or refused whole, and a refusal\n names each entry that failed; it does not bound the work of checking a\n submission, which the recipient bounds at the transport.',
        max_length=256,
        min_length=1,
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
