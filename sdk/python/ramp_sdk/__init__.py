"""RAMP L1 protocol-mechanics helpers (ADR-020 tree sdk/{go,ts,python}/).

Stateless, IO-free protocol mechanics — RFC 7638 thumbprint, Ed25519 signed-URL
verify, RFC 9421 request sign/verify + GET proof-of-possession (both faces),
offer-acceptance sign/verify, base64url codec, and cross-field (message-CEL)
validation — byte-parity-guarded against the sdk/go oracle. Clock and key
resolution are injected (ADR-020 §1/§4); the helpers hold no state and touch no
IO.

Acceptance canonicalization is JCS (RFC 8785): the canonical names are the
``*_jcs`` forms from :mod:`ramp_sdk.core`; the unsuffixed names are aliases kept
for continuity (see :mod:`ramp_sdk.acceptance`).
"""

from __future__ import annotations

from .acceptance import (
    canonical_acceptance_payload,
    sign_offer_acceptance,
    verify_offer_acceptance,
)
from .b64 import b64url_decode, b64url_nopad
from .core import (
    ACCEPTANCE_SIGNATURE_ALGORITHM,
    OFFER_SIGNATURE_ALGORITHM,
    Mode,
    RejectedOffer,
    Result,
    VerifiedOffer,
    Verifier,
    canonical_offer_payload,
    jcs_acceptance_payload,
    sign_offer_acceptance_jcs,
    sign_offer_jcs,
    verify_offer_acceptance_jcs,
)
from .crossfield import cross_field_rule_ids
from .errordetail import (
    ERROR_DETAIL_TYPE,
    REASON_FIELDS,
    catalog_rejection_detail,
    dispute_failure_detail,
    domain_verification_failure_detail,
    error_detail_from,
    parse_error_detail,
    reason,
    registration_failure_detail,
    retrieval_auth_failure_detail,
    transaction_denial_detail,
    usage_report_rejection_detail,
)
from .hashurl import hash_url
from .httpsig import (
    MultisigVerdict,
    RejectReason,
    ReplayStore,
    append_signature,
    content_digest,
    sign_request,
    verify_multisig_request_server,
    verify_request,
    verify_request_server,
)
from .idempotency import generate_idempotency_key, validate_idempotency_key
from .keyresolver import KeyResolver, StaticKeyResolver
from .money import canonicalize_money, format_money, parse_money
from .pop import AGENT_KEY_HEADER, sign_agent_binding, verify_agent_binding
from .resolvers import (
    WBA_DIRECTORY_PATH,
    DirectoryUnavailableError,
    KeyExpiredError,
    KeyRevokedError,
    NoEndpointError,
    ResolverError,
    UnknownKeyError,
    WBAKeyResolver,
    WellKnownEndpointResolver,
    WellKnownKeyResolver,
    wba_directory_url,
)
from .scopes import apply_scopes, normalize_scopes, scopes_subset
from .signedurl import sign_ed25519_signed_url, verify_ed25519_signed_url
from .signing_transport import SignedOutbound, SigningTransport
from .thumbprint import thumbprint
from .window import Window, clock_window, monotonic_window
from .wire import (
    ConnectProtocolVersion,
    ConnectProtocolVersionHeader,
    ContentTypeJSON,
    ContentTypeProto,
    ProtocolVersion,
    RequestIDHeader,
    SignatureAgentHeader,
)

__all__ = [
    "ACCEPTANCE_SIGNATURE_ALGORITHM",
    "AGENT_KEY_HEADER",
    "ERROR_DETAIL_TYPE",
    "OFFER_SIGNATURE_ALGORITHM",
    "REASON_FIELDS",
    "WBA_DIRECTORY_PATH",
    "ConnectProtocolVersion",
    "ConnectProtocolVersionHeader",
    "ContentTypeJSON",
    "ContentTypeProto",
    "DirectoryUnavailableError",
    "KeyExpiredError",
    "KeyResolver",
    "KeyRevokedError",
    "Mode",
    "MultisigVerdict",
    "NoEndpointError",
    "ProtocolVersion",
    "RejectReason",
    "RejectedOffer",
    "ReplayStore",
    "RequestIDHeader",
    "ResolverError",
    "Result",
    "SignatureAgentHeader",
    "SignedOutbound",
    "SigningTransport",
    "StaticKeyResolver",
    "UnknownKeyError",
    "VerifiedOffer",
    "Verifier",
    "WBAKeyResolver",
    "WellKnownEndpointResolver",
    "WellKnownKeyResolver",
    "Window",
    "append_signature",
    "apply_scopes",
    "b64url_decode",
    "b64url_nopad",
    "canonical_acceptance_payload",
    "canonical_offer_payload",
    "canonicalize_money",
    "catalog_rejection_detail",
    "clock_window",
    "content_digest",
    "cross_field_rule_ids",
    "dispute_failure_detail",
    "domain_verification_failure_detail",
    "error_detail_from",
    "format_money",
    "generate_idempotency_key",
    "hash_url",
    "jcs_acceptance_payload",
    "monotonic_window",
    "normalize_scopes",
    "parse_error_detail",
    "parse_money",
    "reason",
    "registration_failure_detail",
    "retrieval_auth_failure_detail",
    "scopes_subset",
    "sign_agent_binding",
    "sign_ed25519_signed_url",
    "sign_offer_acceptance",
    "sign_offer_acceptance_jcs",
    "sign_offer_jcs",
    "sign_request",
    "thumbprint",
    "transaction_denial_detail",
    "usage_report_rejection_detail",
    "validate_idempotency_key",
    "verify_agent_binding",
    "verify_ed25519_signed_url",
    "verify_multisig_request_server",
    "verify_offer_acceptance",
    "verify_offer_acceptance_jcs",
    "verify_request",
    "verify_request_server",
    "wba_directory_url",
]
