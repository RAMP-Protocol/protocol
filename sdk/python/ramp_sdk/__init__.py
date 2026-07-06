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
    jcs_acceptance_payload,
    sign_offer_acceptance_jcs,
    verify_offer_acceptance_jcs,
)
from .crossfield import cross_field_rule_ids
from .httpsig import sign_request, verify_request
from .keyresolver import KeyResolver, StaticKeyResolver
from .pop import sign_agent_binding, verify_agent_binding
from .signedurl import verify_ed25519_signed_url
from .thumbprint import thumbprint

__all__ = [
    "KeyResolver",
    "StaticKeyResolver",
    "b64url_decode",
    "b64url_nopad",
    "canonical_acceptance_payload",
    "cross_field_rule_ids",
    "jcs_acceptance_payload",
    "sign_agent_binding",
    "sign_offer_acceptance",
    "sign_offer_acceptance_jcs",
    "sign_request",
    "thumbprint",
    "verify_agent_binding",
    "verify_ed25519_signed_url",
    "verify_offer_acceptance",
    "verify_offer_acceptance_jcs",
    "verify_request",
]
