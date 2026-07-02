"""RAMP L1 protocol-mechanics helpers (ADR-020 tree sdk/{go,ts,python}/).

Stateless, IO-free protocol mechanics — RFC 7638 thumbprint, Ed25519 signed-URL
verify, RFC 9421 request sign/verify + GET proof-of-possession, offer-acceptance
sign/verify, and cross-field (message-CEL) validation — byte-parity-guarded
against the sdk/go oracle. Clock and key resolution are injected (ADR-020 §1/§4);
the helpers hold no state and touch no IO.
"""

from __future__ import annotations

from .acceptance import (
    canonical_acceptance_payload,
    sign_offer_acceptance,
    verify_offer_acceptance,
)
from .crossfield import cross_field_rule_ids
from .httpsig import sign_request, verify_request
from .keyresolver import KeyResolver, StaticKeyResolver
from .pop import verify_agent_binding
from .signedurl import verify_ed25519_signed_url
from .thumbprint import thumbprint

__all__ = [
    "KeyResolver",
    "StaticKeyResolver",
    "canonical_acceptance_payload",
    "cross_field_rule_ids",
    "sign_offer_acceptance",
    "sign_request",
    "thumbprint",
    "verify_agent_binding",
    "verify_ed25519_signed_url",
    "verify_offer_acceptance",
    "verify_request",
]
