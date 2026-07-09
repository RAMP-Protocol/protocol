"""Agent offer-acceptance signing / verification — SUPERSEDED aliases.

The deterministic-protobuf acceptance form that used to live here is
SUPERSEDED: the platform's canonical acceptance bytes are
JCS(protojson(AgentAcceptancePayload)) — the same RFC 8785 canonicalization the
offer signature uses — implemented in :mod:`ramp_sdk.core` as
``jcs_acceptance_payload`` / ``sign_offer_acceptance_jcs`` /
``verify_offer_acceptance_jcs`` and pinned cross-language by
sdk/go/helpers/testdata/acceptance-vectors.json (``"canonicalization": "jcs"``).

This module now only ALIASES the core JCS forms so a consumer holding the old
names cannot silently pick the wrong canonicalization: the old proto-binary
bytes are gone, and calling these names produces the live JCS bytes. New code
should import the ``*_jcs`` names from :mod:`ramp_sdk.core` (or the top-level
re-exports) directly.

The typed payload surface remains the generated ``wire.models``
``AgentAcceptancePayload`` (do NOT re-declare it).
"""

from __future__ import annotations

# Reuse the generated Pydantic type for the typed surface (do NOT re-declare).
from wire.models import AgentAcceptancePayload as AgentAcceptancePayload  # noqa: PLC0414

from .core import ACCEPTANCE_SIGNATURE_ALGORITHM
from .core import (
    jcs_acceptance_payload as canonical_acceptance_payload,
)
from .core import (
    sign_offer_acceptance_jcs as sign_offer_acceptance,
)
from .core import (
    verify_offer_acceptance_jcs as verify_offer_acceptance,
)

__all__ = [
    "ACCEPTANCE_SIGNATURE_ALGORITHM",
    "AgentAcceptancePayload",
    "canonical_acceptance_payload",
    "sign_offer_acceptance",
    "verify_offer_acceptance",
]
