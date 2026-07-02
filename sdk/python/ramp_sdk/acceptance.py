"""Agent offer-acceptance signing / verification (RAMP-102 §1) — pure L1 helper.

Relocated from the app MCP shim (src/mcp/src/ramp_mcp_shim/acceptance.py). The
agent detached-signs an accepted Offer so the Exchange can bind the agent to the
transaction. The signed bytes are the proto3 deterministic marshal of
``AgentAcceptancePayload`` (offer_sig=1, requester_id=2, requester_domain=3,
idempotency_key=4) and the signature is the hex-encoded Ed25519 over those bytes
(``signature_algorithm = "EdDSA"``).

This MUST stay byte-identical to the Go oracle (``helpers.SignOfferAcceptance`` +
``proto.MarshalOptions{Deterministic}``, sdk/go/helpers/acceptance.go), pinned
cross-language by the shared sdk/go/helpers/testdata/acceptance-vectors.json. The
canonical payload is hand-rolled here because the published ``gen/python`` is
Pydantic-only with no proto serializer; the typed surface reuses the generated
``AgentAcceptancePayload`` (do NOT re-declare it), but the canonical BYTES stay
hand-rolled. proto3 omits an empty-string field entirely (default-skip).

Fail-closed on an empty ``offer_sig`` (mirror Go ``canonicalAcceptancePayload``):
an empty anchor would let the acceptance float free of any concrete offer.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Reuse the generated Pydantic type for the typed surface (do NOT re-declare).
from wire.models import AgentAcceptancePayload

# Proto field numbers of AgentAcceptancePayload (ramp.proto), in ascending order
# — the deterministic marshal emits them low-to-high.
_FIELD_OFFER_SIG = 1
_FIELD_REQUESTER_ID = 2
_FIELD_REQUESTER_DOMAIN = 3
_FIELD_IDEMPOTENCY_KEY = 4

# proto3 LEN wire type (length-delimited): tag = (field_number << 3) | 2.
_WIRE_TYPE_LEN = 2

# The acceptance alg advertised on AgentAcceptance — always EdDSA for Ed25519
# (mirrors helpers.AcceptanceSignatureAlgorithm).
ACCEPTANCE_SIGNATURE_ALGORITHM = "EdDSA"


def _varint(value: int) -> bytes:
    """Encode a non-negative int as a protobuf base-128 varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _len_field(field_number: int, value: str) -> bytes:
    """Encode one length-delimited string field, or nothing when empty.

    proto3 omits a default-valued (empty) string entirely, so an empty value
    contributes zero bytes. The length prefix is the UTF-8 byte count.
    """
    raw = value.encode("utf-8")
    if not raw:
        return b""
    tag = (field_number << 3) | _WIRE_TYPE_LEN
    return bytes([tag]) + _varint(len(raw)) + raw


def canonical_acceptance_payload(
    *,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> bytes:
    """Deterministic proto3 marshal of ``AgentAcceptancePayload``.

    Byte-identical to the Go SDK's ``proto.MarshalOptions{Deterministic}.Marshal``.
    Fail-closed on an empty ``offer_sig``.
    """
    if not offer_sig:
        msg = "cannot accept an unsigned offer (empty offer signature)"
        raise ValueError(msg)
    # Type the surface with the generated model (validates field presence/shape);
    # the wire bytes stay hand-rolled below.
    _typed = AgentAcceptancePayload(
        offerSig=offer_sig,
        requesterId=requester_id,
        requesterDomain=requester_domain,
        idempotencyKey=idempotency_key,
    )
    return b"".join(
        (
            _len_field(_FIELD_OFFER_SIG, _typed.offerSig or ""),
            _len_field(_FIELD_REQUESTER_ID, _typed.requesterId or ""),
            _len_field(_FIELD_REQUESTER_DOMAIN, _typed.requesterDomain or ""),
            _len_field(_FIELD_IDEMPOTENCY_KEY, _typed.idempotencyKey or ""),
        )
    )


def sign_offer_acceptance(
    *,
    seed: bytes,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> tuple[str, str]:
    """Sign the canonical acceptance payload; return ``(signature_hex, "EdDSA")``.

    ``hex(ed25519.Sign(seed, canonical_bytes))`` — byte-identical to
    ``helpers.SignOfferAcceptance``. Raises on an empty ``offer_sig``.
    """
    payload = canonical_acceptance_payload(
        offer_sig=offer_sig,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
    )
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.sign(payload).hex(), ACCEPTANCE_SIGNATURE_ALGORITHM


def verify_offer_acceptance(
    *,
    pubkey_b64: str,
    signature_hex: str,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> bool:
    """Verify ``signature_hex`` over the canonical payload against ``pubkey_b64``.

    ``pubkey_b64`` is STANDARD base64 (as the shared vectors record it). Returns
    False on any mismatch; raises on an empty ``offer_sig`` (fail-closed).
    """
    payload = canonical_acceptance_payload(
        offer_sig=offer_sig,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
    )
    pub = base64.b64decode(pubkey_b64)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature_hex), payload)
    except (InvalidSignature, ValueError):
        return False
    return True
