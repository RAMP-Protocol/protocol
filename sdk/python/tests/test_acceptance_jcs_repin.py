"""Acceptance sign/verify RE-PIN to RFC 8785 JCS.

This re-pin moves BOTH signed payloads (offer AND
acceptance) off Go deterministic protobuf-binary onto RFC 8785 JCS over canonical
proto-JSON:

    signed_payload = JCS(protojson(msg with sig/sig_algorithm cleared))

For acceptance this changes Go canonicalAcceptancePayload (acceptance.go) from the
hand-rolled proto3 field-tag marshal (today's acceptance-vectors.json carries
`canonical_bytes_hex` beginning `0a10…` — proto field tags) to JCS UTF-8 bytes.
The Go golden emitter therefore REGENERATES acceptance-vectors.json to the JCS form
(new canonical bytes AND new signatures — the canonicalization itself changed, so
this is the intended vector change, NOT a behavior-preservation violation).

This re-pin suite asserts the Python core canonicalizes acceptance via JCS and
produces byte-identical canonical bytes + signature to the REGENERATED Go oracle.
It is RED now for TWO expected reasons:
  1. sdk/python/ramp_sdk/core (the JCS acceptance canonicalizer + sign/verify) does
     not exist yet.
  2. The regenerated acceptance vectors do not exist yet — today's
     acceptance-vectors.json is still the protobuf-binary form (no `canonical_jcs`
     field, no `canonicalization: "jcs"` marker). The assertions below require the
     JCS-regenerated shape, so they FAIL against the current file (and the import
     fails outright), a clean TDD-red signal.

Note: this is the acceptance sibling of test_core_offer_verify_parity.py; the two
prove Go/TS/Python agree on the SAME JCS canonicalization for both signed payloads.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: the JCS acceptance canonicalizer + sign/verify live in the new core (do NOT
# reuse the L1 protobuf-binary canonical_acceptance_payload — that is the OLD form).
from ramp_sdk.core import (  # type: ignore[import-not-found]
    jcs_acceptance_payload,
    sign_offer_acceptance_jcs,
    verify_offer_acceptance_jcs,
)

# The shared, REGENERATED (JCS-form) acceptance vectors. The implement step's Go
# emitter (JCS canonicalization) rewrites this file; the assertions below require
# the JCS shape, keeping this suite RED against the current protobuf-binary file.
_ACCEPTANCE_VECTORS_PATH = GO_TESTDATA / "acceptance-vectors.json"
_DOC = load_json(_ACCEPTANCE_VECTORS_PATH)
_VECTORS = _DOC["vectors"]

_SHARED_SEED_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"


def test_acceptance_vectors_declare_jcs_canonicalization() -> None:
    # The regenerated file MUST declare its canonicalization so a reader cannot
    # confuse it with the old protobuf-binary form. RED against today's file, which
    # carries no such marker.
    assert _DOC.get("canonicalization") == "jcs"


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_acceptance_canonical_bytes_are_jcs(vector: dict[str, object]) -> None:
    # The JCS canonical bytes are UTF-8 JSON (RFC 8785), NOT proto3 field tags. The
    # regenerated vectors carry `canonical_jcs` (the exact JCS string); the Python
    # core reproduces it byte-for-byte.
    payload = jcs_acceptance_payload(
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert payload.decode("utf-8") == str(vector["canonical_jcs"])


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_acceptance_sign_matches_regenerated_go_oracle(vector: dict[str, object]) -> None:
    signature_hex, algorithm = sign_offer_acceptance_jcs(
        seed=bytes.fromhex(_SHARED_SEED_HEX),
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert algorithm == "EdDSA"
    # The regenerated signature over the JCS bytes — DIFFERENT from the current
    # protobuf-binary signature_hex, so this FAILS against today's file.
    assert signature_hex == str(vector["signature_hex"])


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_acceptance_verify_accepts_regenerated_signature(vector: dict[str, object]) -> None:
    ok = verify_offer_acceptance_jcs(
        pubkey_b64=str(vector["pubkey_b64"]),
        signature_hex=str(vector["signature_hex"]),
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert ok is True
