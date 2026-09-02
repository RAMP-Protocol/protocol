from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json
from ramp_sdk.core import (
    jcs_request_acceptance_payload,
    sign_request_acceptance_jcs,
    verify_request_acceptance_jcs,
)

_DOC = load_json(GO_TESTDATA / "request-acceptance-vectors.json")
_VECTORS = _DOC["vectors"]


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_request_acceptance_matches_go_oracle(vector: dict[str, object]) -> None:
    items = [
        (str(item["offer_sig"]), str(item["exchange"]))
        for item in vector["items"]  # type: ignore[union-attr]
    ]
    kwargs = {
        "items": items,
        "requester_id": str(vector["requester_id"]),
        "requester_domain": str(vector["requester_domain"]),
        "idempotency_key": str(vector["idempotency_key"]),
    }
    assert jcs_request_acceptance_payload(**kwargs).decode() == vector["canonical_jcs"]
    signature, algorithm = sign_request_acceptance_jcs(
        seed=bytes.fromhex(str(vector["seed_hex"])), **kwargs
    )
    assert algorithm == "EdDSA"
    assert signature == vector["signature_hex"]
    assert verify_request_acceptance_jcs(
        pubkey_b64=str(vector["pubkey_b64"]),
        signature_hex=str(vector["signature_hex"]),
        **kwargs,
    )


def test_request_acceptance_order_is_signed() -> None:
    vector = _VECTORS[0]
    items = [
        (str(item["offer_sig"]), str(item["exchange"]))
        for item in vector["items"]
    ]
    assert not verify_request_acceptance_jcs(
        pubkey_b64=str(vector["pubkey_b64"]),
        signature_hex=str(vector["signature_hex"]),
        items=list(reversed(items)),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
