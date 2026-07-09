"""Idempotency-validate parity (Python side) — TDD red for djeue.

Mirrors the sdk/ts sibling sdk/ts/tests/idempotency-validate.parity.test.ts.

``ramp_sdk.idempotency.validate_idempotency_key`` MUST reproduce the sdk/go
oracle: the ONLY rule is non-empty (protocol min_len=1). The shared vectors at
sdk/go/helpers/testdata/idempotency-validate-vectors.json carry {key, valid}.
A valid key returns (does not raise); an empty key raises.

NOTE: new_idempotency_key MINT is random → NOT vector-gated (behaviour-tested in
test_idempotency_behavior.py). This suite covers the pure VALIDATE face only.

RED now purely because ``ramp_sdk.idempotency`` does not exist yet.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/idempotency.py does not exist yet (TDD red).
from ramp_sdk.idempotency import validate_idempotency_key  # type: ignore[import-not-found]

_VECTORS = load_json(GO_TESTDATA / "idempotency-validate-vectors.json")["vectors"]
_VALID = [v for v in _VECTORS if v["valid"]]
_INVALID = [v for v in _VECTORS if not v["valid"]]


def test_idempotency_validate_vector_set_nonempty() -> None:
    assert len(_VALID) > 0
    assert len(_INVALID) > 0


@pytest.mark.parametrize("vector", _VALID, ids=[v["name"] for v in _VALID])
def test_validate_accepts_valid_key(vector: dict) -> None:
    # Returns without raising for a non-empty key.
    validate_idempotency_key(vector["key"])


@pytest.mark.parametrize("vector", _INVALID, ids=[v["name"] for v in _INVALID])
def test_validate_rejects_empty_key(vector: dict) -> None:
    with pytest.raises(Exception):  # noqa: B017 — surface choice is the port's
        validate_idempotency_key(vector["key"])
