"""Money parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/money.parity.test.ts.

``ramp_sdk.money.canonicalize_money`` MUST reproduce the sdk/go oracle
byte-for-byte. The shared vectors at sdk/go/helpers/testdata/money-vectors.json
carry {input, canonical, valid} derived from Go CanonicalizeMoney (Parse+Format).

The load-bearing cases: Go drops leading zeros (007→7, 00.5→0.5,
0010.20→10.2, 000→0) AND never emits scientific notation for a high-precision
small fraction (0.0000001 stays plain — where str(Decimal('0.0000001')) would
give '1E-7'). The Python face MUST use plain formatting (format(d,'f')), not
str(d). Invalid inputs (empty, negative, leading '+', '1e3', '.5') MUST raise.

RED now purely because ``ramp_sdk.money`` does not exist yet (collection error).
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/money.py does not exist yet (TDD red — missing face).
from ramp_sdk.money import canonicalize_money  # type: ignore[import-not-found]

_VECTORS = load_json(GO_TESTDATA / "money-vectors.json")["vectors"]
_VALID = [v for v in _VECTORS if v["valid"]]
_INVALID = [v for v in _VECTORS if not v["valid"]]


def test_money_vector_set_nonempty() -> None:
    assert len(_VALID) > 0
    assert len(_INVALID) > 0


@pytest.mark.parametrize("vector", _VALID, ids=[v["name"] for v in _VALID])
def test_canonicalize_matches_go_oracle(vector: dict) -> None:
    assert canonicalize_money(vector["input"]) == vector["canonical"]


@pytest.mark.parametrize("vector", _INVALID, ids=[v["name"] for v in _INVALID])
def test_canonicalize_rejects_invalid_wire_money(vector: dict) -> None:
    with pytest.raises(Exception):  # noqa: B017 — surface choice is the port's
        canonicalize_money(vector["input"])
