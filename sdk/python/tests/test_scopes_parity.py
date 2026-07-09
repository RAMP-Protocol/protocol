"""Scopes parity (Python side) — TDD red for djeue.

Mirrors the sdk/ts sibling sdk/ts/tests/scopes.parity.test.ts.

``ramp_sdk.scopes.normalize_scopes``/``scopes_subset`` MUST reproduce the sdk/go
oracle byte-for-byte. The shared vectors at
sdk/go/helpers/testdata/scopes-vectors.json carry:
  - normalize: {input:[str], normalized:[str]|null}  (Go returns nil → JSON null
    for empty/all-empty input, R5 — the comparator treats null == []).
  - subset:    {sub:[str], super:[str], expected:bool}.

RED now purely because ``ramp_sdk.scopes`` does not exist yet (the import below
cannot resolve → collection error). The implement step adds that module.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/scopes.py does not exist yet (TDD red — missing face).
from ramp_sdk.scopes import normalize_scopes, scopes_subset  # type: ignore[import-not-found]

_VECTORS = load_json(GO_TESTDATA / "scopes-vectors.json")
_NORMALIZE = _VECTORS["normalize"]
_SUBSET = _VECTORS["subset"]


def test_scopes_vector_sets_nonempty() -> None:
    assert len(_NORMALIZE) > 0
    assert len(_SUBSET) > 0


@pytest.mark.parametrize("vector", _NORMALIZE, ids=[v["name"] for v in _NORMALIZE])
def test_normalize_matches_go_oracle(vector: dict) -> None:
    # R5: Go emits null for empty/all-empty; the Python face returns []. Coalesce
    # so the empty-input vector matches.
    want = vector["normalized"] or []
    assert normalize_scopes(list(vector["input"])) == want


@pytest.mark.parametrize("vector", _SUBSET, ids=[v["name"] for v in _SUBSET])
def test_subset_matches_go_oracle(vector: dict) -> None:
    sub = vector["sub"] or []
    sup = vector["super"] or []
    assert scopes_subset(list(sub), list(sup)) is vector["expected"]
