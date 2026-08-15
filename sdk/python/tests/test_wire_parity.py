"""Wire-constants parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/wire.parity.test.ts.

Every constant in the shared vector file
sdk/go/helpers/testdata/wire-constants-vectors.json MUST be reachable from the
``ramp_sdk`` package root with the EXACT value the sdk/go oracle carries. The
vectors carry {name, value} and are referenced from the real Go exported
constants, never hand-typed.

SCOPE IS DERIVED, NOT LISTED. The Go identifier and the Python identifier do not
always match: the wire constants keep their Go spelling, while the two signature
algorithms are ``OFFER_SIGNATURE_ALGORITHM`` and
``ACCEPTANCE_SIGNATURE_ALGORITHM`` and live in ``ramp_sdk.core``. That
translation is already maintained in sdk/parity/symbol-map.json for the
API-surface gate, so this suite reads it from there.

An earlier version kept a private Go-name -> attribute map instead. That made
the check opt-in: a vector with no entry raised a KeyError naming the map rather
than reporting an unported constant, and two vectors did exactly that. Reading
the mapping from the shared file makes it opt-out — a new vector must be mapped
and ported, and it cannot pass by being unlisted.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, SYMBOL_MAP, load_json

import ramp_sdk
from ramp_sdk import wire

_VECTORS = load_json(GO_TESTDATA / "wire-constants-vectors.json")["vectors"]


def _python_names() -> dict[str, str]:
    """Bare Go identifier -> the Python name symbol-map.json pins it to.

    Keys in the map are package-qualified (``helpers.ProtocolVersion``), while a
    vector names the bare identifier. One identifier can appear under two
    packages — the Go layer defines RequestIDHeader in both helpers and core —
    so agreeing duplicates collapse to one entry and a disagreement is an error
    worth failing on rather than picking a winner.
    """
    resolved: dict[str, str] = {}
    for qualified, entry in load_json(SYMBOL_MAP)["symbols"].items():
        bare = qualified.rsplit(".", 1)[-1]
        python_name = entry.get("python")
        if python_name is None:
            continue
        if bare in resolved and resolved[bare] != python_name:
            raise AssertionError(
                f"symbol-map.json maps {bare} to two different Python names: "
                f"{resolved[bare]!r} and {python_name!r}"
            )
        resolved[bare] = python_name
    return resolved


_PYTHON_NAME = _python_names()


def test_wire_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_every_vector_is_mapped(vector: dict) -> None:
    """A vector with no Python mapping is an unported constant, not a skip."""
    assert vector["name"] in _PYTHON_NAME, (
        f"{vector['name']} has a wire-constant vector but no Python symbol in "
        "sdk/parity/symbol-map.json — port it and map it, or drop the vector."
    )


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_wire_constant_matches_go_oracle(vector: dict) -> None:
    name = _PYTHON_NAME.get(vector["name"])
    # test_every_vector_is_mapped reports the unmapped case; repeat the check
    # here so this test fails with a sentence instead of a raw KeyError.
    assert name is not None, (
        f"{vector['name']} has no Python symbol in sdk/parity/symbol-map.json"
    )
    assert hasattr(ramp_sdk, name), (
        f"{vector['name']} maps to {name}, which the ramp_sdk root does not "
        "export"
    )
    assert getattr(ramp_sdk, name) == vector["value"]


def test_wire_module_constants_match_their_vectors() -> None:
    """The wire module is the home of the constants that kept their Go names.

    Derived rather than listed: every public name the module defines that also
    has a vector must carry the vector's value. So the module cannot drift, and
    it cannot quietly lose a constant to a rename without the vector check above
    failing too.
    """
    by_name = {v["name"]: v["value"] for v in _VECTORS}
    checked = 0
    for attr in dir(wire):
        if attr.startswith("_") or attr not in by_name:
            continue
        assert getattr(wire, attr) == by_name[attr]
        checked += 1
    assert checked > 0, "ramp_sdk.wire exposes none of the vectored constants"
