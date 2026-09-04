"""Wire-constants parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/wire.parity.test.ts.

``ramp_sdk.wire`` MUST expose the seven wire constants with the EXACT values the
sdk/go oracle carries. The shared vectors at
sdk/go/helpers/testdata/wire-constants-vectors.json carry {name, value},
referenced from the real Go exported constants (never hand-typed). The Go layer
splits RequestIDHeader across helpers/constants.go and core/requestid.go; the
single Python wire module exposes all seven once.

RED now purely because ``ramp_sdk.wire`` does not exist yet.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/wire.py does not exist yet (TDD red — missing face).
from ramp_sdk import wire  # type: ignore[import-not-found]

_VECTORS = load_json(GO_TESTDATA / "wire-constants-vectors.json")["vectors"]

# Go identifier → the attribute the Python wire module must expose (same name).
_ATTR_FOR = {
    "ContentTypeProto": "ContentTypeProto",
    "ContentTypeJSON": "ContentTypeJSON",
    "ConnectProtocolVersionHeader": "ConnectProtocolVersionHeader",
    "ConnectProtocolVersion": "ConnectProtocolVersion",
    "ProtocolVersion": "ProtocolVersion",
    "WellKnownManifestVersion": "WellKnownManifestVersion",
    "RequestIDHeader": "RequestIDHeader",
    "SignatureAgentHeader": "SignatureAgentHeader",
}


def test_wire_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_wire_constant_matches_go_oracle(vector: dict) -> None:
    attr = _ATTR_FOR[vector["name"]]
    assert getattr(wire, attr) == vector["value"]
