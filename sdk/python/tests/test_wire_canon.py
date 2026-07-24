"""sdk/python wire-to-canonical offer canonicalizer.

The RAMP Connect wire emitted by the Broker is snake_case proto-JSON with
EmitUnpopulated (zero-valued scalars, empty repeateds, null messages and
``*_UNSPECIFIED`` enums all present). The offer SIGNATURE covers the CANONICAL form:
the same snake_case proto names, but omit-unpopulated, enums-as-names, then RFC 8785
JCS. Both sides share the naming, so what ``from_wire_offer`` undoes is the
zero-inflation, not the naming; it keeps the signature fields, which
``ramp_sdk.core.canonical_offer_payload`` strips on the way into JCS (hence the manual
strip in the assertions below). It belongs in sdk/python so every RAMP client (MCP
shim, future TS MCP, future Python broker) shares one wire-normalization function
proven byte-identical to the Go oracle.

Four behaviors pinned here:

(a) LEGACY camelCase TOLERANCE — ``offer_wire_camel.json`` is a PRE-FLIP capture,
    taken from the live e2e stack before the Connect wire moved to snake_case proto
    names (``UseProtoNames=true``); ``offer_canonical_go.json`` is the Go canonical
    form of the same offer. It is kept because the inversion must go on tolerating
    the retired lowerCamel form. ``from_wire_offer`` on it produces a canonical dict
    whose JCS (with ``signature``/``signature_algorithm`` stripped) equals the
    committed fixture byte-for-byte. The CURRENT wire is covered by (d).

(b) UNSPECIFIED ENUM PRUNING — a wire offer carrying
    ``deliveryMethod='DELIVERY_METHOD_UNSPECIFIED'`` must emit a canonical dict
    with the ``delivery_method`` key ABSENT (proto zero-value, omitted by canonical
    marshal). This path is NOT exercised by the fixture pair (all enums in the live
    fixture are set to real values); a synthetic wire dict drives it.

(c) SET-EMPTY OPTIONAL SCALAR PRESENCE — ``unit:""`` (an optional string set to
    the empty string) must be PRESENT in the canonical output (proto3
    presence-tracked field, not a zero-value prune). The live fixture covers this
    path (pricing.unit is ``""``), and the parity test (a) asserts it implicitly;
    this dedicated test makes the invariant explicit and survives future fixture
    rotation.

(d) DRIFT-GATED GO-ORACLE PARITY — the committed
    ``sdk/go/helpers/testdata/wire-canonical-vectors.json`` corpus, emitted by the Go
    golden emitter and replayed by Go, Python and TS. This is the authoritative
    parity for the CURRENT snake_case wire; unlike (a) it cannot go silently stale.

(b) and (c) feed camelCase synthetic dicts too, so they exercise the same tolerance
as (a). The rules they pin are naming-independent, and their snake_case twins are the
``unspecified_enum_pruned`` and ``set_empty_optional_unit`` vectors in (d).

RED now: ``ramp_sdk.wire_canon`` does not exist yet. The module-level import
below causes a collection error, which is the established red style in this suite
(mirrors test_client_binding_smoke.py and test_core_offer_verify_parity.py:
module-level import with ``type: ignore[import-not-found]`` → ImportError on
collection → pytest ERRORS = confirmed RED). The implement step adds
``sdk/python/ramp_sdk/wire_canon.py`` (exporting ``from_wire_offer``); these
tests go green with no change to the assertions.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import rfc8785
from conftest import GO_TESTDATA, load_json

# RED: ramp_sdk.wire_canon does not exist yet (TDD red).
# The implement step adds sdk/python/ramp_sdk/wire_canon.py with from_wire_offer.
from ramp_sdk.wire_canon import from_wire_offer  # type: ignore[import-not-found]

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# (a) Legacy camelCase tolerance — Go-oracle parity on the pre-flip fixture
# ---------------------------------------------------------------------------


def test_from_wire_offer_go_oracle_parity() -> None:
    """from_wire_offer(wire_camel) JCS-equals the committed Go canonical output.

    The fixture pair was captured from the LIVE e2e stack BEFORE the Connect wire
    moved to snake_case proto names: offer_wire_camel.json is a real demo offer
    exactly as the Broker's Connect codec emitted it back then (camelCase,
    EmitUnpopulated zero-inflation, ``unit:""`` set-empty optional), and
    offer_canonical_go.json is the canonical form computed by the Go side
    (protojson UseProtoNames + omit-unpopulated, then RFC 8785 JCS) — the byte
    sequence the exchange's offer signature covers.

    The wire has since flipped to snake_case, so this pair no longer describes what
    a Broker emits; it is retained as the tolerance case, pinning that a lowerCamel
    wire offer still canonicalizes correctly. Parity for the CURRENT wire is (d).

    A divergence here means from_wire_offer diverges from the Go oracle and every
    genuine offer signature would fail to verify in the Python shim.
    """
    wire = json.loads((_FIXTURES / "offer_wire_camel.json").read_text())
    want = (_FIXTURES / "offer_canonical_go.json").read_text().strip()

    canon = from_wire_offer(wire)
    stripped = {k: v for k, v in canon.items() if k not in ("signature", "signature_algorithm")}
    got = rfc8785.dumps(stripped).decode()
    assert got == want, f"canonical mismatch:\nGOT:  {got}\nWANT: {want}"


# ---------------------------------------------------------------------------
# (b) UNSPECIFIED enum pruning
# ---------------------------------------------------------------------------


def test_from_wire_offer_prunes_unspecified_enum() -> None:
    """DELIVERY_METHOD_UNSPECIFIED must be absent from the canonical dict.

    The live fixture pair does not exercise this path (all enums are real values).
    This synthetic wire dict proves the _UNSPECIFIED_ENUM regex fires and prunes
    proto zero-valued enum scalars — the canonical marshal omits them.

    The rule is self-evident from the proto3 wire semantics: a field set to the
    zero enum value (the _UNSPECIFIED sentinel) is indistinguishable from an unset
    field on the wire; the canonical form must therefore omit it.
    """
    wire_unspecified: dict[str, object] = {
        "offerId": "test:unspecified",
        "deliveryMethod": "DELIVERY_METHOD_UNSPECIFIED",
        "exchange": "exchange.example",
        "expiresAt": "2026-07-06T00:00:00Z",
    }
    canon = from_wire_offer(wire_unspecified)
    assert "delivery_method" not in canon, (
        f"DELIVERY_METHOD_UNSPECIFIED must be absent from canonical output; "
        f"got delivery_method={canon.get('delivery_method')!r}"
    )


# ---------------------------------------------------------------------------
# (c) Set-empty optional scalar presence
# ---------------------------------------------------------------------------


def test_from_wire_offer_keeps_set_empty_optional_scalar() -> None:
    """unit:'' (proto3 optional set to empty string) must survive canonicalization.

    proto3 presence semantics: a field declared ``optional`` tracks presence
    separately from value. An optional string set to ``""`` is SET (wire-present);
    the canonical form keeps it. A non-optional string at ``""`` is zero and is
    pruned. ``pricing.unit`` is an optional field; ``""`` must appear in output.

    The live fixture covers this implicitly (parity test (a)); this dedicated test
    makes the invariant explicit so it survives future fixture rotation.
    """
    wire_with_unit: dict[str, object] = {
        "offerId": "test:unit-present",
        "deliveryMethod": "DELIVERY_METHOD_INSTRUCTIONS",
        "exchange": "exchange.example",
        "expiresAt": "2026-07-06T00:00:00Z",
        "pricing": {
            "model": "PRICING_MODEL_FREE",
            "rate": "0",
            "currency": "EUR",
            "unitCost": "0",
            "unit": "",
        },
    }
    canon = from_wire_offer(wire_with_unit)
    pricing = canon.get("pricing")
    assert isinstance(pricing, dict), (
        f"pricing must be present in canonical output; got {pricing!r}"
    )
    assert "unit" in pricing, (
        f"pricing.unit='' (set-empty optional) must be kept in canonical output; "
        f"got pricing={pricing!r}"
    )
    assert pricing["unit"] == "", (
        f"pricing.unit must be '' (empty string) in canonical output; "
        f"got pricing.unit={pricing['unit']!r}"
    )


# ---------------------------------------------------------------------------
# (d) Drift-gated Go-oracle vectors (authoritative parity)
# ---------------------------------------------------------------------------

_WIRE_CANONICAL_DOC = load_json(GO_TESTDATA / "wire-canonical-vectors.json")
_WIRE_CANONICAL_VECTORS = _WIRE_CANONICAL_DOC["vectors"]


def test_wire_canonical_vector_matrix_present() -> None:
    """The drift-gated matrix covers the pruning rules, not just a happy path."""
    names = {str(v["name"]) for v in _WIRE_CANONICAL_VECTORS}
    assert {
        "unspecified_enum_pruned",
        "set_empty_optional_unit",
        "struct_ext_multi_key",
        "two_timestamps",
        "repeated_terms_enum",
    } <= names


@pytest.mark.parametrize(
    "vector", _WIRE_CANONICAL_VECTORS, ids=[v["name"] for v in _WIRE_CANONICAL_VECTORS]
)
def test_from_wire_offer_matches_go_vector(vector: dict[str, object]) -> None:
    """from_wire_offer(wire_json) JCS-equals the Go canonical_json byte-for-byte.

    Unlike the live-captured fixture pair in (a), these vectors are emitted by the
    drift-gated Go golden emitter (gen_vectors_test.go TestGenerateVectors): a
    proto change that shifts either the wire emission or the canonical form
    re-flows into the committed file, so this parity can never go silently stale.
    """
    wire = vector["wire_json"]
    assert isinstance(wire, dict)
    canon = from_wire_offer(wire)
    stripped = {k: v for k, v in canon.items() if k not in ("signature", "signature_algorithm")}
    got = rfc8785.dumps(stripped).decode()
    want = rfc8785.dumps(vector["canonical_json"]).decode()
    assert got == want, f"{vector['name']}: canonical mismatch:\nGOT:  {got}\nWANT: {want}"
