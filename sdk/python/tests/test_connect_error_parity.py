"""Connect error-envelope parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors the sdk/ts sibling sdk/ts/tests/connect-error.parity.test.ts and the Go leg
sdk/go/connect/connect_error_corpus_test.go.

``error-detail-vectors.json`` pins the DETAIL's own proto-JSON. This corpus pins the
ENVELOPE the detail arrives in, which is the form this SDK actually reads: with no
protobuf binary codec it cannot open a detail's ``value`` (a base64 Any), so Connect's
``debug`` projection is the only decodable copy.

That projection is lowerCamelCase and no server option changes it — connect-go builds it
with its own protojson codec at default options — while the response bodies the same
server emits are snake_case. Reading ``debug`` with a snake-only model therefore used to
return a detail carrying ``domain`` and ``message`` (single words spell the same either
way) and NO typed reason, for a refusal the Exchange had named precisely. The failure was
silent: the parse succeeded, and the unknown reason block was dropped by the
forward-compatible ``extra="ignore"`` policy that exists for a newer protocol version.

Every vector here was CAPTURED from a real connect-go handler, so the fix is asserted
against what the wire does rather than against a description of it.
"""

from __future__ import annotations

import pytest

from conftest import GO_CONNECT_TESTDATA, load_json
from ramp_sdk.errordetail import error_detail_from, reason

_VECTORS = load_json(GO_CONNECT_TESTDATA / "connect-error-vectors.json")["vectors"]


def test_connect_error_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_reader_extracts_go_projection_from_the_envelope(vector: dict) -> None:
    detail = error_detail_from(vector["envelope"])
    expect = vector["expect"]

    if not expect["has_detail"]:
        assert detail is None, "an envelope carrying no ErrorDetail must read as none"
        return

    assert detail is not None, (
        "no ErrorDetail extracted from an envelope that carries one — the reader is "
        "looking at the wrong member, or the debug projection was not decoded"
    )
    assert detail.domain == expect["domain"]
    assert detail.message == expect["message"]

    # Metadata keys are the EMITTER's, not the proto's. The corpus carries a
    # deliberately lowerCamelCase key so a normalizer that walked into the map would
    # rewrite it and fail here.
    assert (detail.metadata or {}) == (expect["metadata"] or {})

    got = reason(detail)
    if not expect["reason_field"]:
        assert got is None, f"reader invented a reason ({got}) the oracle does not report"
        return
    assert got is not None, (
        f"reader lost the typed reason {expect['reason_enum']} the Exchange sent — "
        "a fail-open read of the one field a caller branches on"
    )
    assert got.value == expect["reason_enum"]
    block = getattr(detail, expect["reason_field"])
    assert block is not None, (
        f"reason arrived under a different oneof member than {expect['reason_field']!r}"
    )


def test_camel_case_debug_projection_is_decoded() -> None:
    """The regression itself, stated once in the open rather than only via the corpus.

    A snake-only read of this envelope parses successfully and reports no reason — which
    is why nothing caught it before the corpus existed.
    """
    envelope = {
        "code": "permission_denied",
        "message": "balance too low",
        "details": [
            {
                "type": "ramp.v1.ErrorDetail",
                "value": "aWdub3JlZA",
                "debug": {
                    "domain": "ramp.v1.ExchangeService",
                    "message": "balance too low",
                    "transactionDenial": {"reason": "DENIAL_REASON_INSUFFICIENT_BALANCE"},
                },
            }
        ],
    }
    detail = error_detail_from(envelope)
    assert detail is not None
    got = reason(detail)
    assert got is not None and got.value == "DENIAL_REASON_INSUFFICIENT_BALANCE"
