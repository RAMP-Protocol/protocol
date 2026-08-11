"""ErrorDetail parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors the sdk/ts sibling sdk/ts/tests/errordetail.parity.test.ts and the Go leg
sdk/go/helpers/errordetail_corpus_test.go.

The ADR-019 failure envelope — ErrorDetail{domain, message, metadata, typed reason
oneof} — was, until the shared corpus, built AND read only in sdk/go. The mcp shim
is the READ side of that contract. ``error-detail-vectors.json`` carries, per
vector, the canonical proto-JSON wire form (``wire_json``) plus the field
projection a reader MUST extract (domain, message, metadata, reason_field,
reason_enum), all DERIVED from the real Go faces.

This suite parses each vector's ``wire_json`` through the Python reader
(``parse_error_detail`` → the generated ``wire.models.ErrorDetail`` model) and
asserts the extracted projection matches the Go oracle byte-for-byte-in-meaning:
same domain/message, same metadata map (order-independent — metadata is an
unordered map, which is exactly why the multi-key vector exists), and the same
typed reason (oneof field + enum NAME) via the ``reason`` accessor. A divergence in
Python's ErrorDetail decoding fails here, at the replay boundary.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED before the reader exists: ramp_sdk.errordetail is a missing module (collection error).
from ramp_sdk.errordetail import (  # type: ignore[import-not-found]
    REASON_FIELDS,
    error_detail_from,
    parse_error_detail,
    reason,
)

_VECTORS = load_json(GO_TESTDATA / "error-detail-vectors.json")["vectors"]


def test_errordetail_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_reader_extracts_go_projection(vector: dict) -> None:
    detail = parse_error_detail(vector["wire_json"])

    assert (detail.domain or "") == vector["domain"]
    assert (detail.message or "") == vector["message"]

    # metadata is an unordered map; a nil map and an empty map are equal (proto3
    # omits an empty map on the wire, so wire_json may carry no metadata key).
    assert (detail.metadata or {}) == (vector["metadata"] or {})

    if vector["reason_field"] == "":
        assert reason(detail) is None
        assert all(getattr(detail, f, None) is None for f in REASON_FIELDS)
    else:
        # Exactly the recorded oneof member is populated, and only it.
        populated = [f for f in REASON_FIELDS if getattr(detail, f, None) is not None]
        assert populated == [vector["reason_field"]]
        got = reason(detail)
        assert got is not None
        assert got.value == vector["reason_enum"]

    # The RegistrationFailure per-member detail, positionally. The empty path is the
    # boundary a decoder most plausibly gets wrong: proto3 omits an empty string, so
    # wire_json carries an entry with no "path" key at all and a reader must still
    # extract "" rather than dropping or shifting the entry.
    want_field_errors = vector.get("field_errors") or []
    got_field_errors = getattr(detail.registration_failure, "field_errors", None) or []
    assert [
        {"path": fe.path or "", "error": fe.error} for fe in got_field_errors
    ] == want_field_errors


def test_error_detail_from_locates_detail_among_connect_error_details() -> None:
    """The ErrorDetailFrom-contract analog: find the ramp.v1.ErrorDetail in a
    Connect error's details array (skipping foreign details) and parse it."""
    vector = next(v for v in _VECTORS if v["reason_field"] == "transaction_denial")
    connect_error = {
        "code": "failed_precondition",
        "message": vector["message"],
        "details": [
            {"type": "google.rpc.RetryInfo", "debug": {"retry_delay": "1s"}},
            {"type": "ramp.v1.ErrorDetail", "debug": vector["wire_json"]},
        ],
    }
    detail = error_detail_from(connect_error)
    assert detail is not None
    assert detail.domain == vector["domain"]
    got = reason(detail)
    assert got is not None
    assert got.value == vector["reason_enum"]


def test_error_detail_from_returns_none_without_ramp_detail() -> None:
    assert error_detail_from({"code": "internal", "details": []}) is None
    assert error_detail_from([{"type": "google.rpc.RetryInfo", "debug": {}}]) is None
