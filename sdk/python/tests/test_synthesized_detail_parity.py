"""Synthesized-detail parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors ``sdk/ts/tests/synthesized-detail.parity.test.ts`` and the Go leg
``sdk/go/connect/synthesized_detail_corpus_test.go``.

Decoding a peer's ErrorDetail is already pinned elsewhere. These two details are
different: nothing on the wire says what they should contain, so the domain, the sentence
and the typed reason are AUTHORED — three times, in three languages, from three copies of
one decision. That is the shape that drifts silently, and it had: this port derived each
edge reason's enum name by uppercasing the token, which is right for two of the eleven
tokens the protocol records and wrong for the rest, so nine real edge refusals carried a
typed reason in Go and none here.

Field errors are compared by PATH and never by text. The constraint prose comes from a
different validator library in each language and the contract calls it non-authoritative,
so pinning it here would pin an accident.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from test_client import FACES, Face, _IDS, _config  # noqa: PLC2701

from conftest import GO_CONNECT_TESTDATA, load_json
import ramp_sdk.sync as sync_client
from ramp_sdk.client import Client
from ramp_sdk.client.errors import CallError, CallErrorKind
from ramp_sdk.errordetail import REASON_FIELDS, reason
from ramp_sdk.regschema import compile_registration_schema
from ramp_sdk.resolvers import RegistrationRequirements

_CORPUS = load_json(GO_CONNECT_TESTDATA / "synthesized-detail-vectors.json")
_PRECHECK = _CORPUS["registration_precheck"]
_EDGE = _CORPUS["edge_refusal"]

_ENDPOINT = "https://exchange.test"


class _Resolver:
    def resolve_endpoint(self, _host: str) -> str:
        return _ENDPOINT


class _Requirements:
    def __init__(self, reqs: RegistrationRequirements) -> None:
        self._reqs = reqs

    def resolve_registration_requirements(self, _exchange: str) -> RegistrationRequirements:
        return self._reqs


def _refuse(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
    raise AssertionError("the pre-check refusal must never reach the wire")


def _assert_recorded_detail(err: CallError, vector: dict[str, Any]) -> None:
    """The detail matches what the oracle recorded for this row."""
    detail = err.detail
    assert detail is not None
    assert (detail.domain or "") == vector["domain"]
    assert (detail.message or "") == vector["message"]
    # Exactly the recorded oneof member is populated, and only it.
    populated = [f for f in REASON_FIELDS if getattr(detail, f, None) is not None]
    assert populated == [vector["reason_field"]]
    got = reason(detail)
    assert got is not None
    assert got.value == vector["reason_enum"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("vector", _PRECHECK, ids=[v["name"] for v in _PRECHECK])
def test_the_registration_pre_check_detail_matches_the_oracle(
    vector: dict[str, Any], face: Face
) -> None:
    schema, verdict = compile_registration_schema(vector["schema"].encode())
    assert verdict == "accepted", "the row's own schema does not compile"
    config = _config(
        endpoint_resolver=_Resolver(),
        registration_requirements=_Requirements(
            RegistrationRequirements(schema=schema, verdict=verdict)
        ),
    )
    transport = httpx.MockTransport(_refuse)
    client = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )

    with pytest.raises(CallError) as caught:
        face.run(
            client.register(
                {"exchange": "exchange.test", "registration_data": vector["data"]}
            )
        )

    err = caught.value
    assert err.kind is CallErrorKind.MALFORMED
    _assert_recorded_detail(err, vector)
    failure = err.detail.registration_failure  # type: ignore[union-attr]
    assert [f.path or "" for f in failure.field_errors or []] == vector["field_error_paths"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("vector", _EDGE, ids=[v["name"] for v in _EDGE])
def test_the_content_leg_detail_matches_the_oracle(
    vector: dict[str, Any], face: Face
) -> None:
    token = vector["reason_token"]

    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(403, json={"error": "denied", "reason": token})

    transport = httpx.MockTransport(respond)
    config = _config()
    client = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )

    with pytest.raises(CallError) as caught:
        face.run(client.fetch("https://edge.test/doc"))

    err = caught.value
    # The raw token reaches the caller either way; only the typed reason is at stake, so a
    # row that records none must still carry the refusal.
    assert err.reason_of() == token

    if vector["reason_field"] == "":
        # The protocol records no reason for this token, or records two and so cannot say
        # which check ran. Promoting one would attribute a failure the wire never
        # attributed.
        assert err.detail is None
        return
    _assert_recorded_detail(err, vector)
