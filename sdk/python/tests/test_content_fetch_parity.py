"""Content-leg parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors the sdk/ts sibling sdk/ts/tests/content-fetch.parity.test.ts and the Go leg
sdk/go/resolvers/content_fetch_corpus_test.go.

The delivery fetch is the one leg where the peer's own words are promoted over the SDK's
classification: an edge that refuses a bound GET answers a small JSON object, and the
token in it becomes the reason a caller branches on. Three things therefore have to agree
across the languages — which answers are a refusal, which tokens the SDK is willing to
repeat, and what a Content-Type reduces to — and none of them is obvious from reading one
side alone.

Go folds this leg into its own FetchError; Python and TypeScript fold it into the client's
CallError, so a caller branches on one failure type for every verb. The projection the
corpus records is the same either way, which is what makes the fold a spelling difference
rather than a divergence.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from conftest import GO_RESOLVERS_TESTDATA, load_json
from ramp_sdk.client import Client, ClientConfig
from ramp_sdk.signing_transport import SigningTransport
from ramp_sdk.client.errors import CallError, CallErrorKind

_VECTORS = load_json(GO_RESOLVERS_TESTDATA / "content-fetch-vectors.json")["vectors"]

_AGENT_SEED = bytes(range(32))

#: The Go failure classes this leg produces, and the shared kind each is spelled as.
_FAILURE_KINDS = {
    "refused": CallErrorKind.REFUSED,
    "unreachable": CallErrorKind.UNREACHABLE,
    "too_large": CallErrorKind.TOO_LARGE,
    "not_signable": CallErrorKind.NOT_SIGNABLE,
    "malformed": CallErrorKind.MALFORMED,
}


def _client(vector: dict[str, Any]) -> Client:
    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        headers = (
            {"content-type": vector["content_type"]} if vector["content_type"] else {}
        )
        return httpx.Response(
            vector["status"], content=vector["body"].encode(), headers=headers
        )

    return Client(
        ClientConfig(
            base_url="https://exchange.test",
            signer=SigningTransport(signer_seed=_AGENT_SEED, keyid="agent.v1"),
        ),
        http=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )


def test_content_fetch_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_reader_extracts_go_projection(vector: dict[str, Any]) -> None:
    client = _client(vector)
    if vector["ok"]:
        content = asyncio.run(client.fetch("https://edge.test/asset"))
        assert content.body == vector["body"].encode()
        # The charset belongs to whoever decodes the bytes; the content carries the media
        # type alone, and a body with no usable header is labelled rather than sniffed.
        assert content.mime_type == vector["mime_type"]
        return

    with pytest.raises(CallError) as excinfo:
        asyncio.run(client.fetch("https://edge.test/asset"))
    err = excinfo.value
    assert err.kind is _FAILURE_KINDS[vector["failure"]]
    # The empty token is the SDK declining to repeat what the publisher wrote.
    assert (err.reason or "") == vector["reason"]
    assert err.reason_of() == vector["reason_of"]
