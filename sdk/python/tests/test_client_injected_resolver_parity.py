"""The client re-checks whatever an injected endpoint resolver hands back — replay of the
shared endpoint-vet corpus, driven through the CLIENT rather than through the resolver.

Mirrors the TypeScript sibling sdk/ts/tests/client-injected-resolver.parity.test.ts and
the Go leg sdk/go/connect/route_injected_resolver_test.go.

The corpus already pins WHAT the endpoint rule decides, and every language replays it
against the resolver. What it did not pin is that the client applies the rule at all to a
resolver it did not write — and ``EndpointResolver`` is a documented, encouraged seam, so
"a caller supplied one" is the ordinary case rather than an exotic one. Without the
re-check a signed usage report or dispute goes wherever that implementation pointed: an
off-host endpoint, or one carrying userinfo the HTTP client then turns into an
Authorization header the SDK never chose.

A refusal must be ``NOT_SENT``, not ``UNREACHABLE``: it is a verdict, and reporting it as
a transport failure would tell a caller to retry something that can never succeed.
"""

from __future__ import annotations

from typing import Any

import pytest

from conftest import GO_RESOLVERS_TESTDATA, load_json
from ramp_sdk.client import CallError, CallErrorKind
from ramp_sdk.client.route import vet_exchange_endpoint

_VECTORS: list[dict[str, Any]] = load_json(
    GO_RESOLVERS_TESTDATA / "endpoint-vet-vectors.json"
)["endpoint_vet"]

# A vector whose serving host is not a usable host is refused before the resolver is
# reached, by the bare-host check; the resolver replay covers that path.
_DRIVEN = [v for v in _VECTORS if v["host"]]


class _Answering:
    """An injected resolver that answers exactly what a vector says, checking nothing."""

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    def resolve_endpoint(self, host: str) -> str:  # noqa: ARG002 - the vector decides
        return self._endpoint


def test_endpoint_vet_vector_set_is_non_empty() -> None:
    assert _DRIVEN
    assert any(v["refused"] for v in _DRIVEN)


@pytest.mark.parametrize("vector", _DRIVEN, ids=[v["name"] for v in _DRIVEN])
def test_the_client_applies_the_rule_to_an_injected_resolvers_answer(
    vector: dict[str, Any],
) -> None:
    resolver = _Answering(vector["endpoint"])
    if not vector["refused"]:
        assert vet_exchange_endpoint(resolver, vector["host"], "report usage") == (
            vector["endpoint"]
        )
        return

    with pytest.raises(CallError) as caught:
        vet_exchange_endpoint(resolver, vector["host"], "report usage")
    assert caught.value.kind is CallErrorKind.NOT_SENT, (
        f"{vector['name']} must be a verdict, not a transport failure"
    )
    # The refusal reaches a log; an endpoint carrying userinfo must not.
    assert "pass@" not in str(caught.value)
