"""Endpoint-rule parity (Python side): which endpoint a well-known manifest is
allowed to advertise, against the Go oracle (sdk/go/internal/endpointrule +
resolvers/endpointresolver.go).

Mirrors the TypeScript sibling sdk/ts/tests/endpoint-vet.parity.test.ts.

The rule is not the sum of its parts, which is why it has a corpus of its own
beside host-rule-vectors.json: an endpoint can be perfectly anchored and still be
one no consumer may dial. The credential cases are the reason. A consumer that
refuses only the spelled-out ``https://user:pass@host`` form has refused a
spelling, not a credential — the same value with no scheme is what a plain URL
parse reads as something other than an authority, and it reaches the anchor check
as the very host it claims to be.

Driven through the RESOLVER rather than a private predicate, because that is where
the rule runs and what a consumer actually calls. The transport is stubbed to a
manifest carrying the vector's endpoint, so each case exercises the bare-host
check, the decode and the vet, and nothing else.
"""

from __future__ import annotations

import httpx
import pytest

from conftest import GO_RESOLVERS_TESTDATA, load_json
from ramp_sdk.resolvers import ResolverError, WellKnownEndpointResolver

_DOC = load_json(GO_RESOLVERS_TESTDATA / "endpoint-vet-vectors.json")
_REFUSED = [v for v in _DOC["endpoint_vet"] if v["refused"]]
_ACCEPTED = [v for v in _DOC["endpoint_vet"] if not v["refused"]]


def _serving_manifest(endpoint: str) -> httpx.Client:
    """A manifest server that always answers with the endpoint under test."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"role": "ROLE_EXCHANGE", "endpoint": endpoint})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_both_partitions_of_the_corpus_are_nonempty() -> None:
    assert len(_REFUSED) > 0
    assert len(_ACCEPTED) > 0


@pytest.mark.parametrize("vector", _ACCEPTED, ids=[v["name"] for v in _ACCEPTED])
def test_an_accepted_endpoint_is_handed_back(vector: dict) -> None:
    r = WellKnownEndpointResolver(http=_serving_manifest(vector["endpoint"]))
    assert r.resolve_endpoint(vector["host"]) == vector["endpoint"]


# The class is not pinned here on purpose. The corpus records the RULE's verdict,
# and two different faults reach it: an unusable serving host is the caller's own
# value (a ValueError, raised before any fetch), while an unusable advertised
# endpoint is a verdict on the Exchange's answer (EndpointRefusedError). Which is
# which is pinned in the integration suite; what this file holds is that all three
# languages refuse the same set.
@pytest.mark.parametrize("vector", _REFUSED, ids=[v["name"] for v in _REFUSED])
def test_a_refused_endpoint_is_never_handed_back(vector: dict) -> None:
    r = WellKnownEndpointResolver(http=_serving_manifest(vector["endpoint"]))
    with pytest.raises((ValueError, ResolverError)):
        r.resolve_endpoint(vector["host"])
