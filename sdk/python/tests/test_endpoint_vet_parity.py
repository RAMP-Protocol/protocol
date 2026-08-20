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
from ramp_sdk.hosts import is_bare_host
from ramp_sdk.resolvers import EndpointRefusedError, WellKnownEndpointResolver

_DOC = load_json(GO_RESOLVERS_TESTDATA / "endpoint-vet-vectors.json")
_REFUSED = [v for v in _DOC["endpoint_vet"] if v["refused"]]
_ACCEPTED = [v for v in _DOC["endpoint_vet"] if not v["refused"]]


def _serving_host_is_usable(host: str) -> bool:
    """Whether a vector's SERVING host is a value a caller could legitimately pass."""
    try:
        return is_bare_host(host)
    except ValueError:
        return False


# The two faults a refused vector can carry, split by DATA rather than by name. An
# unusable serving host is the caller's own argument, refused before any fetch; every
# other refusal is a verdict on what the Exchange advertised.
_REFUSED_BY_THE_RULE = [v for v in _REFUSED if _serving_host_is_usable(v["host"])]
_REFUSED_BEFORE_THE_FETCH = [v for v in _REFUSED if not _serving_host_is_usable(v["host"])]


def _serving_manifest(endpoint: str) -> httpx.Client:
    """A manifest server that always answers with the endpoint under test."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"role": "ROLE_EXCHANGE", "endpoint": endpoint})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_both_partitions_of_the_corpus_are_nonempty() -> None:
    assert len(_REFUSED) > 0
    assert len(_ACCEPTED) > 0


def test_the_caller_fault_partition_stays_the_exception_it_is_written_as() -> None:
    """One vector carries an unusable serving host, and the split below is only
    honest while that stays true. A second one arriving silently would move a
    verdict on the Exchange's answer into the branch that does not require
    EndpointRefusedError, which is the assertion this file exists to make."""
    assert len(_REFUSED_BEFORE_THE_FETCH) == 1
    assert len(_REFUSED_BY_THE_RULE) == len(_REFUSED) - 1


@pytest.mark.parametrize("vector", _ACCEPTED, ids=[v["name"] for v in _ACCEPTED])
def test_an_accepted_endpoint_is_handed_back(vector: dict) -> None:
    r = WellKnownEndpointResolver(http=_serving_manifest(vector["endpoint"]))
    assert r.resolve_endpoint(vector["host"]) == vector["endpoint"]


# The exact class IS pinned, positively. Excluding two wrong classes cannot preserve
# the verdict this branch adds: EndpointRefusedError is FINAL, distinct from "no
# endpoint advertised" and from a transport failure precisely so a caller classifying
# retryability reads it as a decision. A test that accepts anything else would stay
# green while that distinction was erased — and would count a crash as a refusal.
@pytest.mark.parametrize(
    "vector", _REFUSED_BY_THE_RULE, ids=[v["name"] for v in _REFUSED_BY_THE_RULE]
)
def test_a_refused_endpoint_is_refused_by_the_rule(vector: dict) -> None:
    r = WellKnownEndpointResolver(http=_serving_manifest(vector["endpoint"]))
    with pytest.raises(EndpointRefusedError):
        r.resolve_endpoint(vector["host"])


# The one fault that is NOT a verdict on the Exchange: the caller's own argument is
# not a host, so nothing was fetched and there is nothing to have a verdict on. It is
# the plain ValueError is_bare_host itself raises, and it must not be dressed up as a
# refusal of the manifest.
@pytest.mark.parametrize(
    "vector", _REFUSED_BEFORE_THE_FETCH, ids=[v["name"] for v in _REFUSED_BEFORE_THE_FETCH]
)
def test_an_unusable_serving_host_is_the_callers_fault(vector: dict) -> None:
    r = WellKnownEndpointResolver(http=_serving_manifest(vector["endpoint"]))
    with pytest.raises(ValueError) as caught:  # noqa: PT011 - the class IS the assertion
        r.resolve_endpoint(vector["host"])
    assert not isinstance(caught.value, EndpointRefusedError)
