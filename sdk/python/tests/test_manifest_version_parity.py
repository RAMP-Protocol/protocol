"""Replay of the shared manifest-version corpus, driven two ways.

The pure rule (``manifest_version_refusal``) is replayed row by row against the
Go emitter's verdicts. Then the same rows are driven through the REAL endpoint
resolver against a mock manifest server, so the test proves the resolver applies
the rule before it reads the endpoint — a refused document's endpoint is a
perfectly usable one, so the refusal can only be the version gate.

``present`` is its own column because an absent member is not a string: the
resolver reads ``doc.get("ver")`` and gets ``None``, which is the path the
``absent`` row must exercise. Pinned to manifest-version-vectors.json.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from conftest import GO_TESTDATA, load_json
from resolvers_harness import manifest_json

from ramp_sdk.resolvers import ManifestVersionRefusedError, WellKnownEndpointResolver
from ramp_sdk.wire import WellKnownManifestVersion, manifest_version_refusal

_VECTORS = load_json(GO_TESTDATA / "manifest-version-vectors.json")["manifest_version"]
_ACCEPTED = [v for v in _VECTORS if v["accepted"]]
_REFUSED = [v for v in _VECTORS if not v["accepted"]]
_ABSENT = [v for v in _VECTORS if not v["present"]]

_HOST = "exchange.example"
_ENDPOINT = f"https://{_HOST}/ramp.v1.ExchangeService"


def _ver_of(vector: dict) -> str | None:
    """The value the resolver sees: the string when present, None when absent."""
    return vector["ver"] if vector["present"] else None


def _serving(vector: dict) -> httpx.Client:
    """A manifest server that answers with the vector's ver and a usable endpoint."""
    body = manifest_json(_ENDPOINT, ver=_ver_of(vector))

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _resolver(client: httpx.Client) -> WellKnownEndpointResolver:
    return WellKnownEndpointResolver(http=client, ttl=timedelta(hours=1), scheme="https")


def test_corpus_partitions_are_nonempty() -> None:
    assert len(_ACCEPTED) > 0
    assert len(_REFUSED) > 0
    assert len(_ABSENT) > 0


def test_the_current_constant_is_in_the_accepted_partition() -> None:
    assert any(v["ver"] == WellKnownManifestVersion and v["present"] for v in _ACCEPTED)


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_pure_rule_matches_go_oracle(vector: dict) -> None:
    refusal = manifest_version_refusal(_ver_of(vector))
    assert (refusal is None) == vector["accepted"], refusal


@pytest.mark.parametrize("vector", _ACCEPTED, ids=[v["name"] for v in _ACCEPTED])
def test_resolver_accepts_and_reads_the_endpoint(vector: dict) -> None:
    assert _resolver(_serving(vector)).resolve_endpoint(_HOST) == _ENDPOINT


@pytest.mark.parametrize("vector", _REFUSED, ids=[v["name"] for v in _REFUSED])
def test_resolver_refuses_with_the_version_verdict(vector: dict) -> None:
    # A refused document's endpoint is usable, so the refusal can only be the
    # version gate — and ManifestVersionRefusedError is its own class, not a
    # subclass of any other verdict, so the raises() is the whole assertion.
    with pytest.raises(ManifestVersionRefusedError):
        _resolver(_serving(vector)).resolve_endpoint(_HOST)


def test_version_gate_precedes_the_endpoint_gate() -> None:
    """A wrong-version manifest that ALSO advertises nothing reports the version."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=manifest_json(None, ver="2.0"))

    r = _resolver(httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(ManifestVersionRefusedError):
        r.resolve_endpoint(_HOST)


def test_a_refusal_is_not_cached() -> None:
    """Once the origin serves an acceptable document the next resolve succeeds."""
    served: list[str] = ["2.0"]
    hits = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal hits
        hits += 1
        return httpx.Response(200, text=manifest_json(_ENDPOINT, ver=served[0]))

    r = _resolver(httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(ManifestVersionRefusedError):
        r.resolve_endpoint(_HOST)
    served[0] = WellKnownManifestVersion
    assert r.resolve_endpoint(_HOST) == _ENDPOINT
    assert hits == 2
