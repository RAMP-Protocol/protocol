"""Host-rule parity (Python side): ``host_of``, ``is_bare_host`` and
``host_anchored`` mirror the Go oracle (helpers/hosts.go).

Mirrors the TypeScript sibling sdk/ts/tests/host-rule.parity.test.ts.

These three decide where a signed call is allowed to go, from values a network
party supplied, so they are corpus-locked rather than asserted three times. The
corpus is doing more work here than a port might expect: the platform URL parsers
disagree about what a reference even IS before any of this code runs. ``urlsplit``
strips tabs and newlines the oracle refuses outright, lowercases its ``hostname``
accessor, and keeps userinfo inside ``netloc``; WHATWG's ``URL`` in the TypeScript
port folds a scheme's default port away at parse time, earlier than the rule
decides which scheme is in play. A port built on either passes the ordinary cases
and fails the crossings, which is what the crossings are here for.

A reference the oracle cannot read is an ERROR there and a ``ValueError`` here, so
every case carries ``error`` alongside its value and this suite branches on it.
Without that field a port could answer "not anchored" where the oracle says "not a
reference" and still look green.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json
from ramp_sdk.hosts import host_anchored, host_of, is_bare_host

_DOC = load_json(GO_TESTDATA / "host-rule-vectors.json")

# Partitioned the way the TypeScript sibling partitions it. The partitions matter
# on their own: each case picks a raises-assertion or a value assertion, so a
# corpus that lost every unreadable-reference case would register zero raises
# assertions and this file would report green with that contract untested.
_HOST_OF_FAULTS = [v for v in _DOC["host_of"] if v["error"]]
_HOST_OF_VALUES = [v for v in _DOC["host_of"] if not v["error"]]
_BARE_HOST_FAULTS = [v for v in _DOC["is_bare_host"] if v["error"]]
_BARE_HOST_VALUES = [v for v in _DOC["is_bare_host"] if not v["error"]]
_ANCHOR_FAULTS = [v for v in _DOC["host_anchored"] if v["error"]]
_ANCHOR_VALUES = [v for v in _DOC["host_anchored"] if not v["error"]]


def test_every_partition_of_the_corpus_is_nonempty() -> None:
    assert len(_HOST_OF_FAULTS) > 0
    assert len(_HOST_OF_VALUES) > 0
    assert len(_BARE_HOST_FAULTS) > 0
    assert len(_BARE_HOST_VALUES) > 0
    assert len(_ANCHOR_FAULTS) > 0
    assert len(_ANCHOR_VALUES) > 0


@pytest.mark.parametrize("vector", _HOST_OF_VALUES, ids=[v["name"] for v in _HOST_OF_VALUES])
def test_host_of_matches_the_oracle(vector: dict) -> None:
    assert host_of(vector["ref"]) == vector["host"]


@pytest.mark.parametrize("vector", _HOST_OF_FAULTS, ids=[v["name"] for v in _HOST_OF_FAULTS])
def test_host_of_refuses_an_unusable_reference(vector: dict) -> None:
    with pytest.raises(ValueError, match="not a usable host"):
        host_of(vector["ref"])


@pytest.mark.parametrize("vector", _BARE_HOST_VALUES, ids=[v["name"] for v in _BARE_HOST_VALUES])
def test_is_bare_host_matches_the_oracle(vector: dict) -> None:
    assert is_bare_host(vector["ref"]) is vector["bare"]


@pytest.mark.parametrize("vector", _BARE_HOST_FAULTS, ids=[v["name"] for v in _BARE_HOST_FAULTS])
def test_is_bare_host_refuses_an_unusable_reference(vector: dict) -> None:
    with pytest.raises(ValueError, match="not a usable host"):
        is_bare_host(vector["ref"])


@pytest.mark.parametrize("vector", _ANCHOR_VALUES, ids=[v["name"] for v in _ANCHOR_VALUES])
def test_host_anchored_matches_the_oracle(vector: dict) -> None:
    assert host_anchored(vector["anchor"], vector["candidate"]) is vector["anchored"]


@pytest.mark.parametrize("vector", _ANCHOR_FAULTS, ids=[v["name"] for v in _ANCHOR_FAULTS])
def test_host_anchored_refuses_an_unusable_reference(vector: dict) -> None:
    with pytest.raises(ValueError, match="not a usable host"):
        host_anchored(vector["anchor"], vector["candidate"])
