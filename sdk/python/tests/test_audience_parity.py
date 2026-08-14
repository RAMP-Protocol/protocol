"""Audience parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/audience.parity.test.ts.

``ramp_sdk.hosts.is_bare_domain`` and ``ramp_sdk.hosts.check_audience`` MUST
reproduce the sdk/go oracle (helpers/hosts.go, helpers/audience.go). The shared
vectors at sdk/go/helpers/testdata/audience-vectors.json carry the bare-domain
rule ITSELF (pattern + length bound) beside the case lists, so this suite asserts
the constants too: a port that quietly kept its own copy of the pattern would
otherwise pass every case that copy happens to agree on.

The identity fault is a RAISE here and a (verdict, error) pair in Go, so the
vectors carry ``identity_error`` alongside the token and this suite branches on
it. Without that field a port could collapse a deployment fault into a request
rejection and still look green.

Python needs one thing the other two do not: its ``$`` also matches just before a
trailing newline, so the pattern must be applied with ``fullmatch``. The
``trailing_newline`` case is what proves it was.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json
from ramp_sdk.hosts import (
    BARE_DOMAIN_PATTERN,
    MAX_BARE_DOMAIN_LEN,
    check_audience,
    is_bare_domain,
)

_DOC = load_json(GO_TESTDATA / "audience-vectors.json")
_BARE_DOMAIN = _DOC["bare_domain"]
_AUDIENCE = _DOC["audience"]
_IDENTITY_FAULT = [v for v in _AUDIENCE if v["identity_error"]]
_REQUEST_CASES = [v for v in _AUDIENCE if not v["identity_error"]]


def test_audience_vector_sets_nonempty() -> None:
    assert len(_BARE_DOMAIN) > 0
    assert len(_AUDIENCE) > 0
    assert len(_IDENTITY_FAULT) > 0
    assert len(_REQUEST_CASES) > 0


def test_carries_the_same_bare_domain_rule_as_the_oracle() -> None:
    """The rule is one definition or it is nothing."""
    assert BARE_DOMAIN_PATTERN == _DOC["bare_domain_pattern"]
    assert MAX_BARE_DOMAIN_LEN == _DOC["bare_domain_max_len"]


@pytest.mark.parametrize("vector", _BARE_DOMAIN, ids=[v["name"] for v in _BARE_DOMAIN])
def test_is_bare_domain_matches_the_oracle(vector: dict) -> None:
    assert is_bare_domain(vector["value"]) is vector["valid"]


@pytest.mark.parametrize("vector", _REQUEST_CASES, ids=[v["name"] for v in _REQUEST_CASES])
def test_check_audience_matches_the_oracle(vector: dict) -> None:
    assert check_audience(vector["self"], *vector["claimed"]) == vector["expected_verdict"]


@pytest.mark.parametrize("vector", _IDENTITY_FAULT, ids=[v["name"] for v in _IDENTITY_FAULT])
def test_check_audience_refuses_an_unusable_identity(vector: dict) -> None:
    # A fault in this deployment, not in the request — so it is raised, never
    # returned as a verdict a caller could mistake for a rejection.
    with pytest.raises(ValueError):
        check_audience(vector["self"], *vector["claimed"])
