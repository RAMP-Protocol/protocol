"""Identity-document resolution parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/identity-document.parity.test.ts.

``ramp_sdk.hosts.resolve_identity_document`` MUST reproduce the sdk/go oracle
(helpers/identitydocs.go). The shared vectors at
sdk/go/helpers/testdata/identity-document-vectors.json carry both halves of each
answer — whether the reference was accepted AND the exact canonical URL it
resolved to — because a port that accepted the right references and returned a
different URL would be just as wrong as one that accepted the wrong references.

The refusal is a RAISE here and an ``error`` in Go, so this suite branches on the
``accepted`` flag rather than comparing message text: the three languages word
their refusals differently on purpose, and pinning the wording would gate a port
on English rather than on behaviour.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json
from ramp_sdk.hosts import resolve_identity_document

_DOC = load_json(GO_TESTDATA / "identity-document-vectors.json")
_VECTORS = _DOC["identity_document"]
_ACCEPTED = [v for v in _VECTORS if v["accepted"]]
_REFUSED = [v for v in _VECTORS if not v["accepted"]]


def test_identity_document_vector_sets_nonempty() -> None:
    # Both partitions matter on their own: a corpus that lost every refused case
    # would leave the whole same-origin rule untested and still report green.
    assert len(_ACCEPTED) > 0
    assert len(_REFUSED) > 0


@pytest.mark.parametrize("vector", _ACCEPTED, ids=[v["name"] for v in _ACCEPTED])
def test_accepted_references_resolve_as_the_oracle_does(vector: dict) -> None:
    assert resolve_identity_document(vector["manifest_url"], vector["ref"]) == vector["resolved"]


@pytest.mark.parametrize("vector", _REFUSED, ids=[v["name"] for v in _REFUSED])
def test_refused_references_are_refused(vector: dict) -> None:
    with pytest.raises(ValueError):
        resolve_identity_document(vector["manifest_url"], vector["ref"])


def test_a_refusal_does_not_echo_the_credential() -> None:
    """The corpus records a verdict, not a message, so this half is per-language.

    A refusal that names the very userinfo it is refusing puts the credential
    wherever the caller logs its errors.

    The cases reach DIFFERENT refusals on purpose. The last three carry the
    credential somewhere no parser reads as userinfo - a reference that does not
    parse at all, and two opaque references with no authority component - so the
    userinfo checks never fire and the string travels on to a much later refusal.
    This is the same set the Go oracle covers.
    """
    secret = "s3cr3t"  # noqa: S105 - test fixture, not a real credential
    for manifest_url, ref in (
        ("https://a.example/.well-known/ramp.json", f"https://u:{secret}@a.example/x"),
        (f"https://u:{secret}@a.example/ramp.json", "/x"),
        ("https://a.example/.well-known/ramp.json", f"https://u:{secret}@a.example/%zz"),
        ("https://a.example/.well-known/ramp.json", f"https:u:{secret}@a.example/x"),
        ("https://a.example/.well-known/ramp.json", f"u:{secret}@a.example/x"),
    ):
        with pytest.raises(ValueError) as excinfo:
            resolve_identity_document(manifest_url, ref)
        assert secret not in str(excinfo.value)
