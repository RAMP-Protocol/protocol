"""Cross-language revocation-set-membership parity (Python side).

sdk/python ``WBAKeyResolver.revoked()`` MUST reproduce the sdk/go oracle's
verdict for every case in
``sdk/go/helpers/testdata/revocation-membership-vectors.json``. The vector
carries a served WBA directory (keys + windows), a served revocation snapshot
(as_of + revoked thumbprints), a prime thumbprint (a directory-listed key
resolved to populate the snapshot), and labelled cases with the expected verdict.

This test serves those docs against a REAL origin (the shared harness), resolves
the prime thumbprint to prime the snapshot, then asserts ``revoked(tp)`` matches
the oracle for EVERY case — including the load-bearing
directory-absent-but-revoked -> True, which is the whole point of the accessor.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from conftest import GO_TESTDATA, load_json
from resolvers_harness import MutableClock, Origin, revocation_json, wba_file_json

from ramp_sdk.resolvers import WBAKeyResolver

_VECTOR = load_json(GO_TESTDATA / "revocation-membership-vectors.json")


def _as_of() -> datetime:
    return datetime.fromisoformat(_VECTOR["as_of"])


def _directory_keys() -> list[dict[str, Any]]:
    return [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "x": k["x"],
            "not_before": k["not_before"],
            "not_after": k["not_after"],
        }
        for k in _VECTOR["directory_keys"]
    ]


def test_revocation_membership_corpus_nonempty() -> None:
    assert len(_VECTOR["cases"]) > 0


@pytest.mark.parametrize(
    "case",
    _VECTOR["cases"],
    ids=[c["label"] for c in _VECTOR["cases"]],
)
def test_revoked_matches_go_oracle(case: dict[str, Any]) -> None:
    origin = Origin()
    try:
        origin.set_wba(wba_file_json(_directory_keys(), origin.revocation_url()))
        origin.set_revocation(revocation_json(_as_of(), list(_VECTOR["revoked"])))

        r = WBAKeyResolver(scheme="http", now=MutableClock(_as_of()))
        # Prime the revocation snapshot by resolving the directory-listed key.
        r.resolve(_VECTOR["prime_thumbprint"], origin.url)

        assert r.revoked(case["thumbprint"]) is case["expected_revoked"]
        # Empty key_id is never revoked (parity with the Go accessor guard).
        assert r.revoked("") is False
    finally:
        origin.close()
