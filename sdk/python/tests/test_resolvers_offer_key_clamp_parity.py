"""Cross-language offer-key EXPIRY-CLAMP parity (Python side).

sdk/python ``_clamp_expiry`` MUST reproduce the sdk/go ``clampOfferKeyExpiry``
oracle's clamped expiry for EVERY vector in
``sdk/go/resolvers/testdata/offer-key-clamp-vectors.json``. Each vector is
``{label, now, ttl_seconds, not_after, expected_expiry}``: ``now`` / ``not_after`` /
``expected_expiry`` are RFC3339 strings (parsed natively to epoch seconds here),
``ttl_seconds`` is numeric.

The clamped expiry (``min(now + ttl, not_after)``) is what keeps a cached
offer-signing key from being served past its validity window. Replaying the corpus
proves the Python clamp the :class:`CachedOfferKeyResolver` CALLS agrees with the
Go/TS clamp at the boundary the three languages must never disagree on: TTL-first,
not_after-first, and the exact-equality ``now + ttl == not_after`` seam.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json

from ramp_sdk.resolvers.offer_key_cache import _clamp_expiry

_CORPUS = load_json(GO_RESOLVERS_TESTDATA / "offer-key-clamp-vectors.json")


def test_clamp_corpus_nonempty() -> None:
    assert len(_CORPUS["vectors"]) > 0


@pytest.mark.parametrize(
    "vec",
    _CORPUS["vectors"],
    ids=[v["label"] for v in _CORPUS["vectors"]],
)
def test_clamp_matches_go_oracle(vec: dict[str, Any]) -> None:
    now = datetime.fromisoformat(vec["now"]).timestamp()
    not_after = datetime.fromisoformat(vec["not_after"]).timestamp()
    expected = datetime.fromisoformat(vec["expected_expiry"]).timestamp()
    assert _clamp_expiry(now, vec["ttl_seconds"], not_after) == expected
