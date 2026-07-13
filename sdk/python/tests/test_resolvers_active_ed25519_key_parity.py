"""Cross-language active-Ed25519-key selection parity (Python side).

sdk/python ``active_ed25519_key`` / ``active_ed25519_key_with_expiry`` MUST
reproduce the sdk/go oracle's document-order selection for EVERY vector in
``sdk/go/resolvers/testdata/active-ed25519-key-vectors.json``. Each vector is a
WBA directory (keys[] with validity windows + JWK ``x``), an optional
``max_scan``, and the oracle's verdict: the selected key's document-order index
(-1 = none), its raw public key (base64url), and its ``not_after``.

The corpus is the shared parity lock for the H2 base64 edges (standard-alphabet
``x``, ``=``-padded ``x``, valid unpadded ``x``) and the C1 timestamp edges
(offset-less/naive, date-only, empty bounds, the not_before==now / not_after==now
half-open boundaries), plus the ``max_scan`` DoS cap. Replaying it here is what
proves the Python selector selects the SAME key the Go oracle did — the
divergence the byte-parity contract exists to forbid.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json
from wire.models import WBAFile

from ramp_sdk.b64 import b64url_decode_strict
from ramp_sdk.resolvers import (
    active_ed25519_key,
    active_ed25519_key_screened,
    active_ed25519_key_with_expiry,
    active_ed25519_key_with_expiry_screened,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_CORPUS = load_json(GO_RESOLVERS_TESTDATA / "active-ed25519-key-vectors.json")
_NOW = datetime.fromisoformat(_CORPUS["now"])


def _directory(keys: list[dict[str, Any]]) -> WBAFile:
    return WBAFile.model_validate({"keys": keys})


def _scan_kwargs(vec: dict[str, Any]) -> dict[str, int]:
    # null max_scan → exercise the selector's DEFAULT cap (omit the kwarg).
    return {} if vec["max_scan"] is None else {"max_scan": vec["max_scan"]}


def _revoked_predicate(vec: dict[str, Any]) -> Callable[[str], bool]:
    """A predicate over the vector's revoked-thumbprint set (empty for most)."""
    revoked = set(vec["revoked"])
    return lambda tp: tp in revoked


def test_active_key_corpus_nonempty() -> None:
    assert len(_CORPUS["vectors"]) > 0


@pytest.mark.parametrize(
    "vec",
    _CORPUS["vectors"],
    ids=[v["label"] for v in _CORPUS["vectors"]],
)
def test_active_key_matches_go_oracle(vec: dict[str, Any]) -> None:
    directory = _directory(vec["keys"])
    kwargs = _scan_kwargs(vec)
    revoked = _revoked_predicate(vec)

    # The corpus verdict is produced by the Go REVOCATION-AWARE oracle, so replay the
    # screened faces with the vector's revoked set.
    result = active_ed25519_key_screened(directory, _NOW, revoked, **kwargs)
    with_expiry = active_ed25519_key_with_expiry_screened(directory, _NOW, revoked, **kwargs)

    # Empty revoked set: screened selection must equal the bare face — so these
    # vectors also lock the non-screened path (as they did before revocation existed).
    if not vec["revoked"]:
        assert result == active_ed25519_key(directory, _NOW, **kwargs)
        assert with_expiry == active_ed25519_key_with_expiry(directory, _NOW, **kwargs)

    if vec["expected_index"] == -1:
        assert result is None
        assert with_expiry is None
        return

    expected_pub = b64url_decode_strict(vec["expected_pub"])
    assert result == expected_pub
    # Document order: the selected bytes are exactly keys[expected_index].x.
    assert b64url_decode_strict(vec["keys"][vec["expected_index"]]["x"]) == expected_pub

    assert with_expiry is not None
    key, not_after = with_expiry
    assert key == expected_pub
    assert not_after == datetime.fromisoformat(vec["expected_not_after"])
