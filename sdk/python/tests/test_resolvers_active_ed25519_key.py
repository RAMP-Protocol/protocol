"""Behavior suite for ``active_ed25519_key`` — the document-order active-key
selector that complements the thumbprint-keyed ``WBAKeyResolver.resolve``.

Byte-parity with the Go ``ActiveEd25519Key`` / TS ``activeEd25519Key`` oracles:
iterate the directory's keys in DOCUMENT ORDER, examine at most the first
``max_scan`` (default 10, a DoS cap), and return the FIRST key that is
window-active AND a well-formed OKP/Ed25519 JWK whose ``x`` base64url-decodes to
exactly 32 bytes; skip-and-continue past any failing key; ``None`` when none
qualifies. Pure logic over a parsed ``WBAFile`` — no HTTP origin needed. Keys are
minted through the SDK's own byte-parity primitives via the shared harness.
"""

from __future__ import annotations

from typing import Any

from resolvers_harness import (
    ANCHOR,
    HOUR,
    active_jwk,
    expired_jwk,
    make_key,
    wba_jwk,
)
from wire.models import WBAFile

from ramp_sdk.b64 import b64url_nopad
from ramp_sdk.resolvers import active_ed25519_key

# A future (not-yet-valid) window: entirely after the anchor.
def _future_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR + HOUR, ANCHOR + 2 * HOUR)


def _directory(keys: list[dict[str, Any]]) -> WBAFile:
    return WBAFile.model_validate({"keys": keys})


def test_plain_window_selects_first_active_key() -> None:
    # Two active keys: the FIRST in document order wins.
    k1 = make_key()
    k2 = make_key()
    directory = _directory([active_jwk(k1.x), active_jwk(k2.x)])
    assert active_ed25519_key(directory, ANCHOR) == k1.raw_pub


def test_retired_key_ahead_is_skipped() -> None:
    # An expired key ahead of the active one is skipped; the active key wins.
    retired = make_key()
    active = make_key()
    directory = _directory([expired_jwk(retired.x), active_jwk(active.x)])
    assert active_ed25519_key(directory, ANCHOR) == active.raw_pub


def test_future_key_ahead_is_skipped() -> None:
    # A not-yet-valid key ahead of the active one is skipped.
    future = make_key()
    active = make_key()
    directory = _directory([_future_jwk(future.x), active_jwk(active.x)])
    assert active_ed25519_key(directory, ANCHOR) == active.raw_pub


def test_skip_non_okp_and_continue() -> None:
    # A window-active key with a non-OKP kty is skipped; iteration continues.
    bad = make_key()
    good = make_key()
    bad_jwk = active_jwk(bad.x) | {"kty": "RSA"}
    directory = _directory([bad_jwk, active_jwk(good.x)])
    assert active_ed25519_key(directory, ANCHOR) == good.raw_pub


def test_skip_wrong_crv_and_continue() -> None:
    # A window-active key with a non-Ed25519 crv is skipped; iteration continues.
    bad = make_key()
    good = make_key()
    bad_jwk = active_jwk(bad.x) | {"crv": "P-256"}
    directory = _directory([bad_jwk, active_jwk(good.x)])
    assert active_ed25519_key(directory, ANCHOR) == good.raw_pub


def test_skip_undecodable_x_and_continue() -> None:
    # A window-active key whose x is not decodable base64url is skipped.
    good = make_key()
    # "AAAAA" (len ≡ 1 mod 4) is structurally invalid base64 and raises on decode.
    bad_jwk = active_jwk("AAAAA")
    directory = _directory([bad_jwk, active_jwk(good.x)])
    assert active_ed25519_key(directory, ANCHOR) == good.raw_pub


def test_skip_wrong_length_x_and_continue() -> None:
    # A window-active key whose x decodes to 31 bytes (not 32) is skipped.
    good = make_key()
    short_x = b64url_nopad(b"\x01" * 31)
    directory = _directory([active_jwk(short_x), active_jwk(good.x)])
    assert active_ed25519_key(directory, ANCHOR) == good.raw_pub


def test_cap_boundary_valid_key_at_position_ten_is_selected() -> None:
    # Nine inactive fillers then a valid active key at position 10 (0-indexed 9):
    # within the default scan cap of 10, so it IS selected.
    fillers = [expired_jwk(make_key().x) for _ in range(9)]
    target = make_key()
    directory = _directory([*fillers, active_jwk(target.x)])
    assert active_ed25519_key(directory, ANCHOR) == target.raw_pub


def test_cap_boundary_valid_key_at_position_eleven_is_unreachable() -> None:
    # Ten inactive fillers then a valid active key at position 11 (0-indexed 10):
    # beyond the default scan cap of 10, so it is UNREACHABLE → None.
    fillers = [expired_jwk(make_key().x) for _ in range(10)]
    target = make_key()
    directory = _directory([*fillers, active_jwk(target.x)])
    assert active_ed25519_key(directory, ANCHOR) is None


def test_cap_boundary_position_eleven_reachable_with_raised_max_scan() -> None:
    # The cap is a parameter: raising max_scan past the padding reaches the key.
    fillers = [expired_jwk(make_key().x) for _ in range(10)]
    target = make_key()
    directory = _directory([*fillers, active_jwk(target.x)])
    assert active_ed25519_key(directory, ANCHOR, max_scan=11) == target.raw_pub


def test_empty_directory_returns_none() -> None:
    assert active_ed25519_key(_directory([]), ANCHOR) is None


def test_no_active_key_returns_none() -> None:
    # A directory of only inactive keys yields None (parity: Go ErrKeyExpired).
    directory = _directory([expired_jwk(make_key().x), _future_jwk(make_key().x)])
    assert active_ed25519_key(directory, ANCHOR) is None
