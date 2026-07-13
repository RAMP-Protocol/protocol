"""Behavior suite for ``active_ed25519_key`` — the document-order active-key
selector that complements the thumbprint-keyed ``WBAKeyResolver.resolve``.

Byte-parity with the Go ``ActiveEd25519Key`` / TS ``activeEd25519Key`` oracles:
iterate the directory's keys in DOCUMENT ORDER — UNBOUNDED by default (``max_scan``
is an OPTIONAL cap) — and return the FIRST key that is window-active AND a well-formed
OKP/Ed25519 JWK whose ``x`` base64url-decodes to exactly 32 bytes; skip-and-continue
past any failing key; ``None`` when none qualifies. Pure logic over a parsed
``WBAFile`` — no HTTP origin needed. Keys are minted through the SDK's own
byte-parity primitives via the shared harness.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from resolvers_harness import (
    ANCHOR,
    HOUR,
    active_jwk,
    expired_jwk,
    long_jwk,
    make_key,
    wba_jwk,
)
from wire.models import WBAFile

if TYPE_CHECKING:
    import pytest

from ramp_sdk.b64 import b64url_nopad
from ramp_sdk.resolvers import active_ed25519_key, active_ed25519_key_with_expiry


# A future (not-yet-valid) window: entirely after the anchor.
def _future_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR + HOUR, ANCHOR + 2 * HOUR)


# Bounds carrying NO UTC offset (naive/local time). The instant span
# (11:00..13:00) straddles ANCHOR (12:00Z), so a parser that wrongly accepted
# an offset-less bound would treat this key as ACTIVE — the test proves it is
# rejected (fail closed) rather than selected or crashing on the compare.
def _naive_bounds_jwk(x: str) -> dict[str, Any]:
    return active_jwk(x) | {
        "not_before": "2026-05-01T11:00:00",
        "not_after": "2026-05-01T13:00:00",
    }


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


def test_offset_less_bound_is_inactive_not_crash() -> None:
    # A key whose window bounds carry no UTC offset must be treated as inactive
    # (fail closed), never crash the selector; iteration continues to the next.
    naive = make_key()
    good = make_key()
    directory = _directory([_naive_bounds_jwk(naive.x), active_jwk(good.x)])
    assert active_ed25519_key(directory, ANCHOR) == good.raw_pub


def test_offset_less_bound_only_yields_none() -> None:
    # A directory whose only key has offset-less bounds resolves to nothing —
    # on both the plain and with-expiry faces — instead of raising.
    naive = make_key()
    directory = _directory([_naive_bounds_jwk(naive.x)])
    assert active_ed25519_key(directory, ANCHOR) is None
    assert active_ed25519_key_with_expiry(directory, ANCHOR) is None


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


def test_unbounded_default_reaches_high_index_key() -> None:
    # Ten inactive fillers then a valid active key at position 11 (0-indexed 10):
    # the former default cap of 10 would have hidden it, but the UNBOUNDED default
    # now reaches it — the DoS-by-directory-padding footgun is gone.
    fillers = [expired_jwk(make_key().x) for _ in range(10)]
    target = make_key()
    directory = _directory([*fillers, active_jwk(target.x)])
    assert active_ed25519_key(directory, ANCHOR) == target.raw_pub
    # An explicit bound large enough still reaches it.
    assert active_ed25519_key(directory, ANCHOR, max_scan=11) == target.raw_pub


def test_explicit_bound_exhaustion_returns_none_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # An explicit max_scan of 10 is exhausted over the 10 expired fillers before the
    # index-10 key: None is returned AND the exhaustion is logged (a valid key beyond
    # the cap is unreachable) — never silently indistinguishable from a genuine miss.
    fillers = [expired_jwk(make_key().x) for _ in range(10)]
    target = make_key()
    directory = _directory([*fillers, active_jwk(target.x)])
    with caplog.at_level(logging.WARNING, logger="ramp_sdk.resolvers.wba"):
        assert active_ed25519_key(directory, ANCHOR, max_scan=10) is None
    assert any("max_scan" in r.getMessage() for r in caplog.records)


def test_negative_max_scan_clamps_to_scan_none() -> None:
    # A negative max_scan clamps to zero (scan none): None even with an active key
    # present. Parity with Go clamp-to-zero / TS Math.max(0, n).
    active = make_key()
    directory = _directory([active_jwk(active.x)])
    assert active_ed25519_key(directory, ANCHOR, max_scan=-1) is None


def test_mixed_case_kty_crv_is_accepted() -> None:
    # Case-insensitive kty/crv is a DELIBERATE lenient SDK convention (RFC 7517/8037
    # want exact-case OKP / Ed25519). A window-active key with mixed-case kty/crv is
    # accepted and selected, identically across the three SDKs.
    k = make_key()
    jwk = active_jwk(k.x) | {"kty": "oKp", "crv": "ed25519"}
    directory = _directory([jwk])
    assert active_ed25519_key(directory, ANCHOR) == k.raw_pub


def test_none_directory_returns_none_not_raise() -> None:
    # A None directory is guarded (returns None, never raises), matching Go's nil guard.
    assert active_ed25519_key(None, ANCHOR) is None  # type: ignore[arg-type]
    assert active_ed25519_key_with_expiry(None, ANCHOR) is None  # type: ignore[arg-type]


def test_empty_directory_returns_none() -> None:
    assert active_ed25519_key(_directory([]), ANCHOR) is None


def test_no_active_key_returns_none() -> None:
    # A directory of only inactive keys yields None (parity: Go ErrKeyExpired).
    directory = _directory([expired_jwk(make_key().x), _future_jwk(make_key().x)])
    assert active_ed25519_key(directory, ANCHOR) is None


# ── active_ed25519_key_with_expiry — the key + not_after variant ──────────────


def test_with_expiry_returns_selected_key_and_its_not_after() -> None:
    # The FIRST active key wins and its not_after (active_jwk's window upper bound)
    # is returned as an aware datetime alongside the raw key.
    k1 = make_key()
    k2 = make_key()
    directory = _directory([active_jwk(k1.x), active_jwk(k2.x)])
    result = active_ed25519_key_with_expiry(directory, ANCHOR)
    assert result is not None
    key, not_after = result
    assert key == k1.raw_pub
    assert not_after == ANCHOR + HOUR  # active_jwk's not_after


def test_with_expiry_skips_inactive_and_returns_next_active_not_after() -> None:
    # A retired, a future, and a window-active-but-malformed key are all skipped;
    # the returned not_after is the NEXT (selected) active key's — a long window
    # so it is distinct from the skipped keys' bounds.
    retired = make_key()
    future = make_key()
    selected = make_key()
    directory = _directory(
        [
            expired_jwk(retired.x),
            _future_jwk(future.x),
            active_jwk("AAAAA"),  # active window but x is undecodable base64url
            long_jwk(selected.x),
        ]
    )
    result = active_ed25519_key_with_expiry(directory, ANCHOR)
    assert result is not None
    key, not_after = result
    assert key == selected.raw_pub
    assert not_after == ANCHOR + 1000 * HOUR  # long_jwk's not_after


def test_with_expiry_returns_none_when_no_key_qualifies() -> None:
    directory = _directory([expired_jwk(make_key().x), _future_jwk(make_key().x)])
    assert active_ed25519_key_with_expiry(directory, ANCHOR) is None


def test_with_expiry_agrees_with_plain_selector_on_the_key() -> None:
    # Regression: both faces select the SAME key from the same directory. The
    # with-expiry variant only adds not_after; it never changes the selection.
    retired = make_key()
    selected = make_key()
    directory = _directory([expired_jwk(retired.x), long_jwk(selected.x)])
    plain = active_ed25519_key(directory, ANCHOR)
    with_expiry = active_ed25519_key_with_expiry(directory, ANCHOR)
    assert with_expiry is not None
    assert plain == with_expiry[0]
