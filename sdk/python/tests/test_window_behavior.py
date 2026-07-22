"""Window behaviour (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/window.behavior.test.ts.

The signature Window (Go core/sigwindow.go) carries a clock → NOT vector-gated.
Two faces:
  - clock_window(now, ttl_sec): created = int(now()), expires = created+ttl
    (MUST int()-truncate — Go .Unix() floors; the current SigningTransport
     mint uses int(self._now()); an un-truncated default would change signature
     bytes).
  - monotonic_window(now, ttl_sec): expires strictly increases across a burst
    within one wall-clock second, so no two back-to-back signatures share an
    expires cutoff (relay replay-store uniqueness).

RED now purely because ``ramp_sdk.window`` does not exist yet.
"""

from __future__ import annotations

# RED: sdk/python/ramp_sdk/window.py does not exist yet (TDD red — missing face).
from ramp_sdk.window import clock_window, monotonic_window  # type: ignore[import-not-found]


def test_clock_window_truncates_created_and_adds_ttl() -> None:
    # A fractional-second now (seconds domain, matching Go's now().Unix()).
    w = clock_window(lambda: 1_700_000_000.987, 600)
    created, expires = w()
    assert created == 1_700_000_000  # truncated, not 1700000000.987
    assert expires == 1_700_000_600  # created + 600
    assert isinstance(created, int)
    assert isinstance(expires, int)


def test_clock_window_reads_clock_each_call() -> None:
    ts = [1_000.0]
    w = clock_window(lambda: ts[0], 60)
    assert w() == (1_000, 1_060)
    ts[0] = 2_000.5
    assert w() == (2_000, 2_060)


def test_monotonic_window_strictly_increases_expires_within_one_second() -> None:
    w = monotonic_window(lambda: 1_700_000_000, 600)  # frozen wall-clock second
    first = w()
    second = w()
    third = w()
    assert first[0] == 1_700_000_000  # created tracks now()
    assert second[1] > first[1]
    assert third[1] > second[1]


def test_monotonic_window_never_repeats_expires_across_burst() -> None:
    w = monotonic_window(lambda: 1_700_000_000, 600)
    seen = {w()[1] for _ in range(100)}
    assert len(seen) == 100
