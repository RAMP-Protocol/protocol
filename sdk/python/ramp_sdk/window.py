"""Signature Window (sdk/python) — Python port of the sdk/go oracle
(core/sigwindow.go). A ``Window`` returns the RFC 9421 (created, expires) cutoffs
(unix seconds) to stamp on the next outbound signature; it is invoked once per
signed request. Both values derive from a single ``now()`` reading so a
deterministic-clock test stays inside the verifier's freshness window.

The clock is in the SECONDS domain (matching Go's ``now().Unix()``); both faces
truncate to integer seconds via ``int()`` so the produced RFC 9421
@signature-params bytes stay byte-identical to the sign-site's historical inline
mint (R3).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TypeAlias

#: A Window yields the (created, expires) unix-second cutoffs for one signature.
Window: TypeAlias = Callable[[], "tuple[int, int]"]


def clock_window(now: Callable[[], float], ttl_sec: int) -> Window:
    """Return the plain production Window: it stamps each signature with
    clock-derived ``created = int(now())`` and ``expires = created + ttl_sec``.
    ``now`` reads seconds (fractional allowed); the truncation reproduces Go's
    ``.Unix()``.
    """

    def _window() -> tuple[int, int]:
        created = int(now())
        return created, created + ttl_sec

    return _window


def monotonic_window(now: Callable[[], float], ttl_sec: int) -> Window:
    """Return a Window whose expires cutoff strictly increases across calls: it
    tracks ``int(now()) + ttl_sec`` but, when a burst of requests lands in the
    same wall-clock second, bumps expires by one second per call so no two
    back-to-back signatures share a (keyid, expires) pair — keeping identical
    relay requests from colliding in the server's replay store. ``created``
    tracks ``int(now())``, so the pair stays clock-consistent. Thread-safe: the
    running maximum is guarded by a lock.
    """
    lock = threading.Lock()
    last_expires = 0

    def _window() -> tuple[int, int]:
        nonlocal last_expires
        created = int(now())
        floor = created + ttl_sec
        with lock:
            nxt = last_expires + 1 if last_expires >= floor else floor
            last_expires = nxt
        return created, nxt

    return _window
