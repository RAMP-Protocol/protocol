"""Structural guard for the injectable-Window adoption.

DISEASE: a sign site that mints a signature's (created, expires) pair by inline
now+ttl arithmetic (e.g. ``expires = created + self._ttl_sec``) instead of sourcing
it from the injectable Window (``clock_window`` / ``monotonic_window``). Inline
mint cannot be swapped for a monotonic window (unique back-to-back expires) and
re-derives the truncate/ttl contract per-site, drifting from the Go ``.Unix()``
semantics. ``SigningTransport`` was migrated to the Window; this guard pins it stays.

SCOPE — the sign-side mint site (``signing_transport.py``). The verify side PARSES
created/expires from the wire (not a mint) and is intentionally NOT guarded.
``window.py`` itself legitimately computes ``created + ttl`` and is excluded.
"""

from __future__ import annotations

import pathlib
import re

_RAMP_SDK = pathlib.Path(__file__).resolve().parents[1] / "ramp_sdk"

# The pre-migration inline form the sign site must no longer contain.
_FORBIDDEN = re.compile(r"created\s*\+\s*self\._ttl_sec")
_REQUIRED = (
    re.compile(r"from\s+ramp_sdk\.window\s+import"),
    re.compile(r"self\._window\(\)"),
)


def _eval(source: str) -> list[str]:
    out: list[str] = []
    if _FORBIDDEN.search(source):
        out.append("signing_transport.py: forbidden inline now+ttl mint")
    for pat in _REQUIRED:
        if not pat.search(source):
            out.append(f"signing_transport.py: missing Window adoption {pat.pattern}")
    return out


class TestWindowAdoption:
    def test_signing_transport_sources_window_not_inline_mint(self) -> None:
        src = (_RAMP_SDK / "signing_transport.py").read_text(encoding="utf8")
        assert _eval(src) == []

    def test_window_module_exports_both_windows(self) -> None:
        src = (_RAMP_SDK / "window.py").read_text(encoding="utf8")
        assert "def clock_window" in src
        assert "def monotonic_window" in src

    # --- meta-tests ----------------------------------------------------------
    def test_meta_positive_catches_inline_mint(self) -> None:
        bad = "expires = created + self._ttl_sec\nwindow = None"
        assert len(_eval(bad)) > 0

    def test_meta_negative_passes_window_form(self) -> None:
        good = "from ramp_sdk.window import Window, clock_window\ncreated, expires = self._window()"
        assert _eval(good) == []

    def test_meta_would_be_missed_catches_reformatted_mint(self) -> None:
        reformatted = (
            "from ramp_sdk.window import clock_window\n"
            "self._window()\n"
            "expires = created  +  self._ttl_sec\n"  # extra spaces
        )
        violations = _eval(reformatted)
        assert violations == ["signing_transport.py: forbidden inline now+ttl mint"]
