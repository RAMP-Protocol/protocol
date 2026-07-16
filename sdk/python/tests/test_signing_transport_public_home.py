"""ramp_sdk.signing_transport — public class and its top-level re-export.

The outbound auto-sign face (``SigningTransport`` / ``SignedOutbound``) is a public
capability of the SDK. A capability reachable only via a submodule import path is
half-shipped and drifts from the Go/TS public surface; this pins that both classes
are importable from the documented package root and listed in ``ramp_sdk.__all__``.
"""

from __future__ import annotations

import ramp_sdk
from ramp_sdk.signing_transport import SignedOutbound, SigningTransport


def test_signing_transport_re_exported_at_top_level() -> None:
    """ramp_sdk.__init__ re-exports SigningTransport + SignedOutbound at the root."""
    assert ramp_sdk.SigningTransport is SigningTransport
    assert ramp_sdk.SignedOutbound is SignedOutbound


def test_signing_transport_declared_in_all() -> None:
    """Both symbols appear in the package's public __all__ (documented surface)."""
    assert "SigningTransport" in ramp_sdk.__all__
    assert "SignedOutbound" in ramp_sdk.__all__
