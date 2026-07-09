"""ramp_sdk.b64 — the public base64url codec module and its top-level re-export."""

from __future__ import annotations

from ramp_sdk.b64 import b64url_decode, b64url_nopad


# ---- round-trip parity ---------------------------------------------------


def test_b64url_nopad_encodes_and_decodes_round_trip() -> None:
    """b64url_nopad followed by b64url_decode returns the original bytes."""
    raw = bytes(range(32))
    assert b64url_decode(b64url_nopad(raw)) == raw


def test_b64url_nopad_strips_padding() -> None:
    """The encoded string contains no '=' padding characters."""
    result = b64url_nopad(b"\x00" * 3)  # length that would normally produce padding
    assert "=" not in result


def test_b64url_decode_handles_missing_padding() -> None:
    """b64url_decode tolerates a raw string with no padding and still round-trips."""
    raw = b"\xfb\xfc\xfd"
    encoded = b64url_nopad(raw)
    assert "=" not in encoded
    assert b64url_decode(encoded) == raw


def test_b64url_nopad_empty_bytes() -> None:
    assert b64url_nopad(b"") == ""
    assert b64url_decode("") == b""


# ---- top-level re-export -------------------------------------------------


def test_top_level_ramp_sdk_exports_b64url_nopad() -> None:
    """ramp_sdk.__init__ re-exports b64url_nopad at the top level."""
    # RED: __init__ currently does NOT import from .b64 (the module doesn't
    # exist yet), so this import also fails at collection time.
    from ramp_sdk import b64url_nopad as top_b64url_nopad  # type: ignore[attr-defined]

    raw = bytes(range(16))
    assert top_b64url_nopad(raw) == b64url_nopad(raw)
