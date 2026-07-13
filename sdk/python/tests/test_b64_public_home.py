"""ramp_sdk.b64 — the public base64url codec module and its top-level re-export."""

from __future__ import annotations

import base64

import pytest

from ramp_sdk.b64 import b64url_decode, b64url_decode_strict, b64url_nopad


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


# ---- strict JWK-x decode (RFC 8037) --------------------------------------


def test_b64url_decode_strict_accepts_valid_unpadded_urlsafe() -> None:
    """A valid unpadded base64url string decodes identically to the lenient path."""
    raw = bytes(range(32))
    encoded = b64url_nopad(raw)  # unpadded urlsafe, the JWK `x` wire form
    assert b64url_decode_strict(encoded) == raw
    assert b64url_decode_strict(encoded) == b64url_decode(encoded)


def test_b64url_decode_strict_rejects_padding() -> None:
    """`=` padding — which the lenient path re-adds/tolerates — is rejected."""
    raw = b"\x00" * 32
    padded = base64.urlsafe_b64encode(raw).decode()  # carries trailing '='
    assert "=" in padded
    with pytest.raises(ValueError, match="non-urlsafe alphabet or padding"):
        b64url_decode_strict(padded)


def test_b64url_decode_strict_rejects_standard_alphabet() -> None:
    """Standard-alphabet (`+`/`/`) input that the lenient path silently accepts
    (via its `-_`->`+/` remap) is rejected — matching Go's RawURLEncoding."""
    # Bytes whose standard base64 encoding contains both '+' and '/'.
    raw = bytes([0xFB, 0xFF, 0xBF])
    std = base64.standard_b64encode(raw).decode().rstrip("=")
    assert "+" in std or "/" in std
    # The lenient decoder accepts it; the strict one rejects it.
    assert b64url_decode(std) == raw
    with pytest.raises(ValueError, match="non-urlsafe alphabet or padding"):
        b64url_decode_strict(std)


def test_b64url_decode_strict_rejects_invalid_length() -> None:
    """A length ≡ 1 (mod 4) is structurally invalid unpadded base64url."""
    with pytest.raises(ValueError, match="invalid unpadded base64url length"):
        b64url_decode_strict("A")


# ---- top-level re-export -------------------------------------------------


def test_top_level_ramp_sdk_exports_b64url_nopad() -> None:
    """ramp_sdk.__init__ re-exports b64url_nopad at the top level."""
    # RED: __init__ currently does NOT import from .b64 (the module doesn't
    # exist yet), so this import also fails at collection time.
    from ramp_sdk import b64url_nopad as top_b64url_nopad  # type: ignore[attr-defined]

    raw = bytes(range(16))
    assert top_b64url_nopad(raw) == b64url_nopad(raw)
