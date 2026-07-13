"""base64url codec — the shared byte primitive under the thumbprint, signed-URL,
and PoP helpers.

Relocated verbatim from the app MCP shim so the SDK's canonical encodings stay
byte-identical to the wire contract the sdk/go oracle emits; public home is
:mod:`ramp_sdk.b64` (also re-exported at the package top level). RFC 7515 §2
base64url without padding is the wire form for raw Ed25519 keys, RFC 7638
thumbprints, and key seeds. Standard-base64 forms (RFC 9421 ``Signature``
values, ``Content-Digest``) stay on :mod:`base64` directly — they are a
different alphabet and not this helper's concern.
"""

from __future__ import annotations

import base64
import re

# Unpadded base64url alphabet only (RFC 4648 section 5, no padding): A-Z a-z 0-9 `-` `_`.
_B64URL_NOPAD_RE = re.compile(r"[A-Za-z0-9_-]*")


def b64url_nopad(raw: bytes) -> str:
    """Encode bytes as base64url with trailing padding stripped."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(raw: str) -> bytes:
    """Decode a base64url string, re-adding any stripped ``=`` padding.

    LENIENT by design: it re-pads and, because :func:`base64.urlsafe_b64decode`
    tolerates the standard alphabet after its ``-_`` → ``+/`` remap, it also
    accepts standard-alphabet input. That leniency is REQUIRED by the RFC 9421
    ``Signature`` / PoP consumers, which carry STANDARD base64 through this same
    path — do NOT tighten it. JWK key material uses :func:`b64url_decode_strict`.
    """
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def b64url_decode_strict(raw: str) -> bytes:
    """Decode UNPADDED base64url, rejecting ``=`` padding and the standard
    (``+`` / ``/``) alphabet — the JWK OKP ``x`` contract (RFC 8037: key material
    MUST be unpadded base64url).

    Mirrors Go's ``base64.RawURLEncoding.DecodeString`` byte-for-byte so the
    tri-language WBA active-key selector / thumbprint resolver picks the SAME key
    on a directory holding a standard-alphabet or padded ``x`` (which Go rejects).
    Raises :class:`ValueError` on any non-urlsafe character, ``=`` padding, or an
    invalid unpadded length (``len % 4 == 1``).
    """
    if _B64URL_NOPAD_RE.fullmatch(raw) is None:
        raise ValueError("b64url_decode_strict: non-urlsafe alphabet or padding")
    if len(raw) % 4 == 1:
        raise ValueError("b64url_decode_strict: invalid unpadded base64url length")
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
