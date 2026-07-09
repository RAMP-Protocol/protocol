"""Thumbprint parity (Python side) — TDD red for ixs7u.6.

Mirrors the sdk/ts sibling sdk/ts/tests/thumbprint.parity.test.ts in pytest.

sdk/python `ramp_sdk.thumbprint(pubkey)` MUST reproduce, byte-for-byte, the
RFC 7638 JWK Thumbprint the sdk/go oracle emits. The shared vectors at
sdk/go/helpers/testdata/thumbprint-vectors.json are the cross-language guard:
each entry is a base64url-no-pad raw 32-byte Ed25519 public key and its expected
base64url-no-pad thumbprint (= base64url(SHA-256(canonical JWK))). The canonical
JWK is `{"crv":"Ed25519","kty":"OKP","x":"<b64url-nopad(pubkey)>"}` with members
in lexicographic order, no whitespace. The last vector uses the RFC 8032
Ed25519 test-vector public key.

RED now purely because `ramp_sdk` does not exist yet (the import below cannot
resolve → collection error). The implement step relocates the app's
src/mcp/src/ramp_mcp_shim/thumbprint.py into sdk/python/ramp_sdk/thumbprint.py,
at which point this goes green with no change to the assertions.
"""

from __future__ import annotations

import base64

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/thumbprint.py does not exist yet (TDD red).
from ramp_sdk.thumbprint import thumbprint  # type: ignore[import-not-found]

_VECTORS = load_json(GO_TESTDATA / "thumbprint-vectors.json")["vectors"]


def _b64url_nopad_decode(s: str) -> bytes:
    """Inverse of the encoding the vectors carry the pubkey in (b64url no pad)."""
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def test_thumbprint_vector_file_is_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize(
    "vector",
    _VECTORS,
    ids=[v["public_key_b64url"] for v in _VECTORS],
)
def test_thumbprint_matches_go_oracle(vector: dict[str, str]) -> None:
    pub = _b64url_nopad_decode(vector["public_key_b64url"])
    assert len(pub) == 32
    got = thumbprint(pub)
    assert got == vector["thumbprint"]
