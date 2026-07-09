"""sdk/python verbatim-canonicalization guard — TDD red for ov97t.16.

Mirror of the sdk/ts sibling sdk/ts/tests/signedurl-verbatim.guard.test.ts.

THE CONTRACT (Constantine, 2026-07-07): the signed-URL signature covers
``GET\\n<url>`` as OPAQUE URL BYTES. Signer and verifier MUST agree on ``<url>``
byte-for-byte. The ONLY permitted transform is deterministic query handling
(add exp/kid/agent_id, remove sig, sort query) — NEVER host-lowercasing,
default-port stripping, or path-escaping.

This guard pins that invariant WITHOUT a Go vector: it asserts that the sign face
and the verify face build the SAME canonical ``GET\\n<url>`` bytes for a TRICKY
URL. Because Ed25519 is deterministic, byte-identical canonical bytes are exactly
what makes a self-signed URL verify — so the guard is:
    sign(source_url) -> signed_url ; verify(signed_url) is valid
over a URL whose host case, explicit :443, and path space/percent would be mangled
by any urlsplit/urlunsplit normalization on EITHER side.

RED now for reasons that are ALL intended:
  1. sdk/python/ramp_sdk/signedurl.py has no ``sign_ed25519_signed_url`` face yet
     (import fails → collection error).
  2. Even once the sign face lands, ``_canonical_message`` currently round-trips
     through ``urlsplit``/``urlunsplit`` (which can drop/alter host+path bytes). A
     verbatim signer + a normalizing verifier disagree on the tricky URL → the
     self-signed URL fails to verify. This guard stays RED until BOTH faces
     canonicalize verbatim.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# RED: sdk/python/ramp_sdk/signedurl.py has no sign face yet (TDD red).
from ramp_sdk.signedurl import sign_ed25519_signed_url  # type: ignore[attr-defined]
from ramp_sdk.signedurl import verify_ed25519_signed_url

# TRICKY URLs — mixed-case host, explicit :443, space and percent in the PATH.
# These are exactly the inputs a urlsplit/urlunsplit-normalizing canonicalizer
# mangles (Go url.URL.String() escapes the space; a verbatim contract must not).
_TRICKY_SOURCE_URLS = [
    "https://CDN.Example:443/a path/doc",
    "https://CDN.Example/Doc%2Fpart?z=9&a=2",
    "https://Origin.EXAMPLE.com:443/deep/a b/c",
]

_SEED = bytes.fromhex("1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30")
_NOW_UNIX = 1_700_000_100
_EXP_UNIX = 1_700_000_300


@pytest.mark.parametrize("source", _TRICKY_SOURCE_URLS)
def test_self_signed_tricky_url_verifies_verbatim(source: str) -> None:
    priv = Ed25519PrivateKey.from_private_bytes(_SEED)
    pub = priv.public_key().public_bytes_raw()

    signed = sign_ed25519_signed_url(
        source, seed=_SEED, kid="ex.v1", agent_id="", exp=_EXP_UNIX
    )

    # If EITHER face normalizes host/port/path, the sign-time and verify-time bytes
    # differ and this fails — proving the leak.
    result = verify_ed25519_signed_url(
        signed,
        now=_NOW_UNIX,
        resolve_key=lambda kid: pub if kid == "ex.v1" else None,
    )
    assert result.valid is True


@pytest.mark.parametrize("source", _TRICKY_SOURCE_URLS)
def test_signed_url_preserves_host_and_path_bytes_verbatim(source: str) -> None:
    signed = sign_ed25519_signed_url(
        source, seed=_SEED, kid="ex.v1", agent_id="", exp=_EXP_UNIX
    )
    # The emitted URL must still carry the ORIGINAL host casing, the explicit :443,
    # and the raw path bytes — a urlsplit/urlunsplit round-trip that normalized any
    # of these would break this prefix check.
    prefix = source.split("?", 1)[0]
    assert signed.startswith(prefix)
