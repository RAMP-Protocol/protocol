"""RFC 7638 JWK Thumbprint of an Ed25519 public key (ADR-013 D4).

Relocated verbatim from the app MCP shim (src/mcp/src/ramp_mcp_shim/thumbprint.py).
The agent's RFC 9421 ``keyid`` on a bound retrieval GET is this thumbprint (Web
Bot Auth), and it MUST equal the ``agent_id`` the Exchange embedded in the URL —
so this function has to produce byte-identical output to the sdk/go oracle
(``helpers.Thumbprint``, go-jose ``JSONWebKey.Thumbprint``) and the sdk/ts edge.
All three are pinned to the shared testdata/thumbprint-vectors.json.

The canonical JWK is fixed by RFC 7638 §3.2 for OKP keys —
``{"crv":"Ed25519","kty":"OKP","x":"<base64url-nopad(pubkey)>"}``, members in
lexicographic order, no whitespace — and the thumbprint is
``base64url-nopad(SHA-256(canonical JWK))``. The literal JWK string below is the
cross-language byte contract; the source-guard test pins it.
"""

from __future__ import annotations

import hashlib

from ._b64 import b64url_nopad

_ED25519_PUBLIC_KEY_BYTES = 32


def thumbprint(public_key: bytes) -> str:
    """Return the base64url-no-pad RFC 7638 thumbprint of a raw Ed25519 key."""
    if len(public_key) != _ED25519_PUBLIC_KEY_BYTES:
        msg = f"thumbprint: public key must be {_ED25519_PUBLIC_KEY_BYTES} bytes"
        raise ValueError(msg)
    x = b64url_nopad(public_key)
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}'
    digest = hashlib.sha256(canonical.encode()).digest()
    return b64url_nopad(digest)
