"""HashURL — Python port of the sdk/go oracle (helpers/signedurl.go HashURL). It
returns the SHA-256 digest of a signed URL (the transaction_log.signed_url_hash
value, 32 bytes). The hash is over the URL string bytes VERBATIM (opaque bytes,
no WHATWG renormalization — consistent with the opaque-URL signing contract). The
Python face is sync (hashlib); the shared vector encodes the digest as hex.
"""

from __future__ import annotations

import hashlib


def hash_url(signed: str) -> bytes:
    """Return the raw 32-byte SHA-256 digest of the signed URL's verbatim UTF-8
    bytes.
    """
    return hashlib.sha256(signed.encode()).digest()
