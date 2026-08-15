"""Idempotency — Python port of the sdk/go oracle
(helpers/idempotency.go). idempotency_key is a required, persisted,
settlement-bound field on the mutating RPCs: the server dedupes on it so a replay
returns the original result and cannot double-charge. The SDK mints a fresh key
per call by default; to make a call a deliberate replay the application reuses a
stored key. The SDK never tracks keys — the server owns the dedup store.
"""

from __future__ import annotations

import os

from .b64 import b64url_nopad

# _IDEMPOTENCY_KEY_BYTES is the entropy per key (128 bits -> 22 base64url chars).
_IDEMPOTENCY_KEY_BYTES = 16


def generate_idempotency_key() -> str:
    """Return a fresh cryptographically-random, URL-safe idempotency key (16
    random bytes -> base64url, 22 chars, no padding). Use it once per logical
    operation; reuse a stored key only to deliberately replay.
    """
    return b64url_nopad(os.urandom(_IDEMPOTENCY_KEY_BYTES))


def validate_idempotency_key(key: str) -> None:
    """Enforce the protocol's min_len=1 constraint, so the SDK rejects an empty
    key before the server does.
    """
    if key == "":
        msg = "idempotency: idempotency_key must be non-empty"
        raise ValueError(msg)
