"""Idempotency MINT behaviour (Python side) — TDD red for djeue.

Mirrors the sdk/ts sibling sdk/ts/tests/idempotency.behavior.test.ts.

generate_idempotency_key carries entropy → NOT vector-gated. The Go oracle mints 16
crypto-random bytes → base64.RawURLEncoding (22 chars, no padding). The Python
face ``generate_idempotency_key()`` MUST match that SHAPE: a 22-char base64url string,
charset [-A-Za-z0-9_], no padding, and distinct across N calls (entropy).

RED now purely because ``ramp_sdk.idempotency`` does not exist yet.
"""

from __future__ import annotations

import re

# RED: sdk/python/ramp_sdk/idempotency.py does not exist yet (TDD red).
from ramp_sdk.idempotency import generate_idempotency_key  # type: ignore[import-not-found]

_BASE64URL_22 = re.compile(r"^[-A-Za-z0-9_]{22}$")


def test_mints_22char_base64url_no_padding() -> None:
    key = generate_idempotency_key()
    assert _BASE64URL_22.match(key) is not None
    assert "=" not in key


def test_mints_distinct_keys_across_n_calls() -> None:
    n = 512
    seen = {generate_idempotency_key() for _ in range(n)}
    assert len(seen) == n
