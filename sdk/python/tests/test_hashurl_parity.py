"""HashURL parity (Python side) — TDD red for djeue.

Mirrors the sdk/ts sibling sdk/ts/tests/hashurl.parity.test.ts.

``ramp_sdk.hashurl.hash_url`` MUST reproduce the sdk/go oracle: SHA-256 over the
VERBATIM URL bytes (opaque bytes, no WHATWG renormalization), returning the raw
32-byte digest (the transaction_log.signed_url_hash). The shared vectors at
sdk/go/helpers/testdata/hashurl-vectors.json carry {url, sha256_hex}. The Python
face is sync (hashlib); the vector encodes the digest as hex.

RED now purely because ``ramp_sdk.hashurl`` does not exist yet.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/hashurl.py does not exist yet (TDD red — missing face).
from ramp_sdk.hashurl import hash_url  # type: ignore[import-not-found]

_VECTORS = load_json(GO_TESTDATA / "hashurl-vectors.json")["vectors"]


def test_hashurl_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_hash_url_matches_go_oracle(vector: dict) -> None:
    digest = hash_url(vector["url"])
    assert len(digest) == 32
    assert digest.hex() == vector["sha256_hex"]
