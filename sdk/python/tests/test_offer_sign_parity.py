"""sdk/python offer SIGN byte-parity against the Go oracle.

Mirror of the sdk/ts sibling sdk/ts/tests/offer-sign.parity.test.ts, and a direct
sibling of the acceptance-sign exemplar (core.sign_offer_acceptance_jcs).

Under the 3-SDKs=3-SDKs decision a Python Exchange must SIGN offers, not only
verify them. This suite pins the not-yet-existing Python offer-sign face
byte-identical to the Go oracle (helpers.SignOffer): re-signing a vector's
``offer_json`` (with signature/signature_algorithm cleared) under the exchange
signer seed MUST reproduce the exact hex signature ALREADY embedded in
``offer_json["signature"]``, over the exact JCS canonical bytes.

Canonical form = JCS(protojson(offer with sig+alg cleared)) — the SAME primitive
the verify face reuses (core.canonical_offer_payload). Ed25519 is deterministic
(RFC 8032), so the Python signature MUST equal the Go one byte-for-byte.

The offer-sign half is UNAFFECTED by the signed-URL opaque-bytes decision: JCS
over proto-JSON is already deterministic and cross-language byte-agreed.

RED now for TWO expected reasons, both intended:
  1. sdk/python/ramp_sdk/core.py has no ``sign_offer_jcs`` face yet (import fails
     → collection error).
  2. The offer-verify vectors do not yet carry ``exchange_seed_hex`` (Go-emitter
     extension is a later step), so a Python re-sign cannot reproduce the hex.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import GO_TESTDATA, load_json

# Reused, NOT reinvented: the verify-side canonical builder is the byte source of
# truth (disease-scan ALLOWLIST #4). The sign face must produce the same bytes.
from ramp_sdk.core import canonical_offer_payload

# RED: sdk/python/ramp_sdk/core.py has no offer SIGN face yet (TDD red).
from ramp_sdk.core import sign_offer_jcs  # type: ignore[attr-defined]

_VECTORS = load_json(GO_TESTDATA / "offer-verify-vectors.json")["vectors"]
_POSITIVE = [v for v in _VECTORS if bool(v.get("expected_verified"))]


def test_offer_verify_vector_matrix_is_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _POSITIVE, ids=[v["name"] for v in _POSITIVE])
def test_offer_sign_matches_embedded_go_signature(vector: dict[str, Any]) -> None:
    # The Go oracle already embedded its signature in offer_json.signature; a
    # Python re-sign under the exchange seed must reproduce it byte-for-byte.
    seed = bytes.fromhex(str(vector["exchange_seed_hex"]))
    offer = vector["offer_json"]
    embedded = str(offer["signature"])

    sig_hex, alg = sign_offer_jcs(seed=seed, offer=offer)
    assert sig_hex == embedded
    assert alg == "EdDSA"


@pytest.mark.parametrize("vector", _POSITIVE, ids=[v["name"] for v in _POSITIVE])
def test_offer_sign_uses_the_same_canonical_bytes_as_verify(vector: dict[str, Any]) -> None:
    # The sign face must sign exactly canonical_offer_payload(offer) — no re-derived
    # canonicalization. Signing those bytes directly must reproduce the embedded sig.
    seed = bytes.fromhex(str(vector["exchange_seed_hex"]))
    offer = vector["offer_json"]
    payload = canonical_offer_payload(offer)
    direct = Ed25519PrivateKey.from_private_bytes(seed).sign(payload).hex()
    assert direct == str(offer["signature"])


@pytest.mark.parametrize("vector", _POSITIVE, ids=[v["name"] for v in _POSITIVE])
def test_offer_sign_under_wrong_seed_does_not_match(vector: dict[str, Any]) -> None:
    # NEGATIVE (Testing Doctrine point 10): signing under the WRONG seed MUST NOT
    # reproduce the genuine signature.
    wrong_seed = bytes([0] * 31 + [1])
    sig_hex, _alg = sign_offer_jcs(seed=wrong_seed, offer=vector["offer_json"])
    assert sig_hex != str(vector["offer_json"]["signature"])
