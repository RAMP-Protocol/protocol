"""sdk/python/ramp_sdk/core offer-verify parity.

Mirror of the sdk/ts core offer-verify parity suite. The L2 core Verifier splits
received offers into {verified, rejected} by ed25519-verifying the canonical
offer-signature. The signed
payload is NO LONGER Go deterministic protobuf-binary — it is RFC 8785 JCS over the
canonical proto-JSON of the Offer with signature/signature_algorithm cleared:

    signed_payload = JCS(protojson(offer with sig+alg cleared))

so any component (Go/TS/Python) reproduces the exact signed bytes without a
protobuf binary codec. Python core reproduces JCS(protojson(offer)) via a vetted
JCS library over the generated Pydantic types' JSON aligned to the pinned
proto-JSON option set, then ed25519-verifies, returning {verified, rejected} + the
unforgeable VerifiedOffer.

RED now for TWO expected reasons:
  1. sdk/python/ramp_sdk/core does not exist yet (the Verifier import cannot
     resolve).
  2. The shared offer-verify vector MATRIX
     sdk/go/helpers/testdata/offer-verify-vectors.json does not exist yet — the
     implement step (a) switches Go canonicalOfferPayload to JCS(protojson), (b)
     extends the Go golden emitter to emit this matrix. load_json raises
     FileNotFoundError → collection failure, a clean TDD-red signal.

The matrix MUST exercise the hard JCS encodings, not a
single happy path: minimal / struct_ext_multi_key (forces recursive JCS key-sort)
/ two_timestamps / repeated_terms_enum / tamper_negative.
"""

from __future__ import annotations

import base64

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/core does not exist yet (TDD red).
from ramp_sdk.core import Mode, StaticOfferKeyResolver, Verifier  # type: ignore[import-not-found]

# RED (also): the shared offer-verify vector matrix does not exist yet. The
# implement step's Go emitter (JCS canonicalization) produces it; referencing it by
# its planned path keeps this suite RED now.
_OFFER_VERIFY_VECTORS_PATH = GO_TESTDATA / "offer-verify-vectors.json"
_VECTORS = load_json(_OFFER_VERIFY_VECTORS_PATH)["vectors"]

# The required matrix names: the hard JCS encodings, not a
# single happy path.
_REQUIRED_MATRIX = {
    "minimal",
    "struct_ext_multi_key",
    "two_timestamps",
    "repeated_terms_enum",
    "tamper_negative",
}

# The freshness dimension (M-7): the port must agree with the Go oracle on the
# expires_at verdict, including the fail-closed cases. Pinned so a regenerated
# corpus that silently drops the missing/expired vectors fails loudly here — a
# port cannot revert to fail-open (missing expires_at ⇒ "fresh") undetected.
_REQUIRED_FRESHNESS = {
    "fresh_at_now_inclusive",
    "expired_past",
    "missing_expires_at",
}


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def test_offer_verify_vector_matrix_is_nonempty() -> None:
    assert len(_VECTORS) > 0


def test_offer_verify_matrix_covers_the_hard_jcs_encodings() -> None:
    # One happy-path vector would pass while Struct-key-ordering / Timestamp
    # encoding / repeated-field ordering diverge silently. Pin the required matrix.
    names = {str(v["name"]) for v in _VECTORS}
    assert _REQUIRED_MATRIX <= names


def test_offer_verify_matrix_covers_the_freshness_dimension() -> None:
    # Guards M-7: the fail-closed expires_at contract must stay exercised across
    # ports. If the corpus loses these, this suite goes red before a fail-open
    # regression can ship.
    names = {str(v["name"]) for v in _VECTORS}
    assert _REQUIRED_FRESHNESS <= names


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_verifier_sorts_offer_by_jcs_signature(vector: dict[str, object]) -> None:
    exchange = str(vector["exchange"])
    exchange_pub = _b64url_nopad_decode(str(vector["exchange_pub_b64url"]))
    now_unix = int(vector["now_unix"])  # type: ignore[call-overload]
    expected_verified = bool(vector["expected_verified"])

    # Strict mode (fail-closed default): resolver knows exactly this exchange's
    # offer-signing key; the Verifier reproduces JCS(protojson(offer)) and
    # ed25519-verifies. Clock injected for the freshness gate.
    resolver = StaticOfferKeyResolver({exchange: exchange_pub})
    verifier = Verifier(mode=Mode.STRICT, resolver=resolver, now=lambda: now_unix)

    result = verifier.sort([vector["offer_json"]])

    if expected_verified:
        assert len(result.verified) == 1
        assert len(result.rejected) == 0
    else:
        assert len(result.verified) == 0
        assert len(result.rejected) == 1
        assert result.rejected[0].reason is not None
