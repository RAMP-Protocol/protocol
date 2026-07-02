"""Offer-acceptance sign/verify byte-parity (Python side) — TDD red for ixs7u.6.

No sdk/ts sibling (offer-acceptance is agent/exchange-side, not edge). Byte
oracle = the Go SignOfferAcceptance / VerifyOfferAcceptance
(sdk/go/helpers/acceptance.go, proto.MarshalOptions{Deterministic}); port source
= the app's src/mcp/src/ramp_mcp_shim/acceptance.py (hand-rolled deterministic
proto3 marshal of AgentAcceptancePayload fields 1-4 by proto NUMBER, hex Ed25519,
"EdDSA", fail-closed on empty offer_sig).

`ramp_sdk.acceptance.{canonical_acceptance_payload,sign_offer_acceptance,
verify_offer_acceptance}` MUST produce byte-identical canonical bytes + signature
to the Go oracle. The shared vector file
sdk/go/helpers/testdata/acceptance-vectors.json does NOT exist yet — the implement
step EXTENDS the Go golden emitter to create it, SEEDED with the SAME seed the
app fixture uses (0102..1f20) so the emitted vectors cross-check byte-for-byte
against the app's committed testdata/acceptance-vectors.json. Referencing it by
its planned path keeps this test RED now on BOTH the missing module AND the
missing file.

Contract pinned by the BINDING architect-review amendment (supersedes plan step
2):
  - keep the empty-domain (proto3 field-3 default-skip) case;
  - add the fail-closed empty-`offer_sig` NEGATIVE as a non-signable assertion
    (an empty anchor would let the acceptance float free of any concrete offer).

The canonical BYTES stay hand-rolled (gen/python is Pydantic-only, no proto
serializer); the typed surface reuses generated AgentAcceptancePayload where the
implement step wires it. proto3 omits an empty-string field entirely — the
empty-domain vector's canonical bytes MUST skip field 3.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/acceptance.py does not exist yet (TDD red).
from ramp_sdk.acceptance import (  # type: ignore[import-not-found]
    canonical_acceptance_payload,
    sign_offer_acceptance,
    verify_offer_acceptance,
)

# RED (also): this vector file is produced by the Go emitter extension the
# implement step adds (seed 0102..1f20); it does not exist yet. load_json raises
# FileNotFoundError → collection failure, a clean TDD-red signal.
_ACCEPTANCE_VECTORS_PATH = GO_TESTDATA / "acceptance-vectors.json"
_VECTORS = load_json(_ACCEPTANCE_VECTORS_PATH)["vectors"]

# The fixed seed the emitter + app fixture share (BINDING amendment).
_SHARED_SEED_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"


def test_acceptance_vector_file_is_nonempty() -> None:
    assert len(_VECTORS) > 0


def test_acceptance_vectors_include_empty_domain_case() -> None:
    # The empty-domain case pins the proto3 field-3 default-skip contract.
    names = {str(v["name"]) for v in _VECTORS}
    assert "empty_domain" in names


def test_acceptance_vectors_use_the_shared_app_seed() -> None:
    # Cross-check: the emitter is seeded with the SAME seed as the app fixture, so
    # the shared Go oracle and the app provably agree (Core Invariant).
    for v in _VECTORS:
        assert str(v["seed_hex"]) == _SHARED_SEED_HEX


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_canonical_bytes_match_go_oracle(vector: dict[str, object]) -> None:
    payload = canonical_acceptance_payload(
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert payload.hex() == str(vector["canonical_bytes_hex"])


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_sign_offer_acceptance_matches_go_oracle(vector: dict[str, object]) -> None:
    signature_hex, algorithm = sign_offer_acceptance(
        seed=bytes.fromhex(_SHARED_SEED_HEX),
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert algorithm == "EdDSA"
    assert signature_hex == str(vector["signature_hex"])


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_verify_offer_acceptance_accepts_the_oracle_signature(vector: dict[str, object]) -> None:
    ok = verify_offer_acceptance(
        pubkey_b64=str(vector["pubkey_b64"]),
        signature_hex=str(vector["signature_hex"]),
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert ok is True


def test_empty_offer_sig_fails_closed_on_canonical() -> None:
    # Fail-closed on empty offer_sig (mirror Go canonicalAcceptancePayload): an
    # empty anchor would let the acceptance float free of any concrete offer. The
    # canonicalizer MUST refuse to produce bytes, so no signature can be made.
    with pytest.raises(ValueError):
        canonical_acceptance_payload(
            offer_sig="",
            requester_id="agent-1",
            requester_domain="agent.example.com",
            idempotency_key="idem-1",
        )


def test_empty_offer_sig_fails_closed_on_sign() -> None:
    with pytest.raises(ValueError):
        sign_offer_acceptance(
            seed=bytes.fromhex(_SHARED_SEED_HEX),
            offer_sig="",
            requester_id="agent-1",
            requester_domain="agent.example.com",
            idempotency_key="idem-1",
        )
