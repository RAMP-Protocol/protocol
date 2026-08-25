"""Wire-name and hex parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors sdk/ts/tests/wire-names.parity.test.ts and the Go leg
sdk/go/helpers/wire_names_corpus_test.go.

Two textual rules every SDK applies to bytes a PEER chose, and that had drifted into one
transcription per language.

``snake_from_json_name`` inverts protojson's lowerCamelCase spelling. Three copies existed
and they did not agree: two tested an ASCII-uppercase predicate and one tested "not equal
to its own lowercase", which answer differently for a titlecase character. The rule is
ASCII ``A-Z`` and nothing else, which is exactly what protojson can produce.

Hex is how ``Offer.signature`` and the acceptance signature arrive. Go and Python refuse a
sign, whitespace and an odd length; JavaScript's ``parseInt`` accepted all three, so one
language read a signature where two read garbage.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from conftest import GO_TESTDATA, load_json
from ramp_sdk._wire_names import snake_from_json_name
from ramp_sdk.core import Mode, StaticOfferKeyResolver, Verifier

_DOC = load_json(GO_TESTDATA / "wire-names-vectors.json")
_SNAKE: list[dict[str, Any]] = _DOC["snake_from_json_name"]
_HEX: list[dict[str, Any]] = _DOC["hex_decode"]


def test_the_vector_sets_assert_both_outcomes() -> None:
    assert _SNAKE and _HEX
    assert any(not v["ok"] for v in _HEX), "no refused hex vector"
    assert any(v["ok"] for v in _HEX), "no accepted hex vector"


@pytest.mark.parametrize("vector", _SNAKE, ids=[v["name"] for v in _SNAKE])
def test_snake_from_json_name(vector: dict[str, Any]) -> None:
    assert snake_from_json_name(vector["json_name"]) == vector["snake"]


@pytest.mark.parametrize("vector", _HEX, ids=[v["name"] for v in _HEX])
def test_hex_decode(vector: dict[str, Any]) -> None:
    """Driven through the Verifier, whose REJECTION REASON separates the two outcomes.

    ``"offer signature is not valid hex"`` means the decode refused the value; ``"offer
    signature invalid"`` means it decoded and did not match. Both languages already word it
    that way, so the corpus is asserted through a public face and nothing new is exported.

    Asserting only that verification failed would assert nothing: it fails for every vector
    either way, which is how the TypeScript half of this replay stayed green while its
    decoder was lenient.
    """
    verifier = Verifier(
        mode=Mode.STRICT,
        resolver=StaticOfferKeyResolver({"e.test": bytes(32)}),
        now=lambda: 0,
    )
    result = verifier.sort(
        [{"exchange": "e.test", "signature": vector["hex"], "expires_at": "2099-01-01T00:00:00Z"}]
    )
    assert not result.verified
    reason = result.rejected[0].reason
    refused_the_decode = "not valid hex" in reason
    assert refused_the_decode is (not vector["ok"]), (
        f"{vector['name']}: oracle says decodes={vector['ok']}, "
        f"this reader says decodes={not refused_the_decode} ({reason})"
    )


def test_a_value_only_a_lenient_decoder_would_accept_does_not_verify() -> None:
    """The ACCEPTANCE decoder is a second copy of the rule, on a face answering a boolean.

    A refused decode and a signature that merely does not match both read ``False``, so no
    corpus vector fed to it can separate them — which is how this half stayed ungated while
    the offer half was pinned.

    What separates them is a value a LENIENT decoder reads as the RIGHT bytes.
    ``bytes.fromhex`` skips ASCII whitespace between bytes, so a genuine signature with one
    space inserted decodes to the identical bytes there and is refused by the strict check.
    That is the mutation this test exists to fail.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ramp_sdk.core import sign_offer_acceptance_jcs, verify_offer_acceptance_jcs

    seed = bytes(range(32))
    public = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    ).decode()
    fields = {
        "offer_sig": "abcd",
        "requester_id": "agent-1",
        "requester_domain": "agent.test",
        "idempotency_key": "idem-1",
    }
    genuine, _algorithm = sign_offer_acceptance_jcs(seed=seed, **fields)

    # The control: it verifies as issued.
    assert verify_offer_acceptance_jcs(**fields, signature_hex=genuine, pubkey_b64=public)

    # A space between two pairs. bytes.fromhex rebuilds the exact signature from this.
    lenient_only = f"{genuine[:4]} {genuine[4:]}"
    assert lenient_only != genuine
    assert not verify_offer_acceptance_jcs(
        **fields, signature_hex=lenient_only, pubkey_b64=public
    ), "a signature carrying embedded whitespace was accepted"
