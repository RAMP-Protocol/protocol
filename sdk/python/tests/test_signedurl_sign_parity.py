"""sdk/python signed-URL SIGN byte-parity against the Go oracle — TDD red for ov97t.16.

Mirror of the sdk/ts sibling sdk/ts/tests/signedurl-sign.parity.test.ts.

Under the 3-SDKs=3-SDKs decision a Python Exchange must MINT signed delivery URLs,
not only verify them. This suite pins the not-yet-existing Python sign face
byte-identical to the Go oracle (helpers.SignURLEd25519): re-signing a vector's
SOURCE url under its signer seed MUST reproduce the Go-emitted ``signed_url``
STRING exactly.

THE CONTRACT UNDER TEST (Constantine, 2026-07-07): the signature covers
``GET\\n<url>`` as OPAQUE URL BYTES. Neither signer nor verifier re-normalizes
scheme/host/path — the ONLY permitted transform is deterministic query handling
(add exp/kid/agent_id, remove sig, sort query). Today verify uses
``urlsplit``/``urlunsplit`` (which can drop/alter host+path bytes); that is the
divergence this contract eliminates.

RED now for THREE expected reasons, all intended:
  1. sdk/python/ramp_sdk/signedurl.py has no ``sign_ed25519_signed_url`` face yet
     (import fails → collection error).
  2. The signed-URL vectors do not yet carry ``signer_seed_hex`` (Go-emitter
     extension is a later step), so a Python re-sign cannot reproduce the string.
  3. The TRICKY-URL vectors named below (mixed-case host, explicit :443,
     space/percent in the PATH) — the cases that expose the normalization
     divergence — do not exist yet; the implement step emits them.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/signedurl.py has no sign face yet (TDD red).
from ramp_sdk.signedurl import sign_ed25519_signed_url  # type: ignore[attr-defined]

_SIGNEDURL_VECTORS = load_json(GO_TESTDATA / "signedurl-vectors.json")

# The tricky-URL vectors the implement step MUST emit — the cases that expose the
# host-lowercasing / port-stripping / path-escaping divergence. Naming them here
# keeps the suite RED until they exist and documents the contract they pin.
_REQUIRED_TRICKY_VECTORS = {
    "tricky_mixed_case_host",
    "tricky_explicit_default_port",
    "tricky_space_in_path",
    "tricky_percent_in_path",
}


def test_signedurl_vector_file_is_nonempty() -> None:
    assert len(_SIGNEDURL_VECTORS) > 0


def test_tricky_url_vectors_that_expose_the_divergence_exist() -> None:
    # Mixed-case host, explicit :443, space/percent in the PATH — the cases a
    # urlsplit/urlunsplit-normalizing sign face gets WRONG. Their absence is a
    # legitimate TDD-red signal for the Go-emitter extension.
    names = {str(v["name"]) for v in _SIGNEDURL_VECTORS}
    assert _REQUIRED_TRICKY_VECTORS <= names


_POSITIVE = [v for v in _SIGNEDURL_VECTORS if bool(v.get("expected_valid"))]


@pytest.mark.parametrize("vector", _POSITIVE, ids=[v["name"] for v in _POSITIVE])
def test_signedurl_sign_matches_go_oracle_string(vector: dict[str, object]) -> None:
    # POSITIVE parity: re-sign the vector's SOURCE under its signer seed; the
    # emitted STRING must be byte-identical to the oracle's signed_url.
    seed = bytes.fromhex(str(vector["signer_seed_hex"]))
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    emitted = sign_ed25519_signed_url(
        str(vector["source_url"]),
        seed=seed,
        kid=str(vector["kid"]),
        agent_id=str(vector["agent_id"]),
        exp=int(vector["exp_unix"]),  # type: ignore[call-overload]
    )
    assert emitted == str(vector["signed_url"])
    # Guard against an accidentally-unused priv import; the real assertion is the
    # string equality above (deterministic Ed25519).
    assert isinstance(priv, Ed25519PrivateKey)


@pytest.mark.parametrize("vector", _POSITIVE, ids=[v["name"] for v in _POSITIVE])
def test_signedurl_sign_under_wrong_seed_does_not_match(vector: dict[str, object]) -> None:
    # NEGATIVE (Testing Doctrine point 10): re-signing the SAME source under the
    # WRONG seed MUST NOT reproduce the genuine signed_url — different key, different
    # deterministic signature, different string.
    wrong_seed = bytes([0] * 31 + [1])
    emitted = sign_ed25519_signed_url(
        str(vector["source_url"]),
        seed=wrong_seed,
        kid=str(vector["kid"]),
        agent_id=str(vector["agent_id"]),
        exp=int(vector["exp_unix"]),  # type: ignore[call-overload]
    )
    assert emitted != str(vector["signed_url"])
