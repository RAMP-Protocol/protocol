"""RFC 9421 request SIGN byte-parity (Python side).

No sibling exists in sdk/ts (the TS edge never SIGNs a request — it verifies);
this is the surface sdk/python adds. The byte oracle is the Go
SignRequest (sdk/go/helpers/sign.go) + buildSignatureBase (sigbase.go); the port
source is the app's src/mcp/src/ramp_mcp_shim/httpsig.py Signer.sign.

`ramp_sdk.httpsig.sign_request(...)` MUST produce, byte-for-byte, the same
signature base, Signature-Input, and Signature the Go oracle emits. The shared
vector file sdk/go/helpers/testdata/sign-request-vectors.json does NOT exist yet
— the implement step EXTENDS the Go golden emitter to create it (from SignRequest
over a fixed request+body+created+expires, cross-checked by round-tripping
through the real Go SignRequest/VerifyRequest). Referencing it by its planned
path keeps this test RED now on BOTH the missing module AND the missing file.

Contract (the WBA identity split superseded the earlier exactly-four-components
pin — signature-agent joined the required covered set platform-wide, so a
four-component signer would produce signatures the platform rejects):
  - covered set is EXACTLY @method @target-uri content-digest authorization
    signature-agent (NO biscuit / no conditional component beyond these five);
  - Signature-Agent is bound like Authorization: an empty string is still
    covered (the static bootstrap path) — the empty-bind case is a distinct
    vector;
  - created/expires are injected NON-zero (1_700_000_000 / 1_700_000_600 — the
    pop emitter's pinned window; Go omits created/expires from the base when 0,
    so zero values would drop from the signature base);
  - the empty-authorization bound case is a distinct vector (empty-string value
    still covered);
  - assert byte-equality of the FULL signature base + Signature-Input +
    Signature, and that each vector round-trips (verify at a pinned now inside
    the window).

L1 purity (ADR-020 §1/§4): created/expires are INJECTED — sign_request reads no
wall clock. The Signature value is STANDARD base64 (`sig1=:<b64>:`), NOT
b64url-nopad — do not unify with the thumbprint encoding.
"""

from __future__ import annotations

import base64
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/ramp_sdk/httpsig.py does not exist yet (TDD red).
from ramp_sdk.httpsig import sign_request, verify_request  # type: ignore[import-not-found]

# RED (also): this vector file is produced by the Go emitter extension the
# implement step adds; it does not exist yet. load_json raises FileNotFoundError
# → the suite fails at collection, which is a clean TDD-red signal.
_SIGN_REQUEST_VECTORS_PATH = GO_TESTDATA / "sign-request-vectors.json"
_VECTORS = load_json(_SIGN_REQUEST_VECTORS_PATH)["vectors"]

# The covered set the emitter MUST use: exactly these five (signature-agent
# joined with the WBA split), no conditional biscuit component.
_EXPECTED_COVERED = '("@method" "@target-uri" "content-digest" "authorization" "signature-agent")'


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def test_sign_request_vector_file_is_nonempty() -> None:
    assert len(_VECTORS) > 0


def test_sign_request_vector_file_exists_and_covers_empty_authorization() -> None:
    # The vector set MUST include the empty-authorization bound case — an
    # authorization value of "" that is still covered.
    assert _SIGN_REQUEST_VECTORS_PATH.exists()
    authz_values = {str(v.get("authorization", "MISSING")) for v in _VECTORS}
    assert "" in authz_values, (
        "sign-request-vectors.json must include an empty-authorization bound case"
    )


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_sign_request_produces_byte_identical_signature(vector: dict[str, object]) -> None:
    # Enumerated fixed request: method, absolute URL,
    # body→content-digest, authorization value, created, expires. created/expires
    # are INJECTED (L1-pure, no wall clock).
    seed = bytes.fromhex(str(vector["signer_seed_hex"]))
    body = bytes.fromhex(str(vector["body_hex"]))

    result = sign_request(
        method=str(vector["method"]),
        url=str(vector["url"]),
        body=body,
        authorization=str(vector["authorization"]),
        signer_seed=seed,
        keyid=str(vector["keyid"]),
        created=int(vector["created"]),  # type: ignore[arg-type]
        expires=int(vector["expires"]),  # type: ignore[arg-type]
        signature_agent=str(vector.get("signature_agent", "")),
    )

    # Full signature base is byte-identical to the Go oracle.
    assert result.signature_base == str(vector["signature_base"])
    # Covered set is exactly the five RAMP components (no conditional 6th).
    assert _EXPECTED_COVERED in result.signature_input
    # Signature-Input and Signature headers are byte-identical.
    assert result.signature_input == str(vector["signature_input"])
    assert result.signature == str(vector["signature"])


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_sign_request_roundtrips_through_verify(vector: dict[str, object]) -> None:
    # Each vector round-trips: verify the recorded headers at a pinned `now`
    # inside the created/expires window against the recorded public key.
    pub = _b64url_nopad_decode(str(vector["pubkey_b64url"]))
    body = bytes.fromhex(str(vector["body_hex"]))
    now = (int(vector["created"]) + int(vector["expires"])) // 2  # type: ignore[call-overload]

    # Sanity: the recorded pubkey matches the recorded seed (guards a mis-authored
    # vector without reaching past the public surface).
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    derived = (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(str(vector["signer_seed_hex"])))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    assert derived == pub
    Ed25519PublicKey.from_public_bytes(pub)  # well-formed key

    result = verify_request(
        method=str(vector["method"]),
        url=str(vector["url"]),
        body=body,
        signature_input=str(vector["signature_input"]),
        signature=str(vector["signature"]),
        content_digest=str(vector["content_digest"]),
        authorization=str(vector["authorization"]),
        pubkey=pub,
        now=now,
        signature_agent=str(vector.get("signature_agent", "")),
    )
    assert result.valid is True


def test_sign_request_vectors_live_under_shared_go_testdata() -> None:
    # Guard the Core Invariant: the oracle is the SHARED Go emitter output, not a
    # copied app fixture.
    assert _SIGN_REQUEST_VECTORS_PATH.parent == pathlib.Path(GO_TESTDATA)
