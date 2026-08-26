"""RFC 9421 request SIGN byte-parity (Python side).

The byte oracle is the Go SignRequest (sdk/go/helpers/sign.go) + buildSignatureBase
(sigbase.go); the TS sibling is sdk/ts/tests/sign-request.parity.test.ts over
sdk/ts/core/sign-request.ts, and all three replay the same shared vector file
sdk/go/helpers/testdata/sign-request-vectors.json.

``ramp_sdk.httpsig.sign_request(...)`` MUST produce, byte-for-byte, the same signature
base, Signature-Input and Signature the Go oracle emits — and MUST hand back the same
header set a signed request carries, which is what emitted_headers pins.
"""

from __future__ import annotations

import base64
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from conftest import GO_TESTDATA, load_json

from ramp_sdk.httpsig import sign_request, verify_request

#: The shared Go-emitted oracle every port replays.
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
def test_sign_outbound_emits_the_header_set_the_oracle_emits(
    vector: dict[str, object],
) -> None:
    """The headers a signed request CARRIES, compared as a whole map.

    Every other assertion in this file says what was SIGNED. ``emitted_headers`` says
    what is SENT, and the two are different claims. A verifier rebuilds the signature
    base from the request it received, so a covered value bound but never sent is not
    bound at all: it reads the covered names off ``signature-input``, finds nothing on
    the wire under one of them, and refuses.

    See docs/design-history.md, "A covered header the peer never receives is not bound".

    Compared as a MAP, not key by key. Membership assertions are what let the defect ship;
    only a whole-set comparison notices the next header to go missing.

    The oracle records a LIST per name because the verifier reads one — it joins repeated
    values with ", " before rebuilding the base. This face returns a dict, which cannot
    hold a duplicate at all, so each value wraps to a one-element list: the shape says
    where a duplicate CAN arise, which is the merge in a transport wrapper, not here.
    """
    from ramp_sdk.signing_transport import SigningTransport

    created, expires = int(vector["created"]), int(vector["expires"])  # type: ignore[call-overload]
    transport = SigningTransport(
        signer_seed=bytes.fromhex(str(vector["signer_seed_hex"])),
        keyid=str(vector["keyid"]),
        signature_agent=str(vector["signature_agent"]),
        window=lambda: (created, expires),
    )
    signed = transport.sign_outbound(
        method=str(vector["method"]),
        url=str(vector["url"]),
        body=bytes.fromhex(str(vector["body_hex"])),
        authorization=str(vector["authorization"]),
    )
    # Keys VERBATIM, never lowercased first. Normalising here would erase the property
    # under test: emitting a covered name in the wrong case is what put the name on the
    # wire twice and broke the merge, and a gate that folds the case cannot see it.
    emitted = {name: [value] for name, value in signed.headers.items()}
    assert emitted == vector["emitted_headers"]


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
