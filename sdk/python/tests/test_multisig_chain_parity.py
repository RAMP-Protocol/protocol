"""sdk/python multisig forwarding-chain append+verify parity — TDD red for o3szv.

Go carries the ONLY multisig surface today (helpers.AppendSignature,
VerifyMultisigRequest[Resolved], hop budget); under the 3-SDKs decision a Python
broker must append and verify chains too. This suite pins the NEW ported faces
against the shared Go oracle.

Core Invariant (o3szv): the RFC 9421 signature base — including the parameterized
``"signature";key="sigN"`` forwarding-chain component rendered as
``:stdbase64(decoded-predecessor-signature-bytes):`` — must reconstruct
BYTE-FOR-BYTE in Go and Python, so a chain signed in Go verifies in Python AND the
hop-budget / broken-chain / tampered-predecessor rejections match the Go taxonomy
token-for-token. The shared Go emitter is the sole oracle.

Faces under test (do NOT exist yet — RED):
  - ``ramp_sdk.httpsig.append_signature`` — chains sig(N+1) onto a prior
    (signature_input, signature) WITHOUT disturbing existing members; appending to
    an unsigned request (empty prev) is byte-identical to ``sign_request`` (N=1).
  - ``ramp_sdk.server_verify.verify_multisig_request_server`` — parses ALL labels,
    enforces the hop budget FIRST (hop_budget), the structural chain next
    (broken_chain), then verifies each hop (signature); returns a verdict carrying
    the verified keyids in chain order, never raises.

Reject precedence the verdict must expose (mirrors Go verify.go): hop_budget →
broken_chain → signature.

RED until BOTH faces exist: the imports below reference not-yet-existing symbols,
so pytest fails at collection with ImportError — a clean TDD-red signal.
"""

from __future__ import annotations

import base64

import pytest

from conftest import GO_TESTDATA, load_json

# RED: neither symbol exists yet (TDD red step).
from ramp_sdk.httpsig import append_signature  # type: ignore[attr-defined]
from ramp_sdk.keyresolver import StaticKeyResolver
from ramp_sdk.server_verify import verify_multisig_request_server  # type: ignore[attr-defined]

_VECTORS = load_json(GO_TESTDATA / "multisig-chain-vectors.json")["vectors"]


def _by_name(name: str) -> dict[str, object]:
    for v in _VECTORS:
        if v["name"] == name:
            return v
    raise AssertionError(f"missing vector {name}")


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _resolver(hops: list[dict[str, object]]) -> StaticKeyResolver:
    keys = {str(h["keyid"]): _b64url_nopad_decode(str(h["pubkey_b64url"])) for h in hops}
    return StaticKeyResolver(keys)


def test_vector_set_covers_the_positive_and_all_four_negative_chain_cases() -> None:
    names = {v["name"] for v in _VECTORS}
    assert {
        "positive_two_hop",
        "hop_budget_three_over_two",
        "broken_chain_reordered",
        "broken_chain_stripped_middle",
        "broken_chain_missing_link",
        "tampered_predecessor",
    } <= names


def test_positive_two_hop_verifies_and_returns_keyids_in_order() -> None:
    # POSITIVE: the Go-signed 2-hop chain verifies through the Python face and
    # returns the verified keyids in chain order (sig1 agent, sig2 broker).
    v = _by_name("positive_two_hop")
    now = (int(v["created"]) + int(v["expires"])) // 2  # type: ignore[call-overload]
    verdict = verify_multisig_request_server(
        method=str(v["method"]),
        url=str(v["url"]),
        body=bytes.fromhex(str(v["body_hex"])),
        headers={
            "content-digest": str(v["content_digest"]),
            "signature-input": str(v["signature_input"]),
            "signature": str(v["signature"]),
            "authorization": str(v["authorization"]),
            "signature-agent": str(v["signature_agent"]),
        },
        resolver=_resolver(v["hops"]),  # type: ignore[arg-type]
        now=now,
    )
    assert verdict.valid is True  # type: ignore[attr-defined]
    assert list(verdict.keyids) == list(v["expected_keyids"])  # type: ignore[attr-defined]


def test_append_signature_reproduces_the_go_two_hop_chain_byte_identically() -> None:
    # BYTE-IDENTITY: re-signing the chain live (sign_request sig1 + append_signature
    # sig2) under the Go hop seeds reproduces the Go-emitted Signature-Input and
    # Signature byte-for-byte — the cross-language chain-link contract.
    from ramp_sdk.httpsig import sign_request

    v = _by_name("positive_two_hop")
    hops = v["hops"]  # type: ignore[index]
    h1, h2 = hops[0], hops[1]  # type: ignore[index]
    body = bytes.fromhex(str(v["body_hex"]))

    sig1 = sign_request(
        method=str(v["method"]),
        url=str(v["url"]),
        body=body,
        authorization=str(v["authorization"]),
        signer_seed=bytes.fromhex(str(h1["seed_hex"])),
        keyid=str(h1["keyid"]),
        created=int(v["created"]),  # type: ignore[call-overload]
        expires=int(v["expires"]),  # type: ignore[call-overload]
        signature_agent=str(v["signature_agent"]),
    )

    chained = append_signature(
        method=str(v["method"]),
        url=str(v["url"]),
        body=body,
        authorization=str(v["authorization"]),
        signature_agent=str(v["signature_agent"]),
        prev_signature_input=sig1.signature_input,
        prev_signature=sig1.signature,
        signer_seed=bytes.fromhex(str(h2["seed_hex"])),
        keyid=str(h2["keyid"]),
        created=int(v["created"]),  # type: ignore[call-overload]
        expires=int(v["expires"]),  # type: ignore[call-overload]
    )

    assert chained.signature_input == str(v["signature_input"])
    assert chained.signature == str(v["signature"])


def test_append_to_unsigned_request_equals_sign_request_n1() -> None:
    # N=1 INVARIANT: appending to an unsigned request (empty prev) is byte-identical
    # to sign_request — the load-bearing single-sig-is-N=1 property.
    from ramp_sdk.httpsig import sign_request

    v = _by_name("positive_two_hop")
    h1 = v["hops"][0]  # type: ignore[index]
    body = bytes.fromhex(str(v["body_hex"]))
    common = dict(
        method=str(v["method"]),
        url=str(v["url"]),
        body=body,
        authorization=str(v["authorization"]),
        signature_agent=str(v["signature_agent"]),
        signer_seed=bytes.fromhex(str(h1["seed_hex"])),
        keyid=str(h1["keyid"]),
        created=int(v["created"]),  # type: ignore[call-overload]
        expires=int(v["expires"]),  # type: ignore[call-overload]
    )
    signed = sign_request(**common)  # type: ignore[arg-type]
    appended = append_signature(prev_signature_input="", prev_signature="", **common)  # type: ignore[arg-type]
    assert appended.signature_input == signed.signature_input
    assert appended.signature == signed.signature


@pytest.mark.parametrize(
    "name",
    [
        "hop_budget_three_over_two",
        "broken_chain_reordered",
        "broken_chain_stripped_middle",
        "broken_chain_missing_link",
        "tampered_predecessor",
    ],
)
def test_negative_chain_case_rejects_with_go_reason(name: str) -> None:
    # NEGATIVE: each Go-emitted chain reject case rejects (valid=False) with the
    # exact taxonomy token, honoring the hop_budget → broken_chain → signature
    # precedence encoded in the vectors.
    v = _by_name(name)
    now = (int(v["created"]) + int(v["expires"])) // 2  # type: ignore[call-overload]
    verdict = verify_multisig_request_server(
        method=str(v["method"]),
        url=str(v["url"]),
        body=bytes.fromhex(str(v["body_hex"])),
        headers={
            "content-digest": str(v["content_digest"]),
            "signature-input": str(v["signature_input"]),
            "signature": str(v["signature"]),
            "authorization": str(v["authorization"]),
            "signature-agent": str(v["signature_agent"]),
        },
        resolver=_resolver(v["hops"]),  # type: ignore[arg-type]
        now=now,
        max_signatures=int(v["max_signatures"]),  # type: ignore[call-overload]
    )
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == str(v["expected_reason"])  # type: ignore[attr-defined]
