"""sdk/python multisig forwarding-chain append+verify parity.

Go carries the ONLY multisig surface today (helpers.AppendSignature,
VerifyMultisigRequest[Resolved], hop budget); under the 3-SDKs decision a Python
broker must append and verify chains too. This suite pins the NEW ported faces
against the shared Go oracle.

Core Invariant: the RFC 9421 signature base — including the parameterized
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


def test_vector_set_covers_the_positive_and_every_negative_chain_case() -> None:
    names = {v["name"] for v in _VECTORS}
    assert {
        "positive_two_hop",
        "hop_budget_three_over_two",
        "broken_chain_reordered",
        "broken_chain_stripped_middle",
        "broken_chain_missing_link",
        "tampered_predecessor",
        # The same chains missing a covered header — which pin WHERE that is
        # noticed relative to the budget and chain gates, not only that it is.
        "absent_authorization_two_hop",
        "absent_authorization_over_budget",
        "absent_signature_agent_reordered",
        # How a covered header is READ on a chain: a second field line beside the
        # signed one, a bag spelled the conventional way, and a chain whose covered
        # value IS the join of two lines.
        "duplicate_authorization_two_hop",
        "canonical_case_two_hop",
        "duplicate_bound_two_hop",
    } <= names


def _headers_for(v: dict[str, object]) -> dict[str, str]:
    """The header bag a vector describes: the base five, minus what the request does
    not carry, plus any extra field line spelled in another case.

    ``omit_headers`` drops the key entirely, so the face sees a covered name with no
    field line under it rather than an empty one. ``extra_headers`` is applied AFTER
    the base ones so the join order matches the order the oracle added them.
    """
    headers = {
        "content-digest": str(v["content_digest"]),
        "signature-input": str(v["signature_input"]),
        "signature": str(v["signature"]),
        "authorization": str(v["authorization"]),
        "signature-agent": str(v["signature_agent"]),
    }
    for name in v.get("omit_headers") or []:  # type: ignore[union-attr]
        headers.pop(str(name).lower(), None)
    for name, value in (v.get("extra_headers") or {}).items():  # type: ignore[union-attr]
        headers[str(name)] = str(value)
    return headers


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
    common = {
        "method": str(v["method"]),
        "url": str(v["url"]),
        "body": body,
        "authorization": str(v["authorization"]),
        "signature_agent": str(v["signature_agent"]),
        "signer_seed": bytes.fromhex(str(h1["seed_hex"])),
        "keyid": str(h1["keyid"]),
        "created": int(v["created"]),  # type: ignore[call-overload]
        "expires": int(v["expires"]),  # type: ignore[call-overload]
    }
    signed = sign_request(**common)  # type: ignore[arg-type]
    appended = append_signature(prev_signature_input="", prev_signature="", **common)  # type: ignore[arg-type]
    assert appended.signature_input == signed.signature_input
    assert appended.signature == signed.signature


#: The reject cases, DERIVED from the corpus rather than hand-listed. A hand-written
#: name list is how a vector lands and is never replayed — the corpus grew the
#: duplicate-header plumbing and sat unexercised because nothing enumerated it. Every
#: row the emitter adds is now driven the day it is committed.
_NEGATIVE = [str(v["name"]) for v in _VECTORS if not v["expected_verified"]]
_POSITIVE = [str(v["name"]) for v in _VECTORS if v["expected_verified"]]


@pytest.mark.parametrize("name", _NEGATIVE, ids=_NEGATIVE)
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
        headers=_headers_for(v),
        resolver=_resolver(v["hops"]),  # type: ignore[arg-type]
        now=now,
        max_signatures=int(v["max_signatures"]),  # type: ignore[call-overload]
    )
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == str(v["expected_reason"])  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", _POSITIVE, ids=_POSITIVE)
def test_positive_chain_case_verifies_with_go_keyids(name: str) -> None:
    # POSITIVE: every Go-emitted chain the oracle ACCEPTS verifies here too, returning
    # the same keyids in chain order. The rejects above cannot stand in for this: a
    # face that refuses everything passes all of them. This is what catches a reader
    # that resolves a covered header to one field line where the oracle joins, and a
    # reader that matches header names case-sensitively where the wire does not.
    v = _by_name(name)
    now = (int(v["created"]) + int(v["expires"])) // 2  # type: ignore[call-overload]
    verdict = verify_multisig_request_server(
        method=str(v["method"]),
        url=str(v["url"]),
        body=bytes.fromhex(str(v["body_hex"])),
        headers=_headers_for(v),
        resolver=_resolver(v["hops"]),  # type: ignore[arg-type]
        now=now,
        max_signatures=int(v["max_signatures"]),  # type: ignore[call-overload]
    )
    assert verdict.valid is True, f"{name}: {verdict.reason}"  # type: ignore[attr-defined]
    assert list(verdict.keyids) == list(v["expected_keyids"])  # type: ignore[attr-defined]


def _positive_two_hop_call(
    *, extra_headers: dict[str, str] | None = None, max_signature_age: int = 0
) -> object:
    # Build the verify_multisig_request_server call for the positive_two_hop chain,
    # letting a test inject an extra header (e.g. an uncovered entitlement token) or
    # a max_signature_age lifetime clamp. Returns the verdict.
    v = _by_name("positive_two_hop")
    now = (int(v["created"]) + int(v["expires"])) // 2  # type: ignore[call-overload]
    headers = {
        "content-digest": str(v["content_digest"]),
        "signature-input": str(v["signature_input"]),
        "signature": str(v["signature"]),
        "authorization": str(v["authorization"]),
        "signature-agent": str(v["signature_agent"]),
    }
    if extra_headers:
        headers.update(extra_headers)
    return verify_multisig_request_server(
        method=str(v["method"]),
        url=str(v["url"]),
        body=bytes.fromhex(str(v["body_hex"])),
        headers=headers,
        resolver=_resolver(v["hops"]),  # type: ignore[arg-type]
        now=now,
        max_signature_age=max_signature_age,
    )


def test_multisig_uncovered_entitlement_header_is_rejected_per_hop() -> None:
    # A relayed 2-hop request carrying an uncovered X-Entitlement-Token
    # header must be REJECTED with reason "signature" — the per-hop entitlement
    # coverage check (mirrors the single-sig neg_entitlement_uncovered case). The
    # positive chain's covered sets do NOT include x-entitlement-token, so slipping
    # an unsigned entitlement token under the valid hop signatures must fail closed.
    verdict = _positive_two_hop_call(
        extra_headers={"X-Entitlement-Token": "jwt:demo-unsigned-entitlement-token"}
    )
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]


def test_multisig_covered_entitlement_absent_header_still_verifies() -> None:
    # CONTROL: without the entitlement header, the positive chain verifies — the
    # per-hop coverage check is a no-op when the header is absent.
    verdict = _positive_two_hop_call()
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_multisig_signature_within_max_age_bound_verifies() -> None:
    # Lifetime clamp — WITHIN the bound: the positive chain's declared window is 600s;
    # a 700s clamp admits it.
    verdict = _positive_two_hop_call(max_signature_age=700)
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_multisig_signature_equal_to_max_age_bound_verifies() -> None:
    # Lifetime clamp — EQUAL to the bound (inclusive): a 600s clamp admits the 600s
    # window (mirrors Go's `> maxAge` rejection — equality passes).
    verdict = _positive_two_hop_call(max_signature_age=600)
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_multisig_signature_exceeding_max_age_bound_is_rejected() -> None:
    # Lifetime clamp — EXCEEDING the bound: a 500s clamp rejects the 600s window with
    # reason "signature" (per-hop, mirrors Go ErrSignatureLifetimeTooLong).
    verdict = _positive_two_hop_call(max_signature_age=500)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]


def test_multisig_unbounded_max_age_default_verifies() -> None:
    # Lifetime clamp — UNBOUNDED default (0 / omitted): the 600s window is admitted.
    verdict = _positive_two_hop_call(max_signature_age=0)
    assert verdict.valid is True  # type: ignore[attr-defined]
