"""sdk/python full-RPC single-signature SERVER-VERIFY parity.

SINGLE-SIG scope only: multisig forwarding-chain verify (hop budget, broken_chain)
is OUT OF SCOPE and handled separately. This suite pins the generalized
``httpsig.verify_request`` server
face: today ``verify_request`` is a pure primitive that takes an already-resolved
public key and explicit covered fields; it adds a framework-agnostic SERVER
entry that (a) parses the inbound Signature-Input/Signature off the request
headers, (b) resolves the keyid through an INJECTED KeyResolver (SDK owns no
keys), (c) enforces the covered-set/digest/window, (d) runs the two-phase replay
check over an INJECTED store (SDK owns no replay state), (e) reads time through an
INJECTED clock (SDK owns no wall clock), and (f) returns a VERDICT carrying the
reject reason mirroring the Go connectserver taxonomy (classify.go RejectReason /
ErrReplayed) — NOT thrown exceptions at the SDK boundary.

The semantic oracle is sdk/go/connectserver (verify.go / classify.go / reject.go)
over sdk/go/helpers/verify.go. Reject reason tokens mirror RejectReason.String():
"signature" (bad sig / expiry / future-created / wrong-or-unresolvable key /
tampered covered field / missing component — the default) and "replay". The
multisig tokens broken_chain / hop_budget are out of scope here.

RED until BOTH (a) httpsig grows ``verify_request_server`` AND (b) the Go emitter
produces sdk/go/helpers/testdata/verify-request-neg-vectors.json. The implement
step adds both; this test is the TDD-red contract. Referencing the
not-yet-existing symbol + the not-yet-emitted vector file keeps the suite RED on
both the missing server face AND the missing shared negative oracle.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from conftest import GO_TESTDATA, load_json

# RED: ``verify_request_server`` does not exist yet on httpsig (TDD red). It is
# the framework-agnostic single-sig server-verify entry.
from ramp_sdk.httpsig import sign_request, verify_request_server  # type: ignore[attr-defined]
from ramp_sdk.keyresolver import StaticKeyResolver

# The positive round-trip consumes the existing sign-request oracle vectors (the
# same the request SIGNER produces); the negatives consume the Go-emitted
# single-sig negative-verify corpus the implement step adds.
_SIGN_VECTORS = load_json(GO_TESTDATA / "sign-request-vectors.json")["vectors"]

# RED (also): this file does not exist yet — load_json raises FileNotFoundError,
# a clean TDD-red signal that the shared negative oracle is missing.
_NEG_VECTORS_PATH = GO_TESTDATA / "verify-request-neg-vectors.json"
_NEG_VECTORS = load_json(_NEG_VECTORS_PATH)["vectors"]


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class _RecordingResolver:
    """A KeyResolver that records every keyid it was asked to resolve.

    The injected-boundary probe: the server face MUST resolve keys ONLY through
    this holder, so the recorded calls prove no key was read out-of-band.
    """

    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = dict(keys)
        self.calls: list[str | None] = []

    def resolve(self, keyid: str | None) -> bytes | None:
        self.calls.append(keyid)
        if keyid is None:
            return None
        return self._keys.get(keyid)


class _MemoryReplayStore:
    """An in-test replay store the SDK orchestrates over (seen / seen_or_add).

    The SDK ships NO default store, so replay state lives entirely here — the
    state boundary the Core Invariant requires.
    """

    def __init__(self) -> None:
        self.seen: set[str] = set()

    def seen_nonce(self, nonce: str) -> bool:
        return nonce in self.seen

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:  # noqa: ARG002
        if nonce in self.seen:
            return True
        self.seen.add(nonce)
        return False


def test_neg_vector_set_covers_every_single_sig_reject_case() -> None:
    # The Go emitter must produce exactly these named single-sig negatives; the
    # multisig cases (broken_chain / hop_budget) are out of scope.
    names = {v["name"] for v in _NEG_VECTORS}
    assert {
        "neg_bad_sig",
        "neg_replay",
        "neg_expired",
        "neg_wrong_key",
        "neg_tampered_authorization",
        "neg_entitlement_uncovered",
        # How a covered header is READ, which is a separate claim from whether its
        # value was tampered with: a name the request does not carry at all, and a
        # second field line beside the signed one under a different spelling.
        "neg_absent_authorization",
        "neg_absent_signature_agent",
        "neg_duplicate_authorization",
        # The entitlement name carried twice with an empty line first — the coverage
        # rule is skipped entirely by a reader that resolves the name to one line.
        "neg_shadowed_entitlement",
    } <= names


@pytest.mark.parametrize("vector", _SIGN_VECTORS, ids=[v["name"] for v in _SIGN_VECTORS])
def test_oracle_signed_request_verifies_through_server_face(vector: dict[str, object]) -> None:
    # POSITIVE round-trip: an oracle-signed request verifies (valid=True) when its
    # key is injected via the resolver and its window via the clock. The keyid is
    # resolved ONLY through the injected resolver.
    pub = _b64url_nopad_decode(str(vector["pubkey_b64url"]))
    keyid = str(vector["keyid"])
    resolver = _RecordingResolver({keyid: pub})
    store = _MemoryReplayStore()
    now = (int(vector["created"]) + int(vector["expires"])) // 2  # type: ignore[call-overload]

    verdict = verify_request_server(
        method=str(vector["method"]),
        url=str(vector["url"]),
        body=bytes.fromhex(str(vector["body_hex"])),
        headers={
            "content-digest": str(vector["content_digest"]),
            "signature-input": str(vector["signature_input"]),
            "signature": str(vector["signature"]),
            "authorization": str(vector["authorization"]),
            "signature-agent": str(vector.get("signature_agent", "")),
        },
        resolver=resolver,
        replay_store=store,
        now=now,
    )

    assert verdict.valid is True
    # Key resolved ONLY through the injected resolver (no out-of-band read).
    assert keyid in resolver.calls


def test_live_signed_request_roundtrips_through_server_face() -> None:
    # A request signed live by the request SIGNER verifies through the server face.
    seed = bytes.fromhex("55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374")
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    created, expires = 1_700_000_000, 1_700_000_600
    body = b'{"uri":"https://cdn.example/live"}'

    signed = sign_request(
        method="POST",
        url="https://broker.example/ramp.v1.BrokerService/Fetch",
        body=body,
        authorization="Bearer live-token",
        signer_seed=seed,
        keyid="mcp.v1",
        created=created,
        expires=expires,
        signature_agent="https://agent.example",
    )

    resolver = _RecordingResolver({"mcp.v1": pub})
    verdict = verify_request_server(
        method="POST",
        url="https://broker.example/ramp.v1.BrokerService/Fetch",
        body=body,
        headers={
            "content-digest": signed.content_digest,
            "signature-input": signed.signature_input,
            "signature": signed.signature,
            "authorization": "Bearer live-token",
            "signature-agent": "https://agent.example",
        },
        resolver=resolver,
        replay_store=_MemoryReplayStore(),
        now=created + 100,
    )

    assert verdict.valid is True
    assert resolver.calls == ["mcp.v1"]


@pytest.mark.parametrize("vector", _NEG_VECTORS, ids=[v["name"] for v in _NEG_VECTORS])
def test_negative_vector_rejected_with_correct_reason(vector: dict[str, object]) -> None:
    # NEGATIVE: each Go-emitted single-sig negative rejects (valid=False) with the
    # reason token the connectserver taxonomy assigns, and the guarded handler
    # never runs (fail-closed — a verdict, not an exception, at the SDK boundary).
    keys: dict[str, bytes] = {}
    resolver_keyid = str(vector.get("resolver_keyid") or vector["keyid"])
    if vector.get("resolver_pubkey_b64url"):
        keys[resolver_keyid] = _b64url_nopad_decode(str(vector["resolver_pubkey_b64url"]))
    resolver = _RecordingResolver(keys)
    store = _MemoryReplayStore()

    headers = {
        "content-digest": str(vector["content_digest"]),
        "signature-input": str(vector["signature_input"]),
        "signature": str(vector["signature"]),
        "authorization": str(vector["authorization"]),
        "signature-agent": str(vector.get("signature_agent", "")),
    }
    # A vector carrying an "entitlement" value exercises entitlement-coverage
    # enforcement: set the X-Entitlement-Token request header to it. The base
    # request's covered set does not cover the header, so a conformant verifier
    # must reject with reason "signature".
    if vector.get("entitlement"):
        headers["X-Entitlement-Token"] = str(vector["entitlement"])
    # A name the request does NOT carry: the key is dropped, so the face sees a
    # covered name with no field line under it rather than an empty one. Absent is
    # not empty, and the two must not verify alike.
    for name in vector.get("omit_headers") or []:
        headers.pop(str(name).lower(), None)
    # Field lines ADDED beside the base ones, spelled in a different case so the
    # mapping holds both. Applied AFTER, so the join order matches the order the
    # oracle added them; the verbatim spelling is the whole point.
    for name, value in (vector.get("extra_headers") or {}).items():  # type: ignore[union-attr]
        headers[str(name)] = str(value)

    def _verify() -> object:
        return verify_request_server(
            method=str(vector["method"]),
            url=str(vector["url"]),
            body=bytes.fromhex(str(vector["body_hex"])),
            headers=headers,
            resolver=resolver,
            replay_store=store,
            now=int(vector["now"]),  # type: ignore[call-overload]
        )

    if vector.get("replay"):
        # First presentation records the nonce; the SECOND must be rejected.
        first = _verify()
        assert first.valid is True  # type: ignore[attr-defined]

    verdict = _verify()
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == str(vector["expected_reason"])  # type: ignore[attr-defined]


def test_replay_uses_the_injected_store_only() -> None:
    # The SDK owns no replay state: the replay decision is made ENTIRELY by the
    # injected store. The neg_replay vector proves this — the first presentation
    # passes and mutates OUR store; the second trips OUR store's `seen`. Assert the
    # store actually recorded the nonce (state lives here, not in the SDK).
    replay = next((v for v in _NEG_VECTORS if v["name"] == "neg_replay"), None)
    assert replay is not None
    assert replay["expected_reason"] == "replay"

    keys = {}
    resolver_keyid = str(replay.get("resolver_keyid") or replay["keyid"])
    if replay.get("resolver_pubkey_b64url"):
        keys[resolver_keyid] = _b64url_nopad_decode(str(replay["resolver_pubkey_b64url"]))
    store = _MemoryReplayStore()

    verify_request_server(
        method=str(replay["method"]),
        url=str(replay["url"]),
        body=bytes.fromhex(str(replay["body_hex"])),
        headers={
            "content-digest": str(replay["content_digest"]),
            "signature-input": str(replay["signature_input"]),
            "signature": str(replay["signature"]),
            "authorization": str(replay["authorization"]),
            "signature-agent": str(replay.get("signature_agent", "")),
        },
        resolver=StaticKeyResolver(keys),
        replay_store=store,
        now=int(replay["now"]),  # type: ignore[call-overload]
    )
    # The nonce landed in OUR store — the SDK held none of it.
    assert len(store.seen) == 1


def _live_signed_call(*, max_signature_age: int, window: int = 600) -> object:
    # Sign a request live over a `window`-second declared lifetime and verify it
    # through the single-sig server face under the given max_signature_age clamp.
    # Returns the verdict. Backs the lifetime-clamp parity tests.
    seed = bytes.fromhex("55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374")
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    created = 1_700_000_000
    expires = created + window
    body = b'{"uri":"https://cdn.example/clamp"}'
    signed = sign_request(
        method="POST",
        url="https://broker.example/ramp.v1.BrokerService/Fetch",
        body=body,
        authorization="Bearer clamp-token",
        signer_seed=seed,
        keyid="mcp.v1",
        created=created,
        expires=expires,
        signature_agent="https://agent.example",
    )
    return verify_request_server(
        method="POST",
        url="https://broker.example/ramp.v1.BrokerService/Fetch",
        body=body,
        headers={
            "content-digest": signed.content_digest,
            "signature-input": signed.signature_input,
            "signature": signed.signature,
            "authorization": "Bearer clamp-token",
            "signature-agent": "https://agent.example",
        },
        resolver=_RecordingResolver({"mcp.v1": pub}),
        replay_store=_MemoryReplayStore(),
        now=created + 100,
        max_signature_age=max_signature_age,
    )


def test_single_sig_within_max_age_bound_verifies() -> None:
    # Lifetime clamp — WITHIN the bound: a 600s window under a 700s clamp verifies.
    verdict = _live_signed_call(max_signature_age=700)
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_single_sig_equal_to_max_age_bound_verifies() -> None:
    # Lifetime clamp — EQUAL to the bound (inclusive): 600s window under a 600s clamp
    # verifies (mirrors Go's `> maxAge` reject — equality passes).
    verdict = _live_signed_call(max_signature_age=600)
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_single_sig_exceeding_max_age_bound_is_rejected() -> None:
    # Lifetime clamp — EXCEEDING the bound: 600s window under a 500s clamp rejects with
    # reason "signature" (mirrors Go ErrSignatureLifetimeTooLong).
    verdict = _live_signed_call(max_signature_age=500)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]


def test_single_sig_unbounded_max_age_default_verifies() -> None:
    # Lifetime clamp — UNBOUNDED default (0 / omitted): the 600s window is admitted.
    verdict = _live_signed_call(max_signature_age=0)
    assert verdict.valid is True  # type: ignore[attr-defined]
