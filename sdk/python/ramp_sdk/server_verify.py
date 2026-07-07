"""Framework-agnostic RFC 9421 single-signature SERVER-verify face (ADR-020 §4).

The Python sibling of sdk/go/connectserver's single-sig verify path. Where
``httpsig.verify_request`` is the pure primitive (already-resolved key, explicit
covered fields), ``verify_request_server`` is the SERVER entry a Broker/Exchange
built in Python wires behind its framework (ASGI): it (a) parses the inbound
Signature-Input/Signature off the request headers, (b) enforces the RAMP
required-5 covered set, (c) resolves the keyid through an INJECTED KeyResolver
(the SDK owns no keys), (d) reuses ``verify_request`` for the window / digest /
Ed25519 check, (e) runs the two-phase replay check over an INJECTED store (the
SDK owns no replay state), (f) reads time through an INJECTED clock (the SDK owns
no wall clock), and (g) returns a VERDICT carrying the reject reason mirroring the
Go connectserver taxonomy (classify.go ``RejectReason.String()`` /
``ErrReplayed``) — never a thrown exception at the SDK boundary.

SINGLE-SIG scope only (2026-07-07 decision on agentic-content-access-qqkro):
multisig forwarding-chain verify (hop budget, broken_chain) is owned by o3szv.
The reject reason tokens this face emits are exactly the two the single-sig
surface produces: ``"signature"`` (bad sig / expiry / future-created /
wrong-or-unresolvable key / tampered covered field / missing component — the
connectserver default branch) and ``"replay"``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .httpsig import VerifiedRequest, verify_request

if TYPE_CHECKING:
    from .keyresolver import KeyResolver

# The RAMP required covered set, mirroring Go helpers.requiredCoveredComponents.
# The presented Signature-Input MUST declare all five, or the request is rejected
# as a signature failure (Go enforceRequiredComponents).
_REQUIRED_COVERED: frozenset[str] = frozenset(
    {
        "@method",
        "@target-uri",
        "content-digest",
        "authorization",
        "signature-agent",
    }
)

# The connectserver reject-reason tokens (classify.go RejectReason.String()) for
# the single-sig surface. Any signature-authenticity/freshness/key failure is the
# default "signature"; a replayed nonce is "replay".
_REASON_SIGNATURE = "signature"
_REASON_REPLAY = "replay"

# Default replay TTL, mirroring connectserver WithReplayTTL(5m). The injected
# store may ignore it; it is passed through unchanged.
_DEFAULT_REPLAY_TTL_SEC = 300


@runtime_checkable
class ReplayStore(Protocol):
    """Injected replay-nonce store (mirrors Go core.ReplayStore).

    The SDK ships NO default store — replay state lives entirely in the injected
    implementation. ``seen_nonce`` is the read-only first phase; ``seen_or_add``
    is the commit phase (returns True if the nonce was already present).
    """

    def seen_nonce(self, nonce: str) -> bool:
        """Return True if ``nonce`` was already recorded (read-only)."""
        ...

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:
        """Record ``nonce`` (TTL ``ttl_seconds``); return True if already present."""
        ...


@dataclass(frozen=True)
class _ParsedInput:
    """The parsed single-sig Signature-Input: label, covered names, keyid."""

    label: str
    covered: frozenset[str]
    keyid: str | None


def _parse_signature_input(signature_input: str) -> _ParsedInput | None:
    """Parse ``label=("c1" "c2" ...);keyid="..";alg="..";created=..;expires=..``.

    A minimal RFC 8941-shaped parser for the SINGLE-SIG surface (one label, the
    RAMP covered set, string-valued keyid). It extracts the label, the covered
    component names (quoted tokens inside the inner list), and the keyid — the
    fields the required-set enforcement and key resolution need. The window /
    digest / crypto reuse ``verify_request``, which re-parses the verbatim params
    tail, so this parser never needs the integer params.
    """
    eq = signature_input.find("=")
    if eq < 0:
        return None
    label = signature_input[:eq].strip()
    tail = signature_input[eq + 1 :].strip()
    open_paren = tail.find("(")
    close_paren = tail.find(")")
    if open_paren != 0 or close_paren < 0:
        return None
    inner = tail[open_paren + 1 : close_paren]
    covered = frozenset(tok for tok in _quoted_tokens(inner))
    params = tail[close_paren + 1 :]
    keyid = _quoted_param(params, "keyid")
    return _ParsedInput(label=label, covered=covered, keyid=keyid)


def _quoted_tokens(inner: str) -> list[str]:
    """Return the quoted string tokens in an SFV inner list, lowercased.

    Only ``"name"`` tokens are collected (the RAMP covered set carries no
    param-bearing components on the single-sig surface); a malformed token yields
    an empty list member that the required-set check then rejects.
    """
    out: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        if inner[i] == '"':
            j = inner.find('"', i + 1)
            if j < 0:
                break
            out.append(inner[i + 1 : j].lower())
            i = j + 1
        else:
            i += 1
    return out


def _quoted_param(params: str, name: str) -> str | None:
    """Return the value of ``;name="value"`` from an SFV params tail, or None."""
    needle = f';{name}="'
    start = params.find(needle)
    if start < 0:
        return None
    value_start = start + len(needle)
    end = params.find('"', value_start)
    if end < 0:
        return None
    return params[value_start:end]


def _reject(reason: str) -> VerifiedRequest:
    return VerifiedRequest(valid=False, reason=reason)


def _replay_nonce(keyid: str, signature: str) -> str:
    """Derive the replay-store key: keyid + NUL + std-base64(signature bytes).

    Mirrors connectserver.replayNonce (keyid + "\\x00" + std-base64(sig)). The
    signature bytes are decoded from the ``sig1=:<b64>:`` wire form and re-encoded
    canonically so the nonce is independent of incidental wire whitespace.
    """
    raw = _signature_bytes(signature)
    encoded = base64.b64encode(raw).decode() if raw is not None else signature
    return keyid + "\x00" + encoded


def _signature_bytes(signature: str) -> bytes | None:
    first = signature.find(":")
    last = signature.rfind(":")
    if first < 0 or last <= first:
        return None
    try:
        return base64.b64decode(signature[first + 1 : last])
    except (ValueError, TypeError):
        return None


def verify_request_server(
    *,
    method: str,
    url: str,
    body: bytes,
    headers: dict[str, str],
    resolver: KeyResolver,
    replay_store: ReplayStore | None = None,
    now: int,
    replay_ttl_seconds: int = _DEFAULT_REPLAY_TTL_SEC,
) -> VerifiedRequest:
    """Verify an inbound single-signature RAMP request; return a reason-tagged verdict.

    ``headers`` is a lowercased-key mapping carrying at least ``signature-input``,
    ``signature``, ``content-digest``, ``authorization``, and ``signature-agent``.
    Keys resolve ONLY through ``resolver`` (SDK owns no keys); replay state lives
    ONLY in ``replay_store`` when supplied (omit it to disable replay detection);
    time is ``now`` (unix seconds — SDK owns no wall clock). The verdict's reason
    mirrors the Go connectserver taxonomy: ``"signature"`` (the default —
    authenticity/freshness/key/covered-set failures) or ``"replay"``.
    """
    signature_input = headers.get("signature-input", "")
    signature = headers.get("signature", "")
    content_digest = headers.get("content-digest", "")
    authorization = headers.get("authorization", "")
    signature_agent = headers.get("signature-agent", "")

    parsed = _parse_signature_input(signature_input)
    if parsed is None or parsed.keyid is None:
        return _reject(_REASON_SIGNATURE)

    # Required covered-set enforcement (Go enforceRequiredComponents): every one of
    # the five RAMP components must be declared, or a signer omitting a bound field
    # would slip through. Any gap is the default "signature" reason.
    if not parsed.covered >= _REQUIRED_COVERED:
        return _reject(_REASON_SIGNATURE)

    pub = resolver.resolve(parsed.keyid)
    if pub is None:
        # An unresolvable / unknown key is an authentication failure — the Go
        # default branch (ErrUnknownKey carries no distinct sentinel).
        return _reject(_REASON_SIGNATURE)

    verdict = verify_request(
        method=method,
        url=url,
        body=body,
        signature_input=signature_input,
        signature=signature,
        content_digest=content_digest,
        authorization=authorization,
        pubkey=pub,
        now=now,
        signature_agent=signature_agent,
    )
    if not verdict.valid:
        # Collapse the fine-grained primitive reasons (expired / future_created /
        # digest_mismatch / signature_verify / …) into the connectserver default
        # token; the fine-grained string is preserved for logs only by the caller.
        return _reject(_REASON_SIGNATURE)

    if replay_store is not None:
        nonce = _replay_nonce(parsed.keyid, signature)
        # Two-phase (read-only Seen, then SeenOrAdd) mirrors connectserver.verify so
        # a part-way rejection never burns the nonce — for single-sig the phases are
        # over the one signature.
        if replay_store.seen_nonce(nonce):
            return _reject(_REASON_REPLAY)
        if replay_store.seen_or_add(nonce, replay_ttl_seconds):
            return _reject(_REASON_REPLAY)

    return VerifiedRequest(valid=True)
