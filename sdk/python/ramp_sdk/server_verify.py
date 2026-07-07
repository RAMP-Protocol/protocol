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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .httpsig import (
    _MAX_FUTURE_SKEW_SEC,
    VerifiedRequest,
    _signature_base,
    content_digest,
    verify_request,
)
from .multisig_parse import (
    MultisigMember,
    parse_multisig_signature_input,
    signature_bytes_by_label,
)

if TYPE_CHECKING:
    from .keyresolver import KeyResolver

# The connectserver multisig reject-reason tokens (mirrors Go verify.go): a chain
# longer than the budget is "hop_budget"; a structurally-broken chain is
# "broken_chain"; any per-hop authenticity failure collapses to "signature".
_REASON_HOP_BUDGET = "hop_budget"
_REASON_BROKEN_CHAIN = "broken_chain"

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


# --- MULTISIG forwarding-chain server-verify (o3szv) --------------------------
#
# The Python sibling of Go helpers.VerifyMultisigRequest[Resolved]. Reject
# precedence is parity-critical: hop_budget -> broken_chain -> signature. NO replay
# (o3szv R1) — the Go helpers oracle performs none; the per-hop verify core below
# mirrors verify_request's checks MINUS the two-phase ReplayStore path, and the
# chain link resolves to the LIVE predecessor bytes so a stripped / reordered /
# tampered predecessor is rejected.


@dataclass(frozen=True)
class MultisigVerdict:
    """The multisig verify verdict: valid with the verified keyids in chain order,
    or invalid with the classified reason. Never raised — always returned."""

    valid: bool
    reason: str | None = None
    keyids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _RequestFields:
    """The request-level covered fields shared across every hop of a request."""

    method: str
    url: str
    digest_header: str
    authorization: str
    signature_agent: str
    body: bytes


def _enforce_chain(members: list[MultisigMember]) -> bool:
    """The STRUCTURAL forwarding-chain gate (Go enforceSignatureChain): labels are
    exactly sig1..sigN contiguous in header order, sig1 carries no "signature"
    component, and every sigK (K>1) covers exactly one "signature";key="sig(K-1)"."""
    for i, m in enumerate(members):
        if m.label != f"sig{i + 1}":
            return False
        links = [c for c in m.covered if c.name == "signature"]
        if i == 0:
            if links:
                return False
            continue
        if len(links) != 1 or links[0].chain_key != f"sig{i}":
            return False
    return True


def _verify_member(
    fields: _RequestFields,
    member: MultisigMember,
    sig_bytes: bytes | None,
    resolver: KeyResolver,
    now: int,
    chain_link: tuple[str, str] | None,
) -> bool:
    """The per-hop verify core shared by the multisig loop (mirrors Go
    verifySingleSignature MINUS replay): alg + required covered set + window +
    content-digest + key resolution + Ed25519 over the reconstructed base (which
    inserts the forwarding-chain line for a chained hop)."""
    if member.keyid is None:
        return False
    if member.alg is None or member.alg.lower() != "ed25519":
        return False
    if not member.covered_names >= _REQUIRED_COVERED:
        return False
    if member.created is None or member.expires is None:
        return False
    if member.expires < now or member.created > now + _MAX_FUTURE_SKEW_SEC:
        return False
    if fields.digest_header.strip() != content_digest(fields.body):
        return False
    if sig_bytes is None:
        return False
    pub = resolver.resolve(member.keyid)
    if pub is None:
        return False
    base = _signature_base(
        method=fields.method,
        url=fields.url,
        digest_header=fields.digest_header,
        authorization=fields.authorization,
        signature_agent=fields.signature_agent,
        sig_params=member.raw_inner,
        chain_link=chain_link,
    )
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig_bytes, base.encode())
    except (InvalidSignature, ValueError):
        return False
    return True


def _chain_link_for(i: int, sig_map: dict[str, bytes]) -> tuple[str, str] | None:
    """The forwarding-chain base line for hop i (>0): the token
    ``"signature";key="sig(i)"`` and its value ``:<std-base64(live predecessor
    bytes)>:``, or None when the predecessor bytes are absent (a signature failure)."""
    prev_label = f"sig{i}"
    prev_bytes = sig_map.get(prev_label)
    if prev_bytes is None:
        return None
    return f'"signature";key="{prev_label}"', ":" + base64.b64encode(prev_bytes).decode() + ":"


def verify_multisig_request_server(
    *,
    method: str,
    url: str,
    body: bytes,
    headers: dict[str, str],
    resolver: KeyResolver,
    now: int,
    max_signatures: int = 0,
) -> MultisigVerdict:
    """Verify an inbound MULTISIG forwarding-chain RAMP request; return a
    reason-tagged verdict carrying the verified keyids in chain order.

    Enforces the hop budget FIRST (``hop_budget``), then the structural chain
    (``broken_chain``), then every hop's signature (``signature``) — in that
    precedence (mirrors Go VerifyMultisigRequest). ``max_signatures`` 0 / omitted
    means unbounded. Keys resolve ONLY through ``resolver``; time is ``now``.
    """
    signature_input = headers.get("signature-input", "")
    signature = headers.get("signature", "")
    members = parse_multisig_signature_input([signature_input])
    if not members:
        return MultisigVerdict(False, _REASON_SIGNATURE)
    if max_signatures > 0 and len(members) > max_signatures:
        return MultisigVerdict(False, _REASON_HOP_BUDGET)
    if not _enforce_chain(members):
        return MultisigVerdict(False, _REASON_BROKEN_CHAIN)

    sig_map = signature_bytes_by_label(signature)
    fields = _RequestFields(
        method=method,
        url=url,
        digest_header=headers.get("content-digest", ""),
        authorization=headers.get("authorization", ""),
        signature_agent=headers.get("signature-agent", ""),
        body=body,
    )
    keyids: list[str] = []
    for i, member in enumerate(members):
        chain_link = _chain_link_for(i, sig_map) if i > 0 else None
        if i > 0 and chain_link is None:
            return MultisigVerdict(False, _REASON_SIGNATURE)
        keyid = member.keyid
        if keyid is None:
            return MultisigVerdict(False, _REASON_SIGNATURE)
        if not _verify_member(fields, member, sig_map.get(member.label), resolver, now, chain_link):
            return MultisigVerdict(False, _REASON_SIGNATURE)
        keyids.append(keyid)
    return MultisigVerdict(True, None, tuple(keyids))
