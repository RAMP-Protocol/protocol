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

SINGLE-SIG scope only: multisig forwarding-chain verify (hop budget,
broken_chain) is handled by the separate multisig server-verify path below.
The reject reason tokens this face emits are exactly the two the single-sig
surface produces: ``"signature"`` (bad sig / expiry / future-created /
wrong-or-unresolvable key / tampered covered field / missing component — the
connectserver default branch) and ``"replay"``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

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

# RejectReason — the classified verify-gate reject vocabulary, mirroring the Go
# connectserver taxonomy (classify.go RejectReason.String()). The tokens are stable
# audit values a consumer's log / dashboards key on; do not rename them. The
# single-sig face (verify_request_server) emits "signature"/"replay"; the multisig
# face (verify_multisig_request_server) emits "hop_budget"/"broken_chain"/
# "signature". TS splits the same vocabulary by face (RejectReason /
# MultisigRejectReason); Python mirrors Go's single four-token domain.
RejectReason = Literal["signature", "replay", "broken_chain", "hop_budget"]

# The connectserver multisig reject-reason tokens (mirrors Go verify.go): a chain
# longer than the budget is "hop_budget"; a structurally-broken chain is
# "broken_chain"; any per-hop authenticity failure collapses to "signature".
_REASON_HOP_BUDGET: RejectReason = "hop_budget"
_REASON_BROKEN_CHAIN: RejectReason = "broken_chain"

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

# The canonical entitlement-token header (mirrors Go verify.go entitlementHeader
# / entitlementHeaderLower). Format-neutral — the value may be a JWT or an opaque
# token; only its coverage is checked. When the request carries it, the signature
# MUST commit to its lowercase covered-component form, or an unsigned entitlement
# token could be slipped under an otherwise-valid signature.
_ENTITLEMENT_HEADER = "x-entitlement-token"

# The connectserver reject-reason tokens (classify.go RejectReason.String()) for
# the single-sig surface. Any signature-authenticity/freshness/key failure is the
# default "signature"; a replayed nonce is "replay".
_REASON_SIGNATURE: RejectReason = "signature"
_REASON_REPLAY: RejectReason = "replay"

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
    """The parsed single-sig Signature-Input: label, covered names, keyid, window.

    ``created``/``expires`` back the MaxSignatureAge lifetime clamp; the
    freshness/window check itself is re-parsed by ``verify_request`` from the
    verbatim params tail, so these are consumed only for the clamp."""

    label: str
    covered: frozenset[str]
    keyid: str | None
    created: int | None = None
    expires: int | None = None


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
    created = _int_param(params, "created")
    expires = _int_param(params, "expires")
    return _ParsedInput(label=label, covered=covered, keyid=keyid, created=created, expires=expires)


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


def _int_param(params: str, name: str) -> int | None:
    """Return the integer value of ``;name=<int>`` from an SFV params tail, or None.

    Backs the MaxSignatureAge clamp: ``created``/``expires`` are bare SFV integers
    (unquoted), so this reads the digit run after ``;name=`` up to the next ``;``.
    """
    needle = f";{name}="
    start = params.find(needle)
    if start < 0:
        return None
    value_start = start + len(needle)
    end = value_start
    n = len(params)
    while end < n and params[end].isdigit():
        end += 1
    if end == value_start:
        return None
    return int(params[value_start:end])


def _has_entitlement_header(headers: dict[str, str]) -> bool:
    """Return True if the entitlement-token header is present (non-empty).

    Header names are matched case-insensitively (mirrors Go http.Header.Get), so a
    caller passing the canonical ``X-Entitlement-Token`` form is honoured
    alongside the lowercased-key convention this face otherwise reads.
    """
    for name, value in headers.items():
        if name.lower() == _ENTITLEMENT_HEADER and value != "":
            return True
    return False


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
    max_signature_age: int = 0,
) -> VerifiedRequest:
    """Verify an inbound single-signature RAMP request; return a reason-tagged verdict.

    ``headers`` is a lowercased-key mapping carrying at least ``signature-input``,
    ``signature``, ``content-digest``, ``authorization``, and ``signature-agent``.
    Keys resolve ONLY through ``resolver`` (SDK owns no keys); replay state lives
    ONLY in ``replay_store`` when supplied (omit it to disable replay detection);
    time is ``now`` (unix seconds — SDK owns no wall clock). ``max_signature_age``
    (seconds) clamps the declared lifetime (``expires - created``); 0 / omitted
    means unbounded, inclusive at the bound (mirrors Go VerifyOptions.MaxSignatureAge).
    The verdict's reason mirrors the Go connectserver taxonomy: ``"signature"`` (the
    default — authenticity/freshness/key/covered-set/lifetime failures) or ``"replay"``.
    """
    signature_input = headers.get("signature-input", "")
    signature = headers.get("signature", "")
    content_digest = headers.get("content-digest", "")

    # ABSENT is not EMPTY for a covered header, and the difference is the whole reason
    # an empty one is put on the wire at all. The base is rebuilt from the request that
    # ARRIVED, so a name the signature covers and the request does not carry cannot be
    # reconstructed — defaulting it to "" here would invent a value the signer may never
    # have bound and accept a request the oracle refuses (it reads these with Values,
    # not Get, precisely to tell the two apart). See docs/design-history.md, "A covered
    # header the peer never receives is not bound".
    if "authorization" not in headers or "signature-agent" not in headers:
        return _reject(_REASON_SIGNATURE)
    authorization = headers["authorization"]
    signature_agent = headers["signature-agent"]

    parsed = _parse_signature_input(signature_input)
    if parsed is None or parsed.keyid is None:
        return _reject(_REASON_SIGNATURE)

    # Required covered-set enforcement (Go enforceRequiredComponents): every one of
    # the five RAMP components must be declared, or a signer omitting a bound field
    # would slip through. Any gap is the default "signature" reason.
    if not parsed.covered >= _REQUIRED_COVERED:
        return _reject(_REASON_SIGNATURE)

    # Entitlement coverage (Go enforceEntitlementCoverage): if the request carries
    # the entitlement-token header, the signature MUST commit to it (its lowercase
    # covered-component form) — else an unsigned entitlement token could be slipped
    # under a valid signature. Absent header → no constraint. Format-neutral (JWT /
    # opaque). Read the header case-insensitively.
    if _has_entitlement_header(headers) and _ENTITLEMENT_HEADER not in parsed.covered:
        return _reject(_REASON_SIGNATURE)

    # Lifetime clamp (mirrors Go enforceCreatedExpires MaxSignatureAge): reject
    # a declared window longer than allowed — a far-future expires is a wide replay
    # window. 0 = unbounded; inclusive at the bound (== max_signature_age passes).
    if (
        max_signature_age > 0
        and parsed.created is not None
        and parsed.expires is not None
        and parsed.expires - parsed.created > max_signature_age
    ):
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


# --- MULTISIG forwarding-chain server-verify ----------------------------------
#
# The Python sibling of Go helpers.VerifyMultisigRequest[Resolved]. Reject
# precedence is parity-critical: hop_budget -> broken_chain -> signature. NO replay
# — the Go helpers oracle performs none; the per-hop verify core below
# mirrors verify_request's checks MINUS the two-phase ReplayStore path, and the
# chain link resolves to the LIVE predecessor bytes so a stripped / reordered /
# tampered predecessor is rejected.


@dataclass(frozen=True)
class MultisigVerdict:
    """The multisig verify verdict: valid with the verified keyids in chain order,
    or invalid with the classified reason. Never raised — always returned."""

    valid: bool
    reason: RejectReason | None = None
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
    headers: dict[str, str],
    max_age: int = 0,
) -> bool:
    """The per-hop verify core shared by the multisig loop (mirrors Go
    verifySingleSignature MINUS replay): alg + required covered set + entitlement
    coverage + window (with the optional MaxSignatureAge lifetime clamp) +
    content-digest + key resolution + Ed25519 over the reconstructed base (which
    inserts the forwarding-chain line for a chained hop)."""
    if member.keyid is None:
        return False
    if member.alg is None or member.alg.lower() != "ed25519":
        return False
    if not member.covered_names >= _REQUIRED_COVERED:
        return False
    # Entitlement coverage per hop (mirrors Go verifySingleSignature's
    # enforceEntitlementCoverage): if the relayed request carries the entitlement
    # header, THIS member's covered set must include it, else an unsigned
    # entitlement token could be slipped under an otherwise-valid hop signature.
    if _has_entitlement_header(headers) and _ENTITLEMENT_HEADER not in member.covered_names:
        return False
    if member.created is None or member.expires is None:
        return False
    if member.expires < now or member.created > now + _MAX_FUTURE_SKEW_SEC:
        return False
    # Lifetime clamp (mirrors Go enforceCreatedExpires MaxSignatureAge): a
    # signer-chosen far-future expires is a wide replay window. Reject a window
    # longer than allowed. 0 = unbounded; inclusive at the bound (== max_age passes).
    if max_age > 0 and member.expires - member.created > max_age:
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
    max_signature_age: int = 0,
) -> MultisigVerdict:
    """Verify an inbound MULTISIG forwarding-chain RAMP request; return a
    reason-tagged verdict carrying the verified keyids in chain order.

    Enforces the hop budget FIRST (``hop_budget``), then the structural chain
    (``broken_chain``), then every hop's signature (``signature``) — in that
    precedence (mirrors Go VerifyMultisigRequest). ``max_signatures`` 0 / omitted
    means unbounded. ``max_signature_age`` (seconds) clamps each hop's declared
    lifetime (``expires - created``); 0 / omitted means unbounded, inclusive at the
    bound (mirrors Go VerifyOptions.MaxSignatureAge). Keys resolve ONLY through
    ``resolver``; time is ``now``.
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
        if not _verify_member(
            fields,
            member,
            sig_map.get(member.label),
            resolver,
            now,
            chain_link,
            headers,
            max_signature_age,
        ):
            return MultisigVerdict(False, _REASON_SIGNATURE)
        keyids.append(keyid)
    return MultisigVerdict(True, None, tuple(keyids))
