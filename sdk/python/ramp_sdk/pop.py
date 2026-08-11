"""RFC 9421 GET proof-of-possession verification (ADR-013) — pure L1 helper.

Mirrors the sdk/ts sibling (sdk/ts/src/pop.ts ``verifyAgentBinding``). When a
signed URL carries an ``agent_id`` (the agent's RFC 7638 thumbprint), a
code-capable edge requires the fetcher to prove possession of the bound key,
fully offline:

  1. present its raw Ed25519 public key in ``X-RAMP-Agent-Key``, and
  2. sign the GET with RFC 9421 over ``@method`` + ``@target-uri``,

and the edge enforces the 3-way identity:

  agent_id (URL) == keyid (Signature-Input) == thumbprint(presented key)

The Ed25519 verify primitive is INJECTABLE (``verify_ed25519``) so a runtime
without a preferred Ed25519 backend can supply its own — the byte contract is the
signature base, not the primitive. The default primitive uses ``cryptography``.
``now`` is INJECTED (unix seconds) so the verify reads no wall clock. Byte-parity
guard: the pop vectors are produced by the sdk/go signer over the same
@method/@target-uri base (sigbase.go buildSignatureBase).
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .b64 import b64url_decode, b64url_nopad
from .thumbprint import thumbprint

AGENT_KEY_HEADER = "x-ramp-agent-key"

_ED25519_PUBLIC_KEY_BYTES = 32
#: The GET PoP covers exactly two components: @method and @target-uri.
_POP_COVERED_COUNT = 2
#: A proof's created timestamp may not lead the verifier clock by more than this.
_MAX_FUTURE_SKEW_SEC = 300

#: Injected Ed25519 verify primitive: ``(pubkey, signature, message) -> valid?``.
Ed25519Verify = Callable[[bytes, bytes, bytes], bool]


@dataclass(frozen=True)
class PopResult:
    """Verdict of a proof-of-possession verification."""

    ok: bool
    reason: str | None = None


@dataclass(frozen=True)
class _SignatureInput:
    covered: list[str]
    raw_params: str
    keyid: str
    alg: str
    created: int | None
    expires: int | None


def _default_verify_ed25519(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _read_presented_key(headers: Mapping[str, str]) -> bytes | None:
    raw = headers.get(AGENT_KEY_HEADER)
    if not raw:
        return None
    try:
        key = b64url_decode(raw)
    except (ValueError, TypeError):
        return None
    if len(key) != _ED25519_PUBLIC_KEY_BYTES:
        return None
    return key


def _parse_signature_input(raw: str | None) -> _SignatureInput | None:
    """Parse ``label=("@method" "@target-uri");keyid="..";alg="..";created=..;expires=..``."""
    if not raw:
        return None
    eq = raw.find("=")
    if eq < 0:
        return None
    raw_params = raw[eq + 1 :].strip()
    m = re.match(r"^\(([^)]*)\)(.*)$", raw_params)
    if not m:
        return None
    covered = re.findall(r'"([^"]+)"', m.group(1))
    tail = m.group(2)
    keyid = _match_param(tail, r';keyid="([^"]*)"')
    alg = _match_param(tail, r';alg="([^"]*)"')
    if keyid is None or alg is None:
        return None
    return _SignatureInput(
        covered=covered,
        raw_params=raw_params,
        keyid=keyid,
        alg=alg,
        created=_match_int(tail, r";created=(\d+)"),
        expires=_match_int(tail, r";expires=(\d+)"),
    )


def _match_param(s: str, pattern: str) -> str | None:
    m = re.search(pattern, s)
    return m.group(1) if m else None


def _match_int(s: str, pattern: str) -> int | None:
    m = re.search(pattern, s)
    return int(m.group(1)) if m else None


def _parse_signature(raw: str | None) -> bytes | None:
    """Parse the RFC 9421 ``Signature`` header value ``label=:<base64>:``."""
    if not raw:
        return None
    m = re.search(r":([^:]+):", raw)
    if not m:
        return None
    try:
        # The Signature byte string is STANDARD base64 (not b64url-nopad).
        return base64.b64decode(m.group(1))
    except (ValueError, TypeError):
        return None


def _covers_exactly(covered: list[str]) -> bool:
    return len(covered) == _POP_COVERED_COUNT and "@method" in covered and "@target-uri" in covered


def signature_base(method: str, url: str, raw_params: str) -> str:
    """Rebuild the RFC 9421 signature base for the covered GET components.

    MUST stay byte-identical to the sdk/go signer (sigbase.go buildSignatureBase).
    """
    return "\n".join(
        [
            f'"@method": {method.upper()}',
            f'"@target-uri": {url}',
            f'"@signature-params": {raw_params}',
        ]
    )


def sign_agent_binding(
    *,
    url: str,
    signer_seed: bytes,
    created: int,
    expires: int,
) -> tuple[str, str, str]:
    """Produce the agent's GET proof-of-possession — the SIGN face of this module.

    Returns ``(presented_key_b64url, signature_input_value, signature_value)``:
    the ``X-RAMP-Agent-Key`` value, the ``Signature-Input`` header value, and the
    ``Signature`` header value the fetcher attaches to its GET. The covered set is
    exactly ``@method @target-uri`` (ADR-013), keyid is the RFC 7638 thumbprint of
    the signer's public key (the 3-way identity anchor), and the signed bytes are
    the same :func:`signature_base` the verify face reconstructs — byte-identical
    to the sdk/go signer (pinned by pop-vectors.json). ``created``/``expires`` are
    injected unix seconds: the helper reads no clock (L1-pure).
    """
    # The signature base is line-delimited and ``url`` is written into it verbatim,
    # so a control byte would add or split a component line and the bytes signed
    # here would stop describing the request a verifier reconstructs. Refused
    # rather than escaped: no legitimate target URI contains one, and a signature
    # base is the wrong place to be lenient. Mirrors the Go signer, which refuses
    # the same bytes in both the method and the URL; the method arm does not apply
    # here because this face always signs GET.
    #
    # Scanned over the UTF-8 BYTES, not the code points, so the reported offset is
    # the same number Go's strings.IndexFunc reports for the same input. Which
    # inputs are refused is unaffected — a control byte is always a single UTF-8
    # byte — but an unlabelled index under identical wording meant three units.
    raw = url.encode("utf-8")
    bad = next((i for i, b in enumerate(raw) if b < 0x20 or b == 0x7F), None)
    if bad is not None:
        raise ValueError(f"target URI carries a control byte at byte {bad}")

    priv = Ed25519PrivateKey.from_private_bytes(signer_seed)
    pub = priv.public_key().public_bytes_raw()
    keyid = thumbprint(pub)
    sig_params = (
        f'("@method" "@target-uri");keyid="{keyid}";alg="ed25519"'
        f";created={created};expires={expires}"
    )
    raw = priv.sign(signature_base("GET", url, sig_params).encode())
    # The Signature byte string is STANDARD base64 (mirror _parse_signature).
    return (
        b64url_nopad(pub),
        f"sig1={sig_params}",
        f"sig1=:{base64.b64encode(raw).decode()}:",
    )


def _freshness_failure(parsed: _SignatureInput, now: int) -> str | None:
    if parsed.created is None:
        return "pop_missing_created"
    if parsed.created > now + _MAX_FUTURE_SKEW_SEC:
        return "pop_future_created"
    if parsed.expires is None:
        return "pop_missing_exp"
    if now >= parsed.expires:
        return "pop_expired"
    return None


def verify_agent_binding(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    agent_id: str,
    now: int,
    verify_ed25519: Ed25519Verify | None = None,
) -> PopResult:
    """Verify the agent's proof of possession of the key bound to ``agent_id``.

    Returns ``ok=True`` only when the presented key, the RFC 9421 signature, and
    the 3-way identity all check out. ``now`` is unix seconds (injected).
    """
    presented = _read_presented_key(headers)
    if presented is None:
        return PopResult(ok=False, reason="missing_agent_key")

    parsed = _parse_signature_input(headers.get("signature-input"))
    if parsed is None:
        return PopResult(ok=False, reason="malformed_sig_input")
    if parsed.alg.lower() != "ed25519":
        return PopResult(ok=False, reason="unsupported_alg")
    if not _covers_exactly(parsed.covered):
        return PopResult(ok=False, reason="bad_covered_components")

    sig_bytes = _parse_signature(headers.get("signature"))
    if sig_bytes is None:
        return PopResult(ok=False, reason="missing_sig")

    # 3-way identity: keyid and the presented-key thumbprint must both equal the
    # URL-bound agent_id before any signature work is trusted.
    if parsed.keyid != agent_id:
        return PopResult(ok=False, reason="keyid_mismatch")
    if thumbprint(presented) != agent_id:
        return PopResult(ok=False, reason="thumbprint_mismatch")

    stale = _freshness_failure(parsed, now)
    if stale is not None:
        return PopResult(ok=False, reason=stale)

    base = signature_base(method, url, parsed.raw_params).encode()
    verify = verify_ed25519 if verify_ed25519 is not None else _default_verify_ed25519
    if not verify(presented, sig_bytes, base):
        return PopResult(ok=False, reason="pop_sig_invalid")
    return PopResult(ok=True)
