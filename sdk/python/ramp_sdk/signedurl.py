"""Ed25519 signed delivery-URL verification (ADR-013) — pure, IO-free L1 helper.

Mirrors the sdk/ts sibling (sdk/ts/src/verify.ts ``verifyEd25519SignedUrl``) and
the sdk/go oracle (sdk/go/helpers/signedurl.go ``VerifyURLEd25519``). Key
resolution is INJECTED (``resolve_key``) so no IO/state lives in the SDK — the
ADR-020 §4 KeyResolver split; ``now`` is INJECTED so the verify reads no wall
clock.

Byte contract: the canonical signed message is ``"GET\\n<url-without-sig>"``.
Only the ``sig`` param is stripped — the query is NOT re-sorted, matching the Go
signer's already-sorted output (``url.Values.Encode()``). The signed-URL vectors
are produced by the Go signer, so the "no re-sort on verify" invariant is fed the
exact canonically-sorted string the signer emitted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._b64 import b64url_decode

_SIG_PARAM = "sig"
_EXP_PARAM = "exp"
_KID_PARAM = "kid"
_AGENT_ID_PARAM = "agent_id"

#: Injected verifying-key resolver: ``kid -> raw 32-byte Ed25519 key | None``.
ResolveKey = Callable[[str | None], bytes | None]


@dataclass(frozen=True)
class SignedUrlResult:
    """Verdict of a signed-URL verification."""

    valid: bool
    expired: bool
    kid: str | None = None
    agent_id: str | None = None
    reason: str | None = None


def _canonical_message(url: str) -> str:
    """Return ``"GET\\n<url-without-sig>"``: strip only ``sig``, preserve order."""
    parts = urlsplit(url)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != _SIG_PARAM]
    stripped = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))
    return "GET\n" + stripped


def verify_ed25519_signed_url(
    raw_url: str,
    *,
    now: int,
    resolve_key: ResolveKey,
) -> SignedUrlResult:
    """Verify a signed URL against the resolved key, then check expiry at ``now``.

    ``now`` is unix seconds (injected — no wall clock). The signature is verified
    before trusting expiry (both are covered by the sig).
    """
    parts = urlsplit(raw_url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))

    sig_b64 = params.get(_SIG_PARAM)
    if not sig_b64:
        return SignedUrlResult(valid=False, expired=False, reason="missing_sig")
    exp_raw = params.get(_EXP_PARAM)
    if not exp_raw or not exp_raw.isdigit():
        return SignedUrlResult(valid=False, expired=False, reason="missing_exp")
    exp = int(exp_raw)

    kid = params.get(_KID_PARAM)
    agent_id = params.get(_AGENT_ID_PARAM)

    if now >= exp:
        return SignedUrlResult(
            valid=False, expired=True, kid=kid, agent_id=agent_id, reason="expired"
        )

    try:
        sig = b64url_decode(sig_b64)
    except (ValueError, TypeError):
        return SignedUrlResult(valid=False, expired=False, kid=kid, reason="bad_sig_encoding")

    key_bytes = resolve_key(kid)
    if key_bytes is None:
        return SignedUrlResult(valid=False, expired=False, kid=kid, reason="signature_mismatch")

    message = _canonical_message(raw_url).encode()
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(sig, message)
    except (InvalidSignature, ValueError):
        return SignedUrlResult(valid=False, expired=False, kid=kid, reason="signature_mismatch")

    return SignedUrlResult(valid=True, expired=False, kid=kid, agent_id=agent_id)
