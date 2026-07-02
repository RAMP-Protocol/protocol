"""RFC 9421 Ed25519 request signing + verification — pure, IO-free L1 helper.

Relocated from the app MCP shim (src/mcp/src/ramp_mcp_shim/httpsig.py
``Signer.sign``); the byte oracle is the Go ``SignRequest`` (sdk/go/helpers/sign.go)
+ ``buildSignatureBase`` (sigbase.go) and ``VerifyRequest`` (verify.go). The port
MUST produce, byte-for-byte, the same signature base, Signature-Input, and
Signature the Go oracle emits, pinned to the shared
sdk/go/helpers/testdata/sign-request-vectors.json.

Covered set is EXACTLY ``@method @target-uri content-digest authorization`` (no
conditional biscuit component). L1 purity (ADR-020 §1/§4): ``created``/``expires``
are INJECTED — sign reads no wall clock. The ``Signature`` value is STANDARD
base64 (``sig1=:<b64>:``), NOT b64url-nopad — the two encodings are not unified.

``@target-uri`` is rendered verbatim from the supplied absolute URL, matching Go's
``reconstructTargetURI`` (scheme://host + path + "?"+query) when the URL is already
in absolute-canonical form (as the fixed vectors are).
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# RAMP coverage set (ADR-001 §2.1) for the originating sig1 — MUST match the
# Broker/Exchange verifiers' required base components and the Go oracle's
# requiredCoveredComponents.
_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
)

#: A signature's created timestamp may not lead the verifier clock by more than
#: this (mirrors the Go verifier's defaultMaxFutureSkew).
_MAX_FUTURE_SKEW_SEC = 300


@dataclass(frozen=True)
class SignedRequest:
    """The RFC 9421 headers + the signature base produced for a request."""

    content_digest: str
    signature_input: str
    signature: str
    signature_base: str


@dataclass(frozen=True)
class VerifiedRequest:
    """Verdict of an RFC 9421 request verification."""

    valid: bool
    reason: str | None = None


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest header value: ``sha-256=:<std-base64(SHA-256)>:``."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _signature_params(covered: tuple[str, ...], keyid: str, created: int, expires: int) -> str:
    covered_list = " ".join(f'"{c}"' for c in covered)
    return f'({covered_list});keyid="{keyid}";alg="ed25519";created={created};expires={expires}'


def _signature_base(
    *,
    method: str,
    url: str,
    digest_header: str,
    authorization: str,
    sig_params: str,
) -> str:
    return "\n".join(
        [
            f'"@method": {method.upper()}',
            f'"@target-uri": {url}',
            f'"content-digest": {digest_header}',
            f'"authorization": {authorization}',
            f'"@signature-params": {sig_params}',
        ]
    )


def sign_request(
    *,
    method: str,
    url: str,
    body: bytes,
    authorization: str,
    signer_seed: bytes,
    keyid: str,
    created: int,
    expires: int,
) -> SignedRequest:
    """Sign a request over the RAMP covered set; return the RFC 9421 headers.

    ``created``/``expires`` are injected unix seconds (L1-pure, no wall clock).
    Authorization is always bound — pass an empty string to pin its absence.
    """
    digest_header = content_digest(body)
    sig_params = _signature_params(_COVERED_COMPONENTS, keyid, created, expires)
    base = _signature_base(
        method=method,
        url=url,
        digest_header=digest_header,
        authorization=authorization,
        sig_params=sig_params,
    )
    priv = Ed25519PrivateKey.from_private_bytes(signer_seed)
    sig = priv.sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()
    return SignedRequest(
        content_digest=digest_header,
        signature_input=f"sig1={sig_params}",
        signature=f"sig1=:{sig_b64}:",
        signature_base=base,
    )


def _extract_sig_params(signature_input: str) -> str | None:
    """Return the verbatim params string after ``sig1=`` (``(...);keyid=...``)."""
    eq = signature_input.find("=")
    if eq < 0:
        return None
    return signature_input[eq + 1 :].strip()


def _extract_signature_bytes(signature: str) -> bytes | None:
    m = re.search(r":([^:]+):", signature)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1))
    except (ValueError, TypeError):
        return None


def _param_int(sig_params: str, name: str) -> int | None:
    m = re.search(rf";{name}=(\d+)", sig_params)
    return int(m.group(1)) if m else None


def verify_request(
    *,
    method: str,
    url: str,
    body: bytes,
    signature_input: str,
    signature: str,
    content_digest: str,
    authorization: str,
    pubkey: bytes,
    now: int,
) -> VerifiedRequest:
    """Verify an RFC 9421 request against ``pubkey`` at ``now`` (unix seconds).

    ``content_digest`` is the request's Content-Digest header value. Enforces the
    digest, the created/expires window, and the Ed25519 signature over the
    reconstructed base. Pure: key resolution and ``now`` are injected.
    """
    sig_params = _extract_sig_params(signature_input)
    if sig_params is None:
        return VerifiedRequest(valid=False, reason="malformed_sig_input")

    sig_bytes = _extract_signature_bytes(signature)
    if sig_bytes is None:
        return VerifiedRequest(valid=False, reason="missing_sig")

    created = _param_int(sig_params, "created")
    expires = _param_int(sig_params, "expires")
    if created is None:
        return VerifiedRequest(valid=False, reason="missing_created")
    if expires is None:
        return VerifiedRequest(valid=False, reason="missing_expires")
    if expires < now:
        return VerifiedRequest(valid=False, reason="expired")
    if created > now + _MAX_FUTURE_SKEW_SEC:
        return VerifiedRequest(valid=False, reason="future_created")

    expected_digest = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
    if content_digest.strip() != expected_digest:
        return VerifiedRequest(valid=False, reason="digest_mismatch")

    base = _signature_base(
        method=method,
        url=url,
        digest_header=content_digest,
        authorization=authorization,
        sig_params=sig_params,
    )
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig_bytes, base.encode())
    except (InvalidSignature, ValueError):
        return VerifiedRequest(valid=False, reason="signature_verify")
    return VerifiedRequest(valid=True)
