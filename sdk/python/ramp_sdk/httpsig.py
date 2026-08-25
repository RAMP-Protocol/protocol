"""RFC 9421 Ed25519 request signing + verification — pure, IO-free L1 helper.

Relocated from the app MCP shim (src/mcp/src/ramp_mcp_shim/httpsig.py
``Signer.sign``); the byte oracle is the Go ``SignRequest`` (sdk/go/helpers/sign.go)
+ ``buildSignatureBase`` (sigbase.go) and ``VerifyRequest`` (verify.go). The port
MUST produce, byte-for-byte, the same signature base, Signature-Input, and
Signature the Go oracle emits, pinned to the shared
sdk/go/helpers/testdata/sign-request-vectors.json.

Covered set is EXACTLY ``@method @target-uri content-digest authorization
signature-agent`` (no conditional biscuit component). Signature-Agent joined the
required set with the WBA identity split: every signature commits to
the signer's key-directory URL, empty included — this supersedes the earlier
four-component pin. L1 purity (ADR-020 §1/§4): ``created``/``expires`` are
INJECTED — sign reads no wall clock. The ``Signature`` value is STANDARD base64
(``sig1=:<b64>:``), NOT b64url-nopad — the two encodings are not unified.

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

from .multisig_parse import max_sig_label_n, signature_bytes_by_label

# RAMP coverage set (ADR-001 §2.1) for the originating sig1 — MUST match the
# Broker/Exchange verifiers' required base components and the Go oracle's
# requiredCoveredComponents.
_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
    "signature-agent",
)

#: A signature's created timestamp may not lead the verifier clock by more than
#: this (mirrors the Go verifier's defaultMaxFutureSkew).
_MAX_FUTURE_SKEW_SEC = 300


@dataclass(frozen=True)
class SignedRequest:
    """The RFC 9421 headers + the signature base produced for a request.

    EVERY covered header is here, at the value that entered the base — the two whose
    value may be empty included, so a caller attaching what this returns sends what was
    signed. The oracle reaches the same place by mutating the request it was handed
    (``helpers.SignRequest``), which is why it has no such field to omit. See
    docs/design-history.md, "A covered header the peer never receives is not bound".
    """

    content_digest: str
    signature_input: str
    signature: str
    signature_base: str
    #: Echoed from the input so a caller attaching what this returns sends what was
    #: signed. Empty is a value, not an absence.
    authorization: str = ""
    #: The signer's WBA directory, echoed for the same reason. Empty is the
    #: static-bootstrap case and is still carried.
    signature_agent: str = ""


@dataclass(frozen=True)
class VerifiedRequest:
    """Verdict of an RFC 9421 request verification."""

    valid: bool
    reason: str | None = None


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest header value: ``sha-256=:<std-base64(SHA-256)>:``."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _signature_params(
    covered: tuple[str, ...],
    keyid: str,
    created: int,
    expires: int,
    chain_link_token: str | None = None,
) -> str:
    # The optional forwarding-chain token (``"signature";key="sigN"``) is appended
    # as the LAST covered component and rendered VERBATIM — it already carries its
    # own quotes + key= param, so it must NOT be re-wrapped. Default None
    # keeps the single-sig (N=1) inner list byte-identical.
    tokens = [f'"{c}"' for c in covered]
    if chain_link_token is not None:
        tokens.append(chain_link_token)
    covered_list = " ".join(tokens)
    return f'({covered_list});keyid="{keyid}";alg="ed25519";created={created};expires={expires}'


def _signature_base(
    *,
    method: str,
    url: str,
    digest_header: str,
    authorization: str,
    signature_agent: str,
    sig_params: str,
    chain_link: tuple[str, str] | None = None,
) -> str:
    lines = [
        f'"@method": {method.upper()}',
        f'"@target-uri": {url}',
        f'"content-digest": {digest_header}',
        f'"authorization": {authorization}',
        f'"signature-agent": {signature_agent}',
    ]
    # The chain-link line is the LAST covered component BEFORE @signature-params
    # (Go buildSignatureBase renders params.Covered in order, chain link last).
    if chain_link is not None:
        token, value = chain_link
        lines.append(f"{token}: {value}")
    lines.append(f'"@signature-params": {sig_params}')
    return "\n".join(lines)


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
    signature_agent: str = "",
) -> SignedRequest:
    """Sign a request over the RAMP covered set; return the RFC 9421 headers.

    ``created``/``expires`` are injected unix seconds (L1-pure, no wall clock).
    Authorization is always bound — pass an empty string to pin its absence.
    ``signature_agent`` is the signer's WBA key-directory URL, bound the same
    way (empty string for the static bootstrap path), mirroring Go's
    ``bindSignatureAgent``.
    """
    digest_header = content_digest(body)
    sig_params = _signature_params(_COVERED_COMPONENTS, keyid, created, expires)
    base = _signature_base(
        method=method,
        url=url,
        digest_header=digest_header,
        authorization=authorization,
        signature_agent=signature_agent,
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
        authorization=authorization,
        signature_agent=signature_agent,
    )


def append_signature(
    *,
    method: str,
    url: str,
    body: bytes,
    authorization: str,
    signature_agent: str,
    prev_signature_input: str,
    prev_signature: str,
    signer_seed: bytes,
    keyid: str,
    created: int,
    expires: int,
) -> SignedRequest:
    """Chain sig(N+1) onto ``prev_signature_input``/``prev_signature`` WITHOUT
    disturbing existing members of the forwarding chain, the Python port of Go
    ``helpers.AppendSignature``.

    Finds the next label sig(N+1) and predecessor sigN, binds the RAMP base plus a
    ``"signature";key="sigN"`` link whose value is ``:<std-base64(decoded
    predecessor sig bytes)>:`` (re-encoded canonically, NOT a wire splice),
    Ed25519-signs, and returns the APPENDED Signature-Input / Signature. Appending
    to an unsigned request (empty prev) produces a sig1 byte-for-byte identical to
    ``sign_request`` — single-sig is the N=1 case.
    """
    digest_header = content_digest(body)
    has_prev = prev_signature_input != ""
    prev_n = max_sig_label_n(prev_signature_input) if has_prev else 0
    label = f"sig{prev_n + 1}"

    chain_link_token: str | None = None
    chain_link: tuple[str, str] | None = None
    if prev_n > 0:
        prev_label = f"sig{prev_n}"
        prev_bytes = signature_bytes_by_label(prev_signature).get(prev_label)
        if prev_bytes is None:
            raise ValueError(f"append_signature: predecessor {prev_label} not in Signature")
        chain_link_token = f'"signature";key="{prev_label}"'
        chain_link = (chain_link_token, ":" + base64.b64encode(prev_bytes).decode() + ":")

    sig_params = _signature_params(_COVERED_COMPONENTS, keyid, created, expires, chain_link_token)
    base = _signature_base(
        method=method,
        url=url,
        digest_header=digest_header,
        authorization=authorization,
        signature_agent=signature_agent,
        sig_params=sig_params,
        chain_link=chain_link,
    )
    sig = Ed25519PrivateKey.from_private_bytes(signer_seed).sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()
    member_input = f"{label}={sig_params}"
    member_sig = f"{label}=:{sig_b64}:"
    return SignedRequest(
        content_digest=digest_header,
        signature_input=f"{prev_signature_input}, {member_input}" if has_prev else member_input,
        signature=f"{prev_signature}, {member_sig}" if prev_signature != "" else member_sig,
        signature_base=base,
        authorization=authorization,
        signature_agent=signature_agent,
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
    signature_agent: str = "",
) -> VerifiedRequest:
    """Verify an RFC 9421 request against ``pubkey`` at ``now`` (unix seconds).

    ``content_digest`` is the request's Content-Digest header value. Enforces the
    digest, the created/expires window, and the Ed25519 signature over the
    reconstructed base (which commits to ``signature_agent``, empty included).
    Pure: key resolution and ``now`` are injected.
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
        signature_agent=signature_agent,
        sig_params=sig_params,
    )
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig_bytes, base.encode())
    except (InvalidSignature, ValueError):
        return VerifiedRequest(valid=False, reason="signature_verify")
    return VerifiedRequest(valid=True)


# The framework-agnostic single-sig SERVER-verify face lives in server_verify.py
# (it composes this module's verify_request primitive with the injected resolver /
# replay store / clock). Re-export it here so a Broker/Exchange imports the whole
# request-verify surface — primitive + server entry — from ramp_sdk.httpsig.
from .server_verify import (  # noqa: E402
    MultisigVerdict,
    RejectReason,
    ReplayStore,
    verify_multisig_request_server,
    verify_request_server,
)

__all__ = [
    "MultisigVerdict",
    "RejectReason",
    "ReplayStore",
    "SignedRequest",
    "VerifiedRequest",
    "append_signature",
    "content_digest",
    "sign_request",
    "verify_multisig_request_server",
    "verify_request",
    "verify_request_server",
]
