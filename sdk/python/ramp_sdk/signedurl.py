"""Ed25519 signed delivery-URL verification (ADR-013) — pure, IO-free L1 helper.

Mirrors the sdk/ts sibling (sdk/ts/src/verify.ts ``verifyEd25519SignedUrl``) and
the sdk/go oracle (sdk/go/helpers/signedurl.go ``VerifyURLEd25519``). Key
resolution is INJECTED (``resolve_key``) so no IO/state lives in the SDK — the
ADR-020 §4 KeyResolver split; ``now`` is INJECTED so the verify reads no wall
clock.

Byte contract (Constantine, 2026-07-07): the signature covers ``"GET\\n<url>"``
as OPAQUE URL BYTES. Neither signer nor verifier re-normalizes scheme/host/path —
a mixed-case host, an explicit default port, and a raw space or percent in the
path are all preserved verbatim. The ONLY transform is deterministic query
handling (add exp/kid/agent_id, remove sig, sort the query), done identically
across sdk/{go,ts,python}. This is why the canonical string is built by splitting
the raw URL at its first ``?`` and preserving the prefix byte-for-byte, rather
than round-tripping through ``urlsplit``/``urlunsplit`` (which can drop/alter
host+path bytes). The query is re-encoded to match Go's ``url.Values.Encode()``
byte-for-byte via :func:`_query_escape`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .b64 import b64url_decode, b64url_nopad

_SIG_PARAM = "sig"
_EXP_PARAM = "exp"
_KID_PARAM = "kid"
_AGENT_ID_PARAM = "agent_id"

#: Go url.QueryEscape keeps these unreserved bytes unescaped; space -> "+";
#: everything else -> %XX (uppercase). Reproduced here so the three SDKs emit
#: byte-identical query strings.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _query_escape(s: str) -> str:
    """Escape a query key/value exactly as Go's ``url.QueryEscape``."""
    out: list[str] = []
    for byte in s.encode():
        ch = chr(byte)
        if ch in _UNRESERVED:
            out.append(ch)
        elif ch == " ":
            out.append("+")
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def _query_unescape(s: str) -> str:
    """Reverse ``_query_escape``: "+" -> space, "%XX" -> byte, then UTF-8 decode."""
    raw = bytearray()
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "+":
            raw.append(0x20)
            i += 1
        elif ch == "%" and i + 3 <= n:
            raw.append(int(s[i + 1 : i + 3], 16))
            i += 3
        else:
            raw.extend(ch.encode())
            i += 1
    return raw.decode()


def _encode_query(pairs: list[tuple[str, str]]) -> str:
    """Serialize pairs byte-identically to Go's ``url.Values.Encode()``: sort by
    key (stable per-key value order), escape each side, join ``k=v&k=v``."""
    ordered = sorted(pairs, key=lambda kv: kv[0])
    return "&".join(f"{_query_escape(k)}={_query_escape(v)}" for k, v in ordered)


def _parse_query_pairs(raw_query: str) -> list[tuple[str, str]]:
    """Split a raw query into ordered ``(key, value)`` pairs, decoding each side
    exactly as Go's ``url.ParseQuery`` (a "+" decodes to a space)."""
    if raw_query == "":
        return []
    pairs: list[tuple[str, str]] = []
    for part in raw_query.split("&"):
        if part == "":
            continue
        key, sep, value = part.partition("=")
        pairs.append((_query_unescape(key), _query_unescape(value) if sep else ""))
    return pairs


def _canonical_url(
    raw_url: str,
    mutate: Callable[[list[tuple[str, str]]], list[tuple[str, str]]] | None = None,
) -> str:
    """Build the URL whose bytes the signature covers: the raw prefix
    (scheme+host+path, VERBATIM) plus the deterministically re-encoded query. It
    drops ``sig``, applies ``mutate``, sorts, and re-encodes. Shared by the sign
    and verify faces so both agree on the byte contract by construction.
    """
    prefix, sep, raw_query = raw_url.partition("?")
    if not sep:
        prefix, raw_query = raw_url, ""
    pairs = [(k, v) for k, v in _parse_query_pairs(raw_query) if k != _SIG_PARAM]
    if mutate is not None:
        pairs = mutate(pairs)
    encoded = _encode_query(pairs)
    return prefix if encoded == "" else f"{prefix}?{encoded}"


def _set_param(
    pairs: list[tuple[str, str]], key: str, value: str
) -> list[tuple[str, str]]:
    """Set (replacing) a single query key, preserving order: overwrite in place or
    append."""
    for i, (k, _v) in enumerate(pairs):
        if k == key:
            pairs[i] = (key, value)
            return pairs
    pairs.append((key, value))
    return pairs

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
    """Return ``"GET\\n<url>"`` over the URL as OPAQUE BYTES: strip only ``sig``
    and deterministically re-encode the query; preserve scheme/host/path verbatim
    (no ``urlsplit``/``urlunsplit`` normalization). Reuses the SAME builder the
    sign face uses so signer and verifier agree by construction.
    """
    return "GET\n" + _canonical_url(url)


def sign_ed25519_signed_url(
    raw_url: str,
    *,
    seed: bytes,
    kid: str,
    agent_id: str,
    exp: int,
) -> str:
    """Sign ``raw_url`` with the Ed25519 ``seed``, embedding exp (and kid when set,
    agent_id when set) plus the base64url-no-pad signature over ``"GET\\n<url>"``.

    The URL is signed as OPAQUE BYTES — scheme/host/path are preserved verbatim;
    only the query is deterministically re-encoded. The emitted string is
    byte-identical to the Go oracle (``helpers.SignURLEd25519``). An empty
    ``agent_id`` yields a bearer (unbound) URL; an empty ``kid`` omits the param.
    """

    def add_params(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
        pairs = _set_param(pairs, _EXP_PARAM, str(exp))
        if kid != "":
            pairs = _set_param(pairs, _KID_PARAM, kid)
        if agent_id != "":
            pairs = _set_param(pairs, _AGENT_ID_PARAM, agent_id)
        return pairs

    unsigned = _canonical_url(raw_url, add_params)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    sig = priv.sign(("GET\n" + unsigned).encode())
    sig_param = b64url_nopad(sig)
    return _canonical_url(unsigned, lambda pairs: _set_param(pairs, _SIG_PARAM, sig_param))


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
    _prefix, _sep, raw_query = raw_url.partition("?")
    params = dict(_parse_query_pairs(raw_query))

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
