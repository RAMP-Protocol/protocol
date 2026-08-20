"""The content leg: fetching the bytes a signed delivery URL names, presenting the agent
key that URL is bound to. Python port of sdk/go/resolvers/contentfetch.go.

It lives in this tier because it DIALS, and a retrieval endpoint is chosen by a party on
the network rather than by configuration — the exact threat shape the guard exists to
contain. The transport-neutral tiers above stay free of any dialing surface.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ramp_sdk.errordetail import retrieval_auth_failure_detail
from ramp_sdk.pop import AGENT_KEY_HEADER, sign_agent_binding
from ramp_sdk.wire import RequestIDHeader

from .errors import CallError, CallErrorKind

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

    from ramp_sdk.window import Window

#: Bounds one content fetch, in seconds. An agent is blocked on the call that triggered
#: it, so a fetch that has not answered by now is more useful as a reported failure than
#: as a hang.
DEFAULT_CONTENT_TIMEOUT_SEC = 30.0

#: Caps one fetched body at 8 MiB. A memory bound on the fetching process, not a
#: judgement about how large licensed content may be: the body is buffered whole and held
#: for the life of the call, and a batch fetches one per item.
DEFAULT_MAX_CONTENT_BYTES = 8 << 20

#: How long a delivery-fetch proof stays valid, in seconds. Short on purpose, and
#: deliberately NOT the signed URL's own expiry, which can be hours: the proof covers only
#: the method and the URL, so for as long as the window is open anyone who observes the
#: request can repeat it.
DEFAULT_PROOF_WINDOW_SEC = 30

# How much of a refusal body is read before the edge's reason is parsed out of it. The
# payload is a small JSON object; anything past this is not a refusal that can be
# interpreted.
_MAX_ERROR_BODY_BYTES = 4 << 10

# What a body with no usable Content-Type is labelled. Guessing from the bytes would be
# worse: the caller is told what the publisher said, and "unknown" is a true answer where
# a sniffed guess might not be.
_DEFAULT_CONTENT_MIME_TYPE = "application/octet-stream"

# The shape a refusal token may have.
#
# The body this is read from is written by the host just fetched from, and the value is
# promoted over this SDK's own classification. Unchecked, a publisher could answer any
# 4 KiB of text and have it render as though the SDK had said it. Anything that is not
# token-shaped falls back to the failure class, which the SDK does own.
_EDGE_REASON_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# The ErrorDetail domain for a refusal by a delivery edge. It is the failing surface, not
# the fetched resource: the field is a stable grouping key for tooling, so it names the
# tier that refused.
_EDGE_ERROR_DOMAIN = "ramp.v1.Edge"

# type "/" subtype over RFC 9110's token characters, lowercased.
_MEDIA_TYPE_SHAPE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+$")

_OP = "fetch content"


@dataclass(frozen=True)
class Content:
    """One fetched resource."""

    #: The signed delivery URL that was fetched, echoed back so a caller correlating a
    #: batch does not have to keep its own map.
    url: str
    #: The media type the edge served, parameters stripped.
    mime_type: str
    #: The fetched bytes.
    body: bytes


def proof_headers(
    signed_url: str,
    *,
    signer_seed: bytes,
    window: Window,
    request_id: Callable[[], str] | None = None,
) -> dict[str, str]:
    """Mint the proof of possession for one bound GET.

    Composed over the shipped RFC 9421 signer rather than restating the covered-component
    set, so the bytes stay identical to what the edge's verifier reconstructs.
    """
    created, expires = window()
    try:
        agent_key, signature_input, signature = sign_agent_binding(
            url=signed_url, signer_seed=signer_seed, created=created, expires=expires
        )
    except Exception as exc:  # custody can fail any way it likes
        # The given URL is deliberately NOT echoed: this error reaches a log, and a
        # delivery URL carries a live credential in its query.
        raise CallError(CallErrorKind.NOT_SIGNABLE, _OP, cause=_redact(exc)) from exc
    headers = {
        AGENT_KEY_HEADER: agent_key,
        "signature-input": signature_input,
        "signature": signature,
    }
    # Stamped BESIDE the proof rather than covered by it: the correlation id identifies
    # the request in two sets of logs, it authorises nothing. It matters on THIS leg in
    # particular — the RPC legs correlate through the transport, which a plain GET never
    # traverses, so without it the delivery fetch is the one leg carrying no id and an
    # edge that mints its own logs a refusal under a value nothing else knows.
    if request_id is not None:
        headers[RequestIDHeader] = request_id()
    return headers


def read_content(
    signed_url: str, response: httpx.Response, max_bytes: int
) -> Content:
    """Turn one delivery answer into content, or raise the typed failure.

    Reads one byte past the cap so an oversized body is DETECTED rather than silently
    truncated. Truncated content that looks whole is worse than a refusal: the caller has
    paid for it and has no way to tell it is incomplete.
    """
    if not response.is_success:
        raise _edge_refusal(response)
    body = response.content
    if len(body) > max_bytes:
        raise CallError(
            CallErrorKind.TOO_LARGE, _OP, cause=f"body exceeds the {max_bytes} byte cap"
        )
    return Content(
        url=signed_url,
        mime_type=mime_type_of(response.headers.get("content-type")),
        body=body,
    )


def _edge_refusal(response: httpx.Response) -> CallError:
    """The failure for an edge that answered and said no, promoting the edge's own refusal
    token to a typed protocol reason when the vocabularies line up.

    The detail is SYNTHESIZED here rather than received: a delivery edge answers a small
    JSON object, not a protobuf. Its domain names the delivery edge as the failing SURFACE
    — a stable grouping, matching the value the cross-language error-detail corpus already
    uses for this reason block. Deliberately not the fetched URL: domain mirrors
    google.rpc.ErrorInfo.domain so generic tooling can group errors, and a per-URL value
    has unbounded cardinality and groups nothing.
    """
    token = _edge_reason(response.content[:_MAX_ERROR_BODY_BYTES])
    return CallError(
        CallErrorKind.REFUSED,
        _OP,
        status=response.status_code,
        reason=token or None,
        detail=_typed_reason(token) if token else None,
    )


def _typed_reason(token: str) -> Any:
    """Promote an edge token to the typed reason when it names one of the protocol's own
    values, and answer ``None`` otherwise. The edge's vocabulary and the protocol's are
    deliberately separate, and this is the single place they meet."""
    upper = token.upper()
    named = upper if upper.startswith("RETRIEVAL_AUTH_FAILURE_REASON_") else (
        f"RETRIEVAL_AUTH_FAILURE_REASON_{upper}"
    )
    try:
        return retrieval_auth_failure_detail(
            _EDGE_ERROR_DOMAIN, f"delivery refused: {token}", named  # type: ignore[arg-type]
        )
    except Exception:  # an unknown token is simply not one of ours
        return None


def _edge_reason(body: bytes) -> str:
    """Pull the edge's own refusal token out of a rejection body. The edge answers
    ``{"error": "...", "reason": "..."}`` on a binding failure; anything else yields ""."""
    try:
        payload = json.loads(body or b"{}")
    except ValueError:
        return ""
    if not isinstance(payload, dict):
        return ""
    reason = payload.get("reason")
    return reason if isinstance(reason, str) and _EDGE_REASON_TOKEN.match(reason) else ""


def mime_type_of(header: str | None) -> str:
    """Reduce a Content-Type to its media type, dropping parameters such as charset.

    The charset belongs to whoever decodes the bytes; the content carries the media type
    alone.

    The parameters are DISCARDED WITHOUT BEING PARSED, and the media type's shape is checked
    rather than delegated to a parser, because the three SDKs must answer one thing for one
    header. Go's stdlib parser reports a malformed PARAMETER as an error beside a perfectly
    good media type — honouring that answers "unknown" for `text/plain; ;`, discarding the one
    thing the field carries because of the part this is defined to ignore — and it accepts a
    bare token with no slash, which is not a media type at all. The rule is stated instead:
    the text before the first `;`, trimmed and lowercased, must be token "/" token over RFC
    9110's token characters.
    """
    if not header:
        return _DEFAULT_CONTENT_MIME_TYPE
    media_type = header.split(";", 1)[0].strip().lower()
    return media_type if _MEDIA_TYPE_SHAPE.match(media_type) else _DEFAULT_CONTENT_MIME_TYPE


def _redact(exc: BaseException) -> str:
    """Strip a credential out of a failure that names the URL it was dialing. For a
    delivery fetch that query IS the credential, so a message carrying it leaks even when
    this module's own wording is already redacted."""
    return re.sub(r"\bhttps?://\S+", "<url redacted>", str(exc), flags=re.IGNORECASE)


def transport_failure(exc: BaseException) -> CallError:
    """An edge that did not answer, with its URL kept out of the message."""
    return CallError(CallErrorKind.UNREACHABLE, _OP, cause=_redact(exc))
