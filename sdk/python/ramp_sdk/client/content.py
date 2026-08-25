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
from urllib.parse import urlsplit

import httpx

from ramp_sdk._hostref import _BAD_ESCAPE
from ramp_sdk._jsondepth import _MAX_BODY_DEPTH, _raw_nesting_depth
from ramp_sdk.errordetail import retrieval_auth_failure_detail
from ramp_sdk.pop import AGENT_KEY_HEADER
from ramp_sdk.wire import RequestIDHeader

from .errors import CallError, CallErrorKind

if TYPE_CHECKING:
    from collections.abc import Callable

    from ramp_sdk.signing_transport import SigningTransport
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
# \Z, not $: Python's $ also matches before a trailing newline, so "denied\n" would be
# accepted as a token here and refused by Go and TypeScript, whose anchors mean end-of-
# input. The token is echoed into a caller's logs, so the one that admits a newline is the
# one that admits log injection.
_EDGE_REASON_TOKEN = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")

# The ErrorDetail domain for a refusal by a delivery edge. It is the failing surface, not
# the fetched resource: the field is a stable grouping key for tooling, so it names the
# tier that refused.
_EDGE_ERROR_DOMAIN = "ramp.v1.Edge"

# type "/" subtype over RFC 9110's token characters, lowercased.
_MEDIA_TYPE_SHAPE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+$")

_OP = "fetch content"

# The range a TCP port has. A delivery URL naming one outside it names nothing reachable,
# whatever a URL parser makes of the value.
_MIN_PORT = 1
_MAX_PORT = 65535


def _bad_port() -> CallError:
    """The refusal for a delivery URL naming a port outside the range a port has."""
    return CallError(
        CallErrorKind.MALFORMED,
        _OP,
        cause=(
            f"url names a port outside {_MIN_PORT}-{_MAX_PORT} "
            "(value withheld: it carries a live credential)"
        ),
    )


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
    signer: SigningTransport,
    window: Window,
    request_id: Callable[[], str] | None = None,
) -> dict[str, str]:
    """Mint the proof of possession for one bound GET.

    Composed over the shipped RFC 9421 signer rather than restating the covered-component
    set, so the bytes stay identical to what the edge's verifier reconstructs.

    It takes the request SIGNER, not key bytes, because the delivery URL is bound to the
    thumbprint of the agent's request-signing key: a proof minted under any other key
    presents an identity the URL was not issued to. Custody stays in one place.
    """
    vet_signed_url(signed_url)
    try:
        agent_key, signature_input, signature = signer.sign_agent_binding(
            url=signed_url, window=window
        )
    except Exception as exc:  # custody can fail any way it likes
        # The given URL is deliberately NOT echoed: this error reaches a log, and a
        # delivery URL carries a live credential in its query.
        raise CallError(CallErrorKind.NOT_SIGNABLE, _OP, cause=redact_url(exc)) from exc
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


def vet_signed_url(signed_url: str) -> None:
    """Refuse a delivery URL that cannot be used, before a proof is minted for it.

    THE VALUE'S OWN FAULTS ARE REFUSED HERE; the dial's refusals are the dial's. That split
    is the rule all three languages state, and it is stated rather than delegated to
    whichever URL parser the language ships — the three parsers disagree about what
    "unparseable" even means, and a class that changes with the parser is not a contract.
    Measured before this: one value was a permanent verdict in one language and a retryable
    dial failure in the other two, and the disagreement ran in both directions.

    A value fault is: the URL does not parse, it names no scheme or no host, it names a
    port outside the range a port has, it carries a malformed percent-escape where a parse
    would unescape one, or it does not re-serialize to itself. Each will refuse identically
    forever, so a caller must fix the value. A scheme this SDK will not carry a proof over,
    an address the guard refuses and a peer that never answers are all the DIAL's, and
    reported as unreachable.

    The escape check is read PER COMPONENT, the way the host rule already reads it: a
    malformed escape is refused in a path and in a fragment, and admitted in a query, which
    a parse does not unescape — and a delivery URL's query is exactly where a credential
    lives. The predicate is the host rule's own, imported rather than restated.

    A URL that does not RE-SERIALIZE to itself is the subtler one. The proof covers
    ``@target-uri`` as the verbatim string while the request line carries whatever the URL
    re-serializes to, and the signed-URL contract treats scheme/host/path as opaque — so an
    Exchange can legitimately mint a URL those two disagree on, a raw space in the path
    being the reachable case. The signature then cannot verify and the edge reports an
    undifferentiated 403, so refusing here names the cause instead.

    Neither message echoes the URL: its query IS a live credential.
    """
    try:
        # httpx's own parse, deliberately: what matters is whether the value the TRANSPORT
        # will put on the request line still matches the bytes the proof covered, and only
        # this parser answers that. urllib round-trips a raw space verbatim while httpx
        # percent-encodes it, so checking with urllib would miss the reachable case.
        reserialized = str(httpx.URL(signed_url))
    except (ValueError, TypeError, httpx.InvalidURL) as exc:
        raise CallError(
            CallErrorKind.MALFORMED, _OP, cause=f"url is unparseable: {type(exc).__name__}"
        ) from exc
    parsed = urlsplit(signed_url)
    if not parsed.scheme or not parsed.netloc:
        raise CallError(
            CallErrorKind.MALFORMED,
            _OP,
            cause="url names no scheme or no host (value withheld: it carries a live credential)",
        )
    # A port outside the range a port has. httpx checks only that it is digits, so
    # ":99999999999" parses and would then be refused a layer later as a dial that did not
    # happen — the same misfiling, on the same reasoning: no value with this port will ever
    # reach anything. ``urlsplit(...).port`` raises for the range and returns None for an
    # absent one. The HOST rule is deliberately left alone, because its own corpus pins what
    # a bare host may say; this is the delivery leg vetting a value it is about to dial.
    try:
        port = parsed.port
    except ValueError as exc:
        raise _bad_port() from exc
    if port is not None and not _MIN_PORT <= port <= _MAX_PORT:
        # urlsplit admits 0, which is not a port anything listens on. Checked rather than
        # left to the parse, because the rule is the rule and not whatever this parser
        # happens to refuse.
        raise _bad_port()
    if _BAD_ESCAPE.search(parsed.path) or _BAD_ESCAPE.search(parsed.fragment):
        raise CallError(
            CallErrorKind.MALFORMED,
            _OP,
            cause=(
                "url carries a malformed percent-escape "
                "(value withheld: it carries a live credential)"
            ),
        )
    if reserialized != signed_url:
        raise CallError(
            CallErrorKind.MALFORMED,
            _OP,
            cause=(
                "url is not round-trip stable: it re-serializes to a different value "
                "(value withheld: it carries a live credential)"
            ),
        )


def read_content(
    signed_url: str, response: httpx.Response, body: bytes
) -> Content:
    """Turn one delivery answer and the bytes already read from it into content, or raise
    the typed failure.

    The BYTES are handed in rather than read here, because the cap has to bound the read
    itself: the caller streams the body and stops one byte past the cap, so an oversized
    answer is detected without ever being held. Truncated content that looks whole is
    worse than a refusal — the caller has paid for it and has no way to tell it is
    incomplete — so this face never truncates either.
    """
    if not response.is_success:
        raise edge_refusal(response, body)
    return Content(
        url=signed_url,
        mime_type=mime_type_of(response.headers.get("content-type")),
        body=body,
    )


def too_large(max_bytes: int, status: int | None = None) -> CallError:
    """The refusal for a delivery body past its cap."""
    return CallError(
        CallErrorKind.TOO_LARGE,
        _OP,
        status=status,
        cause=f"body exceeds the {max_bytes} byte cap",
    )


#: What a refusal body is read up to. An edge that says no answers a small JSON object;
#: anything past this is not a reason and is not worth holding.
MAX_ERROR_BODY_BYTES = _MAX_ERROR_BODY_BYTES


def edge_refusal(response: httpx.Response, body: bytes) -> CallError:
    """The failure for an edge that answered and said no, promoting the edge's own refusal
    token to a typed protocol reason when the vocabularies line up.

    The detail is SYNTHESIZED here rather than received: a delivery edge answers a small
    JSON object, not a protobuf. Its domain names the delivery edge as the failing SURFACE
    — a stable grouping, matching the value the cross-language error-detail corpus already
    uses for this reason block. Deliberately not the fetched URL: domain mirrors
    google.rpc.ErrorInfo.domain so generic tooling can group errors, and a per-URL value
    has unbounded cardinality and groups nothing.
    """
    token = _edge_reason(body[:_MAX_ERROR_BODY_BYTES])
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
    ``{"error": "...", "reason": "..."}`` on a binding failure; anything else yields "".

    Depth BEFORE the parse, for the reason the RPC reader states: ``json.loads`` descends
    recursively and aborts on a deep document by raising ``RecursionError``, which is not a
    ``ValueError`` — so the handler below never saw it — and not a failure this package says
    it raises. The 4 KiB cap above does not bound it: 4 KiB of ``[`` nests four thousand
    deep, and how much of that an interpreter survives is a property of the interpreter
    rather than a verdict. Measured: the same body raised out of ``Client.fetch`` untyped on
    one supported release and decoded fine on the next.

    A body past the bound yields "" rather than a new failure: the fetch has already been
    refused by the edge, and the token is the one part of that refusal the SDK does not own.
    Falling back to the failure class is what this reader already answers for any body it
    cannot interpret.
    """
    if _raw_nesting_depth(body) > _MAX_BODY_DEPTH:
        return ""
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


def redact_url(exc: BaseException) -> str:
    """Strip a credential out of a failure that names the URL it was dialing. For a
    delivery fetch that query IS the credential, so a message carrying it leaks even when
    this module's own wording is already redacted."""
    return re.sub(r"\bhttps?://\S+", "<url redacted>", str(exc), flags=re.IGNORECASE)


def transport_failure(exc: BaseException) -> CallError:
    """An edge that did not answer, with its URL kept out of the message."""
    return CallError(CallErrorKind.UNREACHABLE, _OP, cause=redact_url(exc))
