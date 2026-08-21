"""The Connect-unary JSON call, everything about it that is not IO.

Every RAMP RPC is unary, so a Connect-unary JSON client is the whole protocol rather than
a subset of it: ``POST /ramp.v1.<Service>/<Method>`` with a JSON body. Full Connect
framing exists for streaming, which RAMP has none of and would never use, and it would
drag in a protobuf binary codec this SDK deliberately does not have — the Pydantic
decision makes this client JSON-only by design, not by omission.

This module holds the parts BOTH faces share: the URL, the header set, the signing, the
request check, and reading an answer. The async client and the sync facade differ only in
which httpx client sends the bytes, so keeping the rest here is what stops them drifting.

Message shapes are not decided here. Bodies are produced and parsed by the generated
Pydantic models, the same path the canonical proto-JSON round-trip gate already proves
loss-free against Go protojson.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Literal

from pydantic import ValidationError
from wire.base import JSON_NAME_ALIAS_ERROR

from ramp_sdk._jsondepth import _raw_nesting_depth
from ramp_sdk.errordetail import error_detail_from
from ramp_sdk.wire import (
    ConnectProtocolVersion,
    ConnectProtocolVersionHeader,
    ContentTypeJSON,
    RequestIDHeader,
)

from .errors import (
    NOT_CANONICAL_WIRE_NAMING,
    CallError,
    CallErrorKind,
    connect_code_from_status,
    kind_of_connect_code,
    malformed,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import BaseModel

    from ramp_sdk.signing_transport import SigningTransport

#: Caps the response body a single RAMP call will read.
#:
#: A RAMP response for a realistic batch is small; the bound is what stops a peer —
#: including one an offer named — spending the caller's memory on its behalf. Mirrors the
#: Go client's DefaultMaxRPCReadBytes.
DEFAULT_MAX_RPC_READ_BYTES = 1 << 20  # 1 MiB

#: Bounds one call, in seconds. A RAMP RPC is interactive — something is waiting on the
#: other end — so a request that has not answered by now is more useful as an error than
#: as a hang. Mirrors the Go client's DefaultCallTimeout.
DEFAULT_CALL_TIMEOUT_SEC = 30.0

# The 2xx band. A status outside it is the Connect error envelope, whatever it says.
_HTTP_OK = 200
_HTTP_MULTIPLE_CHOICES = 300


def rpc_url(base_url: str, service: str, method: str) -> str:
    """Join an origin to the Connect unary path.

    The trailing slash is trimmed so a base URL written either way addresses the same
    method — a doubled slash is a different path to some servers and a 404 from them.
    """
    return f"{base_url.rstrip('/')}/{service}/{method}"


def prepare(
    op: str,
    url: str,
    message: Any,
    *,
    signer: SigningTransport | None,
    request_id: Callable[[], str] | None,
) -> tuple[bytes, dict[str, str]]:
    """Render one request to the bytes that are both signed and sent.

    Serialized ONCE: RFC 9530 Content-Digest covers the exact octets, so re-rendering
    between signing and sending would produce a digest for a body the peer never received.
    """
    try:
        body = json.dumps(message, separators=(",", ":")).encode()
    except (TypeError, ValueError) as exc:
        raise malformed(op, exc) from exc
    headers = {
        "content-type": ContentTypeJSON,
        ConnectProtocolVersionHeader: ConnectProtocolVersion,
    }
    # Stamped BEFORE the signature so the covered headers are written last and nothing
    # here can be mistaken for part of the proof. The correlation id is not covered and is
    # not meant to be: it identifies the request in two sets of logs, it authorises
    # nothing.
    if request_id is not None:
        headers[RequestIDHeader] = request_id()
    if signer is not None:
        try:
            signed = signer.sign_outbound(
                method="POST", url=url, body=body, authorization=""
            )
        except Exception as exc:  # custody can fail any way it likes
            # NOT_SIGNABLE, matching what the content leg answers for the same missing
            # holder: a caller branching on the kind sees one condition under one class,
            # whichever verb met it first.
            raise CallError(CallErrorKind.NOT_SIGNABLE, op, cause=exc) from exc
        headers.update(signed.headers)
    return body, headers


#: Whether a request is checked against its generated model before it is signed and sent.
#: ``"strict"`` is the default; a caller that means to probe a server with a deliberately
#: invalid message turns it off.
#:
#: DELIBERATELY STRICTER THAN GO, which defaults to ValidationOff. These two SDKs are the
#: ones handed to external partners, so catching a missing recipient or idempotency key
#: before anything is signed is worth more here than matching the oracle's default. It
#: costs nothing in safety: the Exchange enforces the same rules whatever this says, and
#: the answer coming back is validated either way.
#:
#: And it is a SMALLER check than the Go client's, not an equal one — see
#: :func:`validate_request`, which says so about the same rule.
Validation = Literal["strict", "off"]


def validate_request(
    op: str, message: Any, model: type[BaseModel], validation: Validation
) -> None:
    """Refuse a request the protocol would reject anyway, before it costs a signature and
    a round trip.

    The check is FIELD-level, which is what the generated model carries: the cross-field
    CEL rules stay server-authoritative, so this is a smaller check than the Go client's
    protovalidate interceptor, not an equal one. What it does catch is the common case — a
    required recipient or idempotency key left unset — where the server's only possible
    answer is a refusal.

    The validated value is DISCARDED and the caller's own object is what gets sent: a
    parse fills declared defaults, and sending those would put fields on the wire the
    caller never set.
    """
    if validation == "off":
        return
    try:
        model.model_validate(message)
    except ValidationError as exc:
        raise _schema_failure(
            op, exc, "request failed its generated schema; the server could only refuse it"
        ) from exc


def decode_with_raw(
    op: str, status: int, body: str, model: type[BaseModel]
) -> tuple[Any, dict[str, Any]]:
    """Decode one answer and hand back the RAW object beside the parsed message.

    Discovery needs both and they must be the same read: the parse is the GATE — it proves
    the answer well formed and its field names canonical — while offer verification has to
    run over what the responder actually sent, because a parse fills declared defaults and
    a signature covers no such thing. Parsing the body twice would be a second read of the
    same bytes for no gain.
    """
    _refuse_redirect(op, status)
    payload = _parse_json(op, status, body)
    parsed = _validate(op, status, payload, model)
    return parsed, payload if isinstance(payload, dict) else {}


def decode(op: str, status: int, body: str, model: type[BaseModel]) -> Any:
    """Turn one answer into a parsed message, or raise the typed failure.

    A non-2xx is the Connect error envelope ``{code, message, details}``. The typed reason
    rides in ``details``, which :func:`~ramp_sdk.errordetail.error_detail_from` reads —
    including the lowerCamelCase ``debug`` projection connect-go emits there and no server
    codec replaces.
    """
    _refuse_redirect(op, status)
    return _validate(op, status, _parse_json(op, status, body), model)


_HTTP_MULTIPLE_CHOICES_END = 400


def _refuse_redirect(op: str, status: int) -> None:
    """A 3xx is a server that did not answer, not one that declined.

    Every leg refuses to follow a redirect, so one reaching a reader means the call did not
    happen — and there is nothing in a redirect body to interpret. Unconditional on purpose:
    a 302 carrying a Connect envelope would otherwise be read as the peer's own verdict, and
    connect-go has no answer to mirror here because its transport follows redirects and
    never surfaces one.
    """
    if _HTTP_MULTIPLE_CHOICES <= status < _HTTP_MULTIPLE_CHOICES_END:
        raise CallError(
            CallErrorKind.UNREACHABLE,
            op,
            status=status,
            cause="peer answered with a redirect, which this client does not follow",
        )


def _validate(op: str, status: int, payload: Any, model: type[BaseModel]) -> Any:
    if not _HTTP_OK <= status < _HTTP_MULTIPLE_CHOICES:
        raise _connect_envelope_error(op, status, payload)
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise _schema_failure(op, exc, "peer answer failed its generated schema") from exc


def _schema_failure(op: str, exc: ValidationError, summary: str) -> CallError:
    """Name what a generated model refused.

    The wire policy — the lowerCamelCase ``json_name`` alias is out of contract, at every
    depth — belongs to the schemas, so it lives with them on :class:`wire.base.WireModel`
    and this tier only says what its refusal MEANS to a caller. Recognised by the error
    ``type`` the validator raises rather than by its message, so the wording stays free to
    change.
    """
    if any(err.get("type") == JSON_NAME_ALIAS_ERROR for err in exc.errors()):
        return CallError(
            CallErrorKind.MALFORMED, op, reason=NOT_CANONICAL_WIRE_NAMING, cause=str(exc)
        )
    return malformed(op, summary)


#: How deep a peer's answer may nest.
#:
#: The same 32 the error-detail reader uses and the protocol sets for a stranger's JSON in
#: ``AccountRegistration.data_schema``, so one number covers how deep any document this SDK
#: did not write may be. The deepest instance in the whole conformance corpus is 5.
_MAX_BODY_DEPTH = 32


def _parse_json(op: str, status: int, body: str) -> Any:
    # Depth BEFORE the parse, because ``json.loads`` descends recursively and aborts on a
    # deep document by raising ``RecursionError`` — which is not a ``ValueError``, so the
    # handler below never saw it, and not a failure this package says it raises. A 40 KB
    # body, far under the read cap, threw an untyped exception out of every verb, on the
    # success path as well as the error path.
    #
    # A check placed after the parse would be reached only by documents harmless enough to
    # parse. The scan is lexical and shared with the registration-schema compiler, which
    # documents the same trap; counting needs no recursion.
    if _raw_nesting_depth(body.encode("utf-8", errors="replace")) > _MAX_BODY_DEPTH:
        raise CallError(
            CallErrorKind.MALFORMED,
            op,
            status=status,
            cause=f"answer nests deeper than {_MAX_BODY_DEPTH} containers",
        )
    try:
        return json.loads(body or "{}")
    except ValueError as exc:
        # A non-2xx body that is not JSON did not come from the service: it is a gateway,
        # a proxy or a load balancer answering for it. The STATUS is then the only thing
        # that classifies it, which is what connect-go does with the same answer — and
        # calling a momentary 502 malformed would put a retryable outage in the "this peer
        # is broken" class. A 2xx that is not JSON is a different thing: the service
        # claimed to answer and did not, which IS malformed.
        if not _HTTP_OK <= status < _HTTP_MULTIPLE_CHOICES:
            raise CallError(
                kind_of_connect_code(connect_code_from_status(status)),
                op,
                status=status,
                reason=connect_code_from_status(status),
                cause=exc,
            ) from exc
        raise CallError(CallErrorKind.MALFORMED, op, status=status, cause=exc) from exc


def _connect_envelope_error(op: str, status: int, payload: Any) -> CallError:
    envelope = payload if isinstance(payload, dict) else {}
    code = envelope.get("code")
    code = code if isinstance(code, str) else ""
    # An envelope carrying no code is not a verdict the peer reached, so the STATUS decides
    # the class — which is what connect-go does with the same answer. Reporting a draining
    # gateway's 503 as a refusal tells a caller not to retry a usage report that would
    # succeed a moment later.
    if not code:
        code = connect_code_from_status(status)
    message = envelope.get("message")
    return CallError(
        kind_of_connect_code(code),
        op,
        status=status,
        # The peer's own token, which is the Connect code here. A caller that wants more
        # than the class reads the typed detail.
        reason=code or None,
        detail=error_detail_from(envelope),
        cause=message if isinstance(message, str) else None,
    )


def as_call_error(op: str, exc: BaseException) -> CallError:
    """Classify a failure the transport raised. An already-classified CallError passes
    through; anything else is a peer that did not answer."""
    if isinstance(exc, CallError):
        return exc
    return CallError(CallErrorKind.UNREACHABLE, op, cause=exc)
