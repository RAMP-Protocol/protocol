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

from ramp_sdk._wire_names import snake_from_json_name
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
#: ``"strict"`` is the default, mirroring the Go client. A caller that means to probe a
#: server with a deliberately invalid message turns it off.
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
    except Exception as exc:  # pydantic's ValidationError, by any name
        raise malformed(
            op, "request failed its generated schema; the server could only refuse it"
        ) from exc


def decode(op: str, status: int, body: str, model: type[BaseModel]) -> Any:
    """Turn one answer into a parsed message, or raise the typed failure.

    A non-2xx is the Connect error envelope ``{code, message, details}``. The typed reason
    rides in ``details``, which :func:`~ramp_sdk.errordetail.error_detail_from` reads —
    including the lowerCamelCase ``debug`` projection connect-go emits there and no server
    codec replaces.
    """
    payload = _parse_json(op, status, body)
    if not _HTTP_OK <= status < _HTTP_MULTIPLE_CHOICES:
        raise _connect_envelope_error(op, status, payload)
    _assert_canonical_naming(op, payload, model)
    try:
        return model.model_validate(payload)
    except Exception as exc:  # pydantic's ValidationError, by any name
        raise malformed(op, "peer answer failed its generated schema") from exc


def _parse_json(op: str, status: int, body: str) -> Any:
    try:
        return json.loads(body or "{}")
    except ValueError as exc:
        # A body that is not JSON is not an answer this protocol defines, whatever the
        # status said. Reported as malformed rather than as the status's own class,
        # because the status is the peer's claim about a body that turned out not to
        # exist.
        raise CallError(CallErrorKind.MALFORMED, op, status=status, cause=exc) from exc


def _connect_envelope_error(op: str, status: int, payload: Any) -> CallError:
    envelope = payload if isinstance(payload, dict) else {}
    code = envelope.get("code")
    code = code if isinstance(code, str) else ""
    message = envelope.get("message")
    return CallError(
        kind_of_connect_code(code) if code else CallErrorKind.REFUSED,
        op,
        status=status,
        # The peer's own token, which is the Connect code here. A caller that wants more
        # than the class reads the typed detail.
        reason=code or None,
        detail=error_detail_from(envelope),
        cause=message if isinstance(message, str) else None,
    )


def _assert_canonical_naming(op: str, payload: Any, model: type[BaseModel]) -> None:
    """Refuse an answer whose field names are lowerCamelCase.

    The RAMP wire is snake_case proto-JSON and the camelCase json_name alias is out of
    contract, so a conformant Exchange serves snake_case — connect-go does that only when
    a codec with UseProtoNames is registered, which a RAMP deployment does and a stock
    connect-go server does not. The generated models accept snake_case only and IGNORE
    what they do not recognise, so a camelCase answer would otherwise parse SUCCESSFULLY
    into a message with every multiword field missing: no offers, no rate limit, no
    absence reason, and no error anywhere. Silence is the wrong answer to a peer that is
    not speaking the protocol.

    The check is at the message ROOT and nowhere deeper. That is what makes it safe rather
    than merely cheap: open maps — ``ext``, ``metadata``, a Struct — hold caller-chosen
    keys, and those live inside a root field's VALUE, so a root-key comparison cannot
    reach them. A camelCase peer is camelCase everywhere, so the root is enough to
    recognise one; the case it cannot see is a message whose populated fields are all
    single words, where the two spellings are identical and nothing is lost either way.
    """
    if not isinstance(payload, dict):
        return
    declared = set(model.model_fields)
    for key in payload:
        if key in declared:
            continue
        name = snake_from_json_name(key)
        if name != key and name in declared:
            raise CallError(
                CallErrorKind.MALFORMED,
                op,
                reason=NOT_CANONICAL_WIRE_NAMING,
                cause=(
                    f"peer answered with the lowerCamelCase json_name alias ({key}); the "
                    "RAMP wire is snake_case proto-JSON, so its answer cannot be read "
                    "without silently dropping every multiword field"
                ),
            )


def as_call_error(op: str, exc: BaseException) -> CallError:
    """Classify a failure the transport raised. An already-classified CallError passes
    through; anything else is a peer that did not answer."""
    if isinstance(exc, CallError):
        return exc
    return CallError(CallErrorKind.UNREACHABLE, op, cause=exc)
