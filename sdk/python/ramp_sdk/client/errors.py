"""The client's typed failure — Python port of sdk/go/connect/callerror.go.

A refusal and a failure are different things, and a caller handles the situations
differently. It cannot tell them apart from a message, so the class is carried as a value.

The one worth naming is: WE refused to send. The routing checks that precede a call to an
offer-derived address can decline before anything leaves the process, and folding that
into "unreachable" — as a network timeout — hides the difference between "the network is
bad" and "the address failed a security check". They call for opposite responses.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wire.models import ErrorDetail

#: The reason a peer's answer is refused for spelling its field names the wrong way.
#:
#: It is the SDK's own verdict rather than a token the peer sent, which is the one place
#: that happens: the peer's failure IS that it did not speak the contract, so there is no
#: refusal of its own to carry. Go never produces it — it speaks binary proto, and
#: protojson accepts both spellings on the way in — so this is a value only the JSON
#: clients can observe, not a divergence in the shared failure taxonomy.
NOT_CANONICAL_WIRE_NAMING = "not_canonical_wire_naming"


class CallErrorKind(enum.Enum):
    """Why a client call did not produce an answer."""

    #: The zero classification; it carries none.
    UNKNOWN = "unknown"
    #: A server that answered and said no, with a status and, usually, a typed reason.
    REFUSED = "refused"
    #: A server that did not answer: dial failure, timeout, or a redirect this SDK
    #: refused to follow.
    UNREACHABLE = "unreachable"
    #: THIS SDK declining to send. The address failed the plain-hostname, same-host or
    #: dial-time guard, so nothing left the process and no signature was exposed.
    NOT_SENT = "not_sent"
    #: A request that could not be built, or an answer that could not be read as the
    #: protocol defines it. Nothing was acted on.
    MALFORMED = "malformed"
    #: A response body past the configured cap.
    TOO_LARGE = "too_large"
    #: A signature or proof that could not be produced, typically custody declining or
    #: timing out. Nothing left the process.
    NOT_SIGNABLE = "not_signable"


class CallError(Exception):
    """The client's typed failure.

    Every verb raises this and nothing else, so ``except CallError`` is not a coin flip on
    the very type callers are told to branch on — which is what happens when a method
    raises a typed error where it declines to send and a bare transport error where the
    peer refuses.
    """

    def __init__(
        self,
        kind: CallErrorKind,
        op: str,
        *,
        status: int | None = None,
        reason: str | None = None,
        detail: ErrorDetail | None = None,
        cause: BaseException | str | None = None,
    ) -> None:
        self.kind = kind
        #: The verb that failed, in the SDK's own words ("discover", "fetch content").
        self.op = op
        #: HTTP status when the peer answered; ``None`` otherwise.
        self.status = status
        #: The peer's own refusal token when it sent one (a Connect code, an edge reason).
        self.reason = reason
        #: The typed protocol reason when there is one.
        self.detail = detail
        self.cause = cause
        super().__init__(_render(kind, op, status, reason, cause))

    def reason_of(self) -> str:
        """The most specific machine-readable reason available: the peer's own token when
        it sent one, otherwise the failure class."""
        return self.reason or self.kind.value


def _render(
    kind: CallErrorKind,
    op: str,
    status: int | None,
    reason: str | None,
    cause: BaseException | str | None,
) -> str:
    # Mirrors the Go failure renderer's shape (package, op, class, status, reason, cause)
    # so a log line reads the same whichever SDK produced it.
    parts = [f"ramp/client: {op}: {kind.value}"]
    if status:
        parts.append(f"status {status}")
    if reason:
        parts.append(f"reason {reason}")
    if cause is not None:
        parts.append(str(cause))
    return ": ".join(parts)


def not_sent(op: str, cause: BaseException | str) -> CallError:
    """The refusal for an address that failed a routing check.

    Its own constructor because every such refusal must state which check declined and
    must never carry a status: nothing was sent, so there is nothing to report one for.
    """
    return CallError(CallErrorKind.NOT_SENT, op, cause=cause)


def malformed(op: str, cause: BaseException | str) -> CallError:
    """The refusal for a request that could not be assembled, or an answer that could not
    be read as the protocol defines it."""
    return CallError(CallErrorKind.MALFORMED, op, cause=cause)


#: The Connect code a status implies when the body is not an envelope that names one.
#:
#: connect-go derives the code from the HTTP STATUS in exactly two cases: a body it cannot
#: read as an envelope, and an envelope carrying no code. Both are what a deployment's own
#: infrastructure produces — a gateway draining, a proxy answering with its own HTML page —
#: and the difference between "the Exchange declined this" and "nothing answered" is the
#: whole reason the failure classes exist. Anything not listed is ``unknown``, which reads
#: as a refusal.
#:
#: Not a rule invented here: it is connect-go's own table (protocol.go, httpToCode), and the
#: transport-failure corpus is captured from a real client so a future change to it is
#: reported rather than mirrored by hand.
_STATUS_CODES = {
    # A 3xx reached this client only because the send refused to follow it, and every leg
    # refuses. That is a server that did not answer the call, not one that declined it —
    # which is what all three failure taxonomies say a redirect is. connect-go maps these
    # to CodeUnknown, but it never sees one: its transport follows redirects, so the row is
    # unreachable there rather than decided.
    301: "unavailable",
    302: "unavailable",
    303: "unavailable",
    307: "unavailable",
    308: "unavailable",
    400: "internal",
    401: "unauthenticated",
    403: "permission_denied",
    404: "unimplemented",
    429: "unavailable",
    502: "unavailable",
    503: "unavailable",
    504: "unavailable",
}


def connect_code_from_status(status: int) -> str:
    """The Connect code a non-envelope answer carries, derived from its status."""
    return _STATUS_CODES.get(status, "unknown")


def kind_of_connect_code(code: str) -> CallErrorKind:
    """The Connect code a peer answered with, mapped onto the failure class.

    A peer that answered is a refusal, whatever it said: the distinction a caller needs is
    "it said no" versus "it never answered", and only the first is worth surfacing a
    reason for. Three codes land on the second side. ``unavailable`` is the transport
    failure proper; ``deadline_exceeded`` and ``canceled`` are LOCAL outcomes wearing a
    Connect code, so neither means the peer reached a verdict — classifying a caller's own
    cancellation as a refusal would tell it the Exchange declined a call the Exchange may
    never have seen. ``resource_exhausted`` is the read cap seen from this side: the
    peer's answer was larger than the client agreed to read.
    """
    if code in ("unavailable", "deadline_exceeded", "canceled"):
        return CallErrorKind.UNREACHABLE
    if code == "resource_exhausted":
        return CallErrorKind.TOO_LARGE
    return CallErrorKind.REFUSED
