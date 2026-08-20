"""Reading one answer under a cap, and the transport split the cap protects.

The bound is what stops a peer spending the caller's memory on its behalf, and on three
of the legs that peer is a host another party named — an offer-derived Exchange, or a
delivery edge. It has to bound the READ, not report on it afterwards: httpx buffers a
whole response before ``.content`` is available, and it decompresses on the way, so a
check against an already-materialised body is a measurement rather than a limit. Two
hundred kilobytes of gzip expand to two hundred megabytes before such a check can fire.

So every leg streams and stops one byte past the cap. Detected, never truncated:
truncated content that looks whole is worse than a refusal, because the caller has no way
to tell it is incomplete and on the delivery leg has already paid for it.

``accept-encoding: identity`` rides along for the same reason. Bounding the decoded
stream is already enough to hold memory, but asking for no coding at all means the cap
counts the bytes on the wire as well, and it keeps the three languages reading the same
answer: TypeScript's undici does not decode a content coding, so a client that accepted
one would be handed octets it then blamed the peer for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import CallError, CallErrorKind

if TYPE_CHECKING:
    from . import _verbs

#: Asks the peer for no content coding. See the module docstring.
IDENTITY_ENCODING = {"accept-encoding": "identity"}


def over_cap(op: str, max_bytes: int, status: int | None = None) -> CallError:
    """The refusal for an answer past its cap."""
    return CallError(
        CallErrorKind.TOO_LARGE,
        op,
        status=status,
        cause=f"body exceeds the {max_bytes} byte cap",
    )


def decode_body(chunks: list[bytes]) -> str:
    """Join what was read into the text the decode step parses."""
    return b"".join(chunks).decode("utf-8", errors="replace")


def rpc_headers(plan: _verbs.Plan) -> dict[str, str]:
    """The plan's own headers plus the encoding request every leg makes."""
    return {**plan.headers, **IDENTITY_ENCODING}


def guarded_leg(plan: _verbs.Plan) -> bool:
    """Whether this plan dials a host another party named.

    Mirrors the Go client's split: a second, address-guarded transport carries the
    offer-derived legs, and the configured home Exchange keeps a plain one. An operator
    that points the SDK at a private origin chose that address; an offer that names one
    did not.
    """
    return plan.guarded


def bounded_chunks(op: str, max_bytes: int, status: int) -> _Bounded:
    """An accumulator that refuses at the first byte past the cap."""
    return _Bounded(op=op, max_bytes=max_bytes, status=status)


class _Bounded:
    """Collects a streamed body, raising as soon as it is one byte too long.

    Shared by the async and the blocking faces: only the iteration differs between them,
    and the rule must not.
    """

    __slots__ = ("_chunks", "_max", "_op", "_status", "_total")

    def __init__(self, *, op: str, max_bytes: int, status: int) -> None:
        self._op = op
        self._max = max_bytes
        self._status = status
        self._chunks: list[bytes] = []
        self._total = 0

    def add(self, chunk: bytes) -> None:
        self._total += len(chunk)
        if self._total > self._max:
            raise over_cap(self._op, self._max, self._status)
        self._chunks.append(chunk)

    @property
    def chunks(self) -> list[bytes]:
        return self._chunks

    def text(self) -> str:
        return decode_body(self._chunks)

    def body(self) -> bytes:
        return b"".join(self._chunks)
