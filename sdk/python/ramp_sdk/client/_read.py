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

Streaming alone is NOT enough, which is the part that took a second measurement to see.
``iter_bytes()`` yields the decoded output of one raw read, and the gzip decoder expands a
64 KiB raw chunk in a single unbounded ``zlib.decompress()`` — so a peer that gzips anyway
materialises one chunk far past the cap before the running total can refuse it. Measured at
70 MiB of growth against a 1 MiB cap.

So the client negotiates ``accept-encoding: identity`` and REFUSES a coding it did not ask
for. That check, not the running total, is what makes the bound hold at any chunk size: a
coding on the response is the peer breaking a negotiation it answered. It also keeps the
three languages reading the same answer — undici does not decode a content coding, so a
client that accepted one would be handed octets it then blamed the peer for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import CallError, CallErrorKind

if TYPE_CHECKING:
    import httpx

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


def refuse_unrequested_encoding(op: str, response: httpx.Response) -> None:
    """Refuse a response carrying a content coding the client did not ask for.

    Every leg sends ``accept-encoding: identity``, so a coding here is the peer answering a
    negotiation and then ignoring it. It is refused BEFORE the body is read, because that
    is the only bound that holds at any chunk size: the decoder expands a whole raw read at
    once, so a running total over decoded chunks can be overshot by however much one chunk
    happens to inflate to.

    ``identity`` itself is not a coding, and neither is an absent header.
    """
    coding = (response.headers.get("content-encoding") or "").strip().lower()
    if coding in ("", "identity"):
        return
    raise CallError(
        CallErrorKind.MALFORMED,
        op,
        status=response.status_code,
        cause=(
            f"peer answered with content-encoding {coding!r} after being asked for "
            "identity; a coding this client did not negotiate cannot be read under a bound"
        ),
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
