"""The response caps bound the READ, on every leg and in both faces.

A cap read off ``response.content`` is a measurement, not a limit: httpx buffers the whole
body before that attribute exists, and decompresses on the way, so the allocation has
already happened by the time the comparison runs. Measured against a local server, 199 KB
of gzip on the wire reached 200 MB resident before a 1 MiB check could fire — and the
peers on three of these legs are hosts another party named: an offer-derived Exchange and
a delivery edge.

So every leg streams and stops one byte past the cap, and asks for ``identity`` encoding
so the cap counts wire bytes too. These tests drive real HTTP against a local server,
because the defect was invisible to a mock transport that hands back a body already in
memory.
"""

from __future__ import annotations

import asyncio
import gzip
import contextlib
import http.server
import socketserver
import threading
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from ramp_sdk import sync as blocking
from ramp_sdk.client import BrokerClient, Client, ClientConfig
from ramp_sdk.client.errors import CallError, CallErrorKind
from ramp_sdk.signing_transport import SigningTransport

if TYPE_CHECKING:
    from collections.abc import Iterator

_SEED = bytes(range(32))
_REQUESTER = {"id": "agent-1", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"}

#: Well past the 1 MiB RPC cap once expanded, and small on the wire.
_EXPANDED = b"A" * (32 << 20)
_GZIPPED = gzip.compress(_EXPANDED)


class _Handler(http.server.BaseHTTPRequestHandler):
    """Answers every request with an oversized body, gzipped if the client accepted it."""

    seen_accept_encoding: str | None = None

    def _respond(self) -> None:
        type(self).seen_accept_encoding = self.headers.get("accept-encoding")
        gzip_ok = "gzip" in (self.headers.get("accept-encoding") or "")
        payload = _GZIPPED if gzip_ok else _EXPANDED
        self.send_response(200)
        self.send_header("content-type", "application/json")
        if gzip_ok:
            self.send_header("content-encoding", "gzip")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        # The client stops reading at its cap, which is the point of the test.
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(payload)

    do_GET = _respond  # noqa: N815 - the name BaseHTTPRequestHandler dispatches on
    do_POST = _respond  # noqa: N815

    def log_message(self, *_args: Any) -> None:
        return


class _GzipAnyway(_Handler):
    """Answers gzip whatever the client negotiated — a peer breaking its own answer."""

    def _respond(self) -> None:
        type(self).seen_accept_encoding = self.headers.get("accept-encoding")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-encoding", "gzip")
        self.send_header("content-length", str(len(_GZIPPED)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(_GZIPPED)

    do_GET = _respond  # noqa: N815 - the name BaseHTTPRequestHandler dispatches on
    do_POST = _respond  # noqa: N815


@pytest.fixture
def gzipping_server() -> Iterator[str]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _GzipAnyway)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def oversized_server() -> Iterator[str]:
    _Handler.seen_accept_encoding = None
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _config(base_url: str) -> ClientConfig:
    return ClientConfig(
        base_url=base_url,
        requester=_REQUESTER,
        signer=SigningTransport(signer_seed=_SEED, keyid="agent.v1"),
    )


def test_the_async_rpc_leg_refuses_an_oversized_answer(oversized_server: str) -> None:
    async def run() -> CallError:
        async with Client(_config(oversized_server)) as client:
            with pytest.raises(CallError) as caught:
                await client.discover({"exchange": "exchange.test"})
            return caught.value

    assert asyncio.run(run()).kind is CallErrorKind.TOO_LARGE


def test_the_blocking_rpc_leg_refuses_an_oversized_answer(oversized_server: str) -> None:
    with (
        blocking.Client(_config(oversized_server)) as client,
        pytest.raises(CallError) as caught,
    ):
        client.discover({"exchange": "exchange.test"})
    assert caught.value.kind is CallErrorKind.TOO_LARGE


def test_the_broker_leg_refuses_an_oversized_answer(oversized_server: str) -> None:
    with (
        blocking.BrokerClient(_config(oversized_server)) as broker,
        pytest.raises(CallError) as caught,
    ):
        broker.resolve({})
    assert caught.value.kind is CallErrorKind.TOO_LARGE


def test_the_client_negotiates_identity(oversized_server: str) -> None:
    # httpx's own default is "gzip, deflate", so without an explicit identity the peer is
    # invited to send 200 KB that becomes 200 MB inside the client.
    with blocking.Client(_config(oversized_server)) as client, pytest.raises(CallError):
        client.discover({"exchange": "exchange.test"})
    assert _Handler.seen_accept_encoding == "identity"


def test_a_coding_the_client_did_not_negotiate_is_refused(gzipping_server: str) -> None:
    """The peer answers ``identity`` with gzip anyway — the case a running total cannot hold.

    Refused as MALFORMED rather than TOO_LARGE, and refused BEFORE the body is read: the
    decoder expands a whole raw read at once, so by the time a decoded chunk could be
    counted the memory is already spent.
    """
    with blocking.Client(_config(gzipping_server)) as client, pytest.raises(CallError) as caught:
        client.discover({"exchange": "exchange.test"})
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert "content-encoding" in str(caught.value)


def test_the_async_face_refuses_it_too(gzipping_server: str) -> None:
    async def run() -> CallError:
        async with Client(_config(gzipping_server)) as client:
            with pytest.raises(CallError) as caught:
                await client.discover({"exchange": "exchange.test"})
            return caught.value

    assert asyncio.run(run()).kind is CallErrorKind.MALFORMED


def test_an_injected_client_is_not_closed_by_the_sdk(oversized_server: str) -> None:
    injected = httpx.Client(follow_redirects=False)
    with blocking.Client(_config(oversized_server), http=injected):
        pass
    assert not injected.is_closed, "the SDK closed a transport it did not build"
    injected.close()


def test_a_client_the_sdk_built_is_closed_with_it(oversized_server: str) -> None:
    client = blocking.Client(_config(oversized_server))
    with client:
        pass
    assert client._http.is_closed
    assert client._guarded.is_closed


def test_the_async_client_is_a_context_manager() -> None:
    async def run() -> bool:
        async with Client(_config("https://exchange.test")) as client:
            return client is not None

    assert asyncio.run(run()) is True


def test_the_broker_client_is_a_context_manager() -> None:
    async def run() -> bool:
        async with BrokerClient(_config("https://broker.test")) as broker:
            return broker is not None

    assert asyncio.run(run()) is True


def test_the_delivery_deadline_covers_proof_minting() -> None:
    """The budget bounds the whole fetch, not the round trip after signing finished.

    Minting may call out to a custody backend bounded only by that backend's own client, so
    a timeout applied to the round trip alone left "bounds one content fetch" untrue: the
    call took as long as signing took and then started a fresh full budget on top. Measured
    before this at 3.0 s against a 0.5 s budget.

    NOT_SIGNABLE, which is what Go answers for the same condition — its Fetch runs one
    context across both halves. It does not interrupt signing; what it bounds is the total.
    """

    class _SlowSigner(SigningTransport):
        def sign_agent_binding(self, *, url: str, window: Any) -> tuple[str, str, str]:
            time.sleep(0.3)
            return super().sign_agent_binding(url=url, window=window)

    config = ClientConfig(
        base_url="https://exchange.test",
        requester=_REQUESTER,
        signer=_SlowSigner(signer_seed=_SEED, keyid="agent.v1"),
        content_timeout_sec=0.05,
    )
    with blocking.Client(config) as client, pytest.raises(CallError) as caught:
        client.fetch("https://edge.test/x")
    assert caught.value.kind is CallErrorKind.NOT_SIGNABLE
    assert "budget" in str(caught.value)
