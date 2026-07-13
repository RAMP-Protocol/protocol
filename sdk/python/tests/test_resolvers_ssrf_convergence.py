"""Real-dial behavioral convergence for the SSRF guard's redirect-depth cap and its
overall wall-clock budget — the sdk/python behavioral half (the input->verdict
predicate parity for redirect + host-set lives in test_resolvers_wba_ssrf.py, next
to the address/scheme replays).

The real httpx client is configured to the same redirect cap the shared corpus
pins (max_redirects), and the deadline test proves a slow resolution is bounded
rather than pinning the caller forever.
"""

from __future__ import annotations

import http.server
import socket
import threading
import time

import httpx
import pytest

from ramp_sdk.resolvers import _http, _ssrf
from ramp_sdk.resolvers._http import fetch_strict, guarded_client, ssrf_guard
from ramp_sdk.resolvers._ssrf import MAX_REDIRECTS
from ramp_sdk.resolvers.errors import DirectoryUnavailableError


class _RedirectChainHandler(http.server.BaseHTTPRequestHandler):
    """/n redirects to /(n-1); /0 is the terminal 200. The server's own base URL is
    injected as a class attribute so redirects are absolute."""

    base: str = ""

    def do_GET(self) -> None:
        try:
            n = int(self.path.lstrip("/"))
        except ValueError:
            n = 0
        if n <= 0:
            self.send_response(200)
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Location", f"{self.base}/{n - 1}")
        self.end_headers()

    def log_message(self, *_a: object) -> None:
        return


def _serve(handler: type[http.server.BaseHTTPRequestHandler]):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def test_redirect_depth_cap_real_dial(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real guarded httpx client follows exactly MAX_REDIRECTS hops and refuses
    the next — the real-dial confirmation that the client honors the shared corpus.

    Uses the guard-ALWAYS transport (ssrf_guard) with blocked_address mocked to
    allow the loopback origin, and the SAME max_redirects the factory sets, so this
    exercises the cap, not the address guard.
    """
    monkeypatch.setattr(_ssrf, "blocked_address", lambda _ip: False)
    server, port = _serve(_RedirectChainHandler)
    _RedirectChainHandler.base = f"http://127.0.0.1:{port}"
    client = httpx.Client(
        transport=ssrf_guard(), follow_redirects=True, max_redirects=MAX_REDIRECTS
    )
    try:
        # Exactly at the cap: followed to the 200 terminal.
        assert client.get(f"http://127.0.0.1:{port}/{MAX_REDIRECTS}").status_code == 200
        # One hop over the cap: refused (httpx raises TooManyRedirects).
        with pytest.raises(httpx.TooManyRedirects):
            client.get(f"http://127.0.0.1:{port}/{MAX_REDIRECTS + 1}")
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_total_wall_clock_budget_bounds_slow_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow getaddrinfo must not pin the guarded fetch past the overall budget.

    httpx's timeout is per-phase and does not cover our getaddrinfo, so the guarded
    fetch wraps an OVERALL wall-clock budget. Here getaddrinfo is made to block far
    longer than a shrunk budget; fetch_strict must return (as a DirectoryUnavailable
    outage) well within the sleep, proving the caller is bounded.
    """
    real_getaddrinfo = socket.getaddrinfo

    def _slow_getaddrinfo(*args: object, **kwargs: object):
        time.sleep(5.0)
        return real_getaddrinfo(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _slow_getaddrinfo)
    monkeypatch.setattr(_http, "_TOTAL_FETCH_DEADLINE_S", 0.3)
    monkeypatch.setenv("ALLOW_INSECURE", "true")  # http scheme; address guard stays ON

    client = guarded_client()
    start = time.monotonic()
    try:
        with pytest.raises(DirectoryUnavailableError):
            fetch_strict(client, "http://127.0.0.1:9/")
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"guarded fetch was not bounded by the budget (took {elapsed:.2f}s)"
    finally:
        client.close()
