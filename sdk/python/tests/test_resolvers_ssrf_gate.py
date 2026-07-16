"""Real-dial tests for the ONE env-driven best-effort guarded HTTP client factory,
Python side (mirror of the Go reference guardedclient_fromenv_internal_test.go).

``ramp_sdk.resolvers`` exposes EXACTLY ONE public guarded-client construction pair
— ``guarded_client(**httpx_kwargs)`` / ``guarded_async_client(**httpx_kwargs)`` —
driven by two orthogonal env flags:

  - SKIP_SSRF toggles the dial-time ADDRESS guard (default: on).
  - ALLOW_INSECURE toggles the SCHEME guard (default: https-only).

The two dimensions are independent, so each pillar sets the OTHER flag to the
permissive value to isolate the dimension under test. These are the Python mirror
of the four Go reference pillars, 1:1.

Real-dial ONLY — an in-process 127.0.0.1 server, driven via ``asyncio.run`` for
the async face so the suite needs no async-test plugin.
"""

from __future__ import annotations

import asyncio
import http.server
import threading

import pytest

import ramp_sdk.resolvers as resolvers_pkg
from ramp_sdk.resolvers._ssrf import SsrfError

_ENV_SKIP_SSRF = "SKIP_SSRF"
_ENV_ALLOW_INSECURE = "ALLOW_INSECURE"


def _serve(handler: type[http.server.BaseHTTPRequestHandler]):
    """Start an in-process HTTP server on 127.0.0.1; return (server, port)."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:  # silence the test server
        return


def test_guarded_client_blocks_loopback_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pillar 1: with the address guard on (SKIP_SSRF unset) the factory client
    refuses a loopback target at the dial seam. ALLOW_INSECURE is set so the http
    scheme is not the refuser — the ADDRESS guard is isolated."""
    monkeypatch.delenv(_ENV_SKIP_SSRF, raising=False)
    monkeypatch.setenv(_ENV_ALLOW_INSECURE, "true")
    server, port = _serve(_OkHandler)
    client = resolvers_pkg.guarded_client()
    try:
        with pytest.raises(SsrfError) as excinfo:
            client.get(f"http://127.0.0.1:{port}/")
        assert "SSRF" in str(excinfo.value)
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_skip_ssrf_reaches_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pillar 2: with SKIP_SSRF set the address guard steps aside and the async
    factory reaches the loopback origin. ALLOW_INSECURE is set so the http scheme
    is permitted — proving SKIP_SSRF alone drops the address pin (async face)."""
    monkeypatch.setenv(_ENV_SKIP_SSRF, "true")
    monkeypatch.setenv(_ENV_ALLOW_INSECURE, "true")
    server, port = _serve(_OkHandler)

    async def _attempt() -> int:
        client = resolvers_pkg.guarded_async_client()
        try:
            resp = await client.get(f"http://127.0.0.1:{port}/")
            return resp.status_code
        finally:
            await client.aclose()

    try:
        assert asyncio.run(_attempt()) == 200
    finally:
        server.shutdown()
        server.server_close()


def test_refuses_http_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pillar 3: with ALLOW_INSECURE unset a plaintext http:// target is refused
    for SCHEME. SKIP_SSRF is set so the address guard is absent and cannot be the
    refuser — proving http is refused on its own, not merely because it is loopback."""
    monkeypatch.setenv(_ENV_SKIP_SSRF, "true")
    monkeypatch.delenv(_ENV_ALLOW_INSECURE, raising=False)
    server, port = _serve(_OkHandler)
    client = resolvers_pkg.guarded_client()
    try:
        with pytest.raises(SsrfError) as excinfo:
            client.get(f"http://127.0.0.1:{port}/")
        assert "SSRF" in str(excinfo.value)
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_allow_insecure_permits_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pillar 4: with ALLOW_INSECURE set a plaintext http:// target is reached.
    SKIP_SSRF is set so the address guard is out of the way — proving ALLOW_INSECURE
    alone permits the http scheme."""
    monkeypatch.setenv(_ENV_SKIP_SSRF, "true")
    monkeypatch.setenv(_ENV_ALLOW_INSECURE, "true")
    server, port = _serve(_OkHandler)
    client = resolvers_pkg.guarded_client()
    try:
        assert client.get(f"http://127.0.0.1:{port}/").status_code == 200
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_proxy_env_does_not_tunnel_past_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mirror of Go TestGuardedClientNoProxyTunnel: with the address guard on and
    HTTP(S)_PROXY set, the guarded client must NOT tunnel a loopback target past
    the dial guard — it uses a no-proxy transport (trust_env=False). ALLOW_INSECURE
    is set so the http scheme reaches the transport and the address/proxy dimension
    is isolated."""
    monkeypatch.delenv(_ENV_SKIP_SSRF, raising=False)
    monkeypatch.setenv(_ENV_ALLOW_INSECURE, "true")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    server, port = _serve(_OkHandler)
    client = resolvers_pkg.guarded_client()
    try:
        with pytest.raises(SsrfError):
            client.get(f"http://127.0.0.1:{port}/")
    finally:
        client.close()
        server.shutdown()
        server.server_close()
