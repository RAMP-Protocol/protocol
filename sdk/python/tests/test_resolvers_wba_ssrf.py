"""SSRF-guard parity for the WBA default transport (port of the Go oracle's
wbakeyresolver_ssrf_internal_test.go).

The WBA directory host is derived from a caller-supplied Signature-Agent header
and fetched BEFORE the ed25519 signature check, so the DEFAULT transport must be
SSRF-guarded. These suites pin (1) the reserved-range classification byte-for-byte
against the Go set — including the ranges the naive ipaddress heuristics miss
(CGNAT 100.64/10, 0.0.0.0/8, v4-mapped and NAT64 forms embedding a private v4) —
and (2) that the guarded default transport refuses a loopback target.
"""

from __future__ import annotations

import http.server
import threading

import pytest
from conftest import GO_TESTDATA, load_json

from ramp_sdk.resolvers._http import guarded_fetch
from ramp_sdk.resolvers._ssrf import SsrfError, allowed_scheme, blocked_address

# The shared adversarial corpora (Go emits, all SDKs consume — never edited here).
_ADDRESS_VECTORS = load_json(GO_TESTDATA / "ssrf-address-vectors.json")["vectors"]
_SCHEME_VECTORS = load_json(GO_TESTDATA / "ssrf-scheme-vectors.json")["vectors"]


@pytest.mark.parametrize("vec", _ADDRESS_VECTORS, ids=lambda v: v["name"])
def test_address_corpus_parity(vec: dict) -> None:
    """blocked_address must agree with the Go oracle on EVERY address vector."""
    assert _ADDRESS_VECTORS, "address corpus must be non-empty"
    assert blocked_address(vec["addr"]) is vec["blocked"], (
        f"{vec['name']} ({vec['addr']}): expected blocked={vec['blocked']}"
    )


@pytest.mark.parametrize("vec", _SCHEME_VECTORS, ids=lambda v: v["name"])
def test_scheme_corpus_parity(vec: dict) -> None:
    """allowed_scheme must agree with the Go oracle on EVERY scheme vector."""
    assert _SCHEME_VECTORS, "scheme corpus must be non-empty"
    assert allowed_scheme(vec["scheme"]) is vec["allowed"], (
        f"{vec['name']} ({vec['scheme']}): expected allowed={vec['allowed']}"
    )

# Mirrors TestSSRFBlocked_ReservedRanges (Go): each MUST be classified blocked.
_BLOCKED = [
    "0.1.2.3",  # 0.0.0.0/8 non-zero host — missed by ipaddress is_reserved alone
    "10.0.0.1",  # RFC 1918
    "100.64.0.1",  # CGNAT — missed by is_private
    "127.0.0.1",  # loopback
    "169.254.169.254",  # link-local / cloud metadata
    "172.16.5.5",  # RFC 1918
    "192.168.1.1",  # RFC 1918
    "198.18.0.1",  # benchmarking
    "192.0.2.7",  # TEST-NET-1
    "::1",  # v6 loopback
    "fc00::1",  # ULA
    "fe80::1",  # v6 link-local
    "::ffff:169.254.1.1",  # v4-mapped link-local — must unwrap
    "::ffff:10.0.0.1",  # v4-mapped RFC 1918
    "64:ff9b::a9fe:a9fe",  # NAT64-embedded 169.254.169.254 — must unwrap
    "64:ff9b::0a00:0001",  # NAT64-embedded 10.0.0.1
    "2001:db8::1",  # documentation
    # Extra coverage beyond the Go list, all in the shared prefix table:
    "240.0.0.1",  # reserved / future use (240/4)
    "255.255.255.255",  # limited broadcast
    "224.0.0.1",  # multicast
    "192.88.99.1",  # 6to4 relay anycast
    "203.0.113.9",  # TEST-NET-3
    "198.51.100.9",  # TEST-NET-2
    "64:ff9b:1::1",  # NAT64 local-use /48 (prefix-table hit, not unwrap)
]

# Mirrors the Go allowed list — public addresses must NOT be blocked.
_ALLOWED = [
    "8.8.8.8",  # public v4
    "1.1.1.1",  # public v4
    "93.184.216.34",  # public v4 (example.com)
    "2606:4700:4700::1111",  # public v6 (cloudflare)
    "2606:4700::",  # public v6
]


@pytest.mark.parametrize("addr", _BLOCKED)
def test_blocked_address_rejects_reserved(addr: str) -> None:
    assert blocked_address(addr) is True, f"{addr} should be blocked"


@pytest.mark.parametrize("addr", _ALLOWED)
def test_blocked_address_allows_public(addr: str) -> None:
    assert blocked_address(addr) is False, f"{addr} should be allowed"


def test_blocked_address_accepts_ipaddress_object() -> None:
    import ipaddress

    assert blocked_address(ipaddress.ip_address("10.0.0.1")) is True
    assert blocked_address(ipaddress.ip_address("8.8.8.8")) is False


def test_guarded_fetch_refuses_loopback() -> None:
    """The guarded default transport must refuse a loopback target.

    Port of TestGuardedWBAClientBlocksLoopback: an in-process server listens on
    127.0.0.1, so a successful GET would prove the guard is absent. The refusal is
    an ``SsrfError`` (an ``OSError``) whose message mentions the SSRF guard.
    """
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(SsrfError) as excinfo:
            guarded_fetch(f"http://127.0.0.1:{port}/")
        assert "SSRF" in str(excinfo.value)
    finally:
        server.shutdown()
        server.server_close()


def _serve(handler: type[http.server.BaseHTTPRequestHandler]):
    """Start an in-process HTTP server on 127.0.0.1; return (server, port)."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_guarded_fetch_refuses_redirect_to_ftp() -> None:
    """A 302 to an ftp:// target must be refused with an SsrfError.

    A scheme denylist is unwinnable, so the guarded transport is deny-by-default:
    only http/https redirects are followed. The ftp target is never dialed.
    """
    location = "ftp://ftp.example.com/secret"

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def log_message(self, *_a: object) -> None:
            return

    server, port = _serve(_RedirectHandler)
    try:
        with pytest.raises(SsrfError) as excinfo:
            guarded_fetch(f"http://127.0.0.1:{port}/")
        assert "SSRF" in str(excinfo.value)
    finally:
        server.shutdown()
        server.server_close()


def test_guarded_fetch_refuses_redirect_to_internal_address() -> None:
    """A 302 to an internal (loopback) address must be refused with an SsrfError.

    The redirect scheme (http) is allowed, but the redirect is followed through
    the SAME guarded opener, so the internal target is re-checked on connect and
    rejected — the rebinding window is closed on the redirect host too.
    """

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        # Redirect to a well-known internal address (cloud IMDS) the guard blocks.
        location = "http://169.254.169.254/latest/meta-data/"

        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", self.location)
            self.end_headers()

        def log_message(self, *_a: object) -> None:
            return

    server, port = _serve(_RedirectHandler)
    try:
        with pytest.raises(SsrfError) as excinfo:
            guarded_fetch(f"http://127.0.0.1:{port}/")
        assert "SSRF" in str(excinfo.value)
    finally:
        server.shutdown()
        server.server_close()


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:  # silence the test server
        return
