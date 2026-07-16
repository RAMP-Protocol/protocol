"""RAMP-24 anti-amplification parity (Python port of the Go
wbakeyresolver_debounce_test.go).

The unknown-thumbprint force-refresh is throttled to one directory fetch per
debounce window per host, and a concurrent burst coalesces to one in-flight
fetch. Because the resolver runs BEFORE the ed25519 check and the fetch host is
the caller-supplied Signature-Agent, an unauthenticated caller must not drive N
outbound GETs with N unknown-thumbprint requests.

The SAME behavioral bound as go/ts: a fetch-COUNTING origin + an injected clock
assert a burst of N unknown lookups -> 1 fetch (independent of N); the window
resumes after sync_debounce; a concurrent burst -> 1 fetch.
"""

from __future__ import annotations

import queue
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from resolvers_harness import (
    ANCHOR,
    HOUR,
    MutableClock,
    long_jwk,
    loopback_client,
    make_key,
    wba_file_json,
)

from ramp_sdk.resolvers import UnknownKeyError, WBAKeyResolver

_WBA_DIR_PATH = "/.well-known/http-message-signatures-directory"


class CountingOrigin:
    """A real in-process origin that serves ONE WBA directory document and counts
    every fetch of it, so a test can assert HOW MANY outbound GETs a burst made.
    An optional gate blocks each response until released, and ``arrived`` signals
    each blocked arrival — together they hold the singleflight leader in-flight so
    a concurrent burst's coalescing is observable."""

    def __init__(self) -> None:
        self._doc: bytes | None = None
        self._hits_lock = threading.Lock()
        self._hits = 0
        self.gate: threading.Event | None = None
        self.arrived: queue.Queue[bool] | None = None
        origin = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # BaseHTTPRequestHandler method contract
                if self.path.split("?")[0] != _WBA_DIR_PATH:
                    self.send_response(404)
                    self.end_headers()
                    return
                origin._record_hit()
                if origin.arrived is not None:
                    origin.arrived.put(True)
                if origin.gate is not None:
                    origin.gate.wait()
                doc = origin._doc
                if doc is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(doc)

            def log_message(self, *_args: Any) -> None:  # silence the test server
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _record_hit(self) -> None:
        with self._hits_lock:
            self._hits += 1

    def hits(self) -> int:
        with self._hits_lock:
            return self._hits

    def set_wba(self, body: str) -> None:
        self._doc = body.encode()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def test_unknown_thumbprint_burst_debounced() -> None:
    """A burst of N unknown lookups for one host forces exactly ONE directory
    fetch (independent of N); a lookup after the debounce window fetches again.

    RED before the fix: the unknown path force-fetches on every miss -> N fetches.
    """
    known = make_key()
    origin = CountingOrigin()
    origin.set_wba(wba_file_json([long_jwk(known.x)]))
    try:
        clock = MutableClock(ANCHOR)
        r = WBAKeyResolver(
            http=loopback_client(),
            scheme="http",
            ttl=HOUR,
            sync_debounce=timedelta(seconds=5),
            now=clock,
        )

        # Prime the directory cache with the known key (no force-refresh), then
        # measure only the forced fetches the burst triggers.
        assert r.resolve(known.tp, origin.url) == known.raw_pub
        primed = origin.hits()

        burst = 50
        for i in range(burst):
            with pytest.raises(UnknownKeyError):
                r.resolve(f"unknown-thumbprint-{i}", origin.url)
        assert origin.hits() - primed == 1

        # Advance past the debounce window (still within TTL): one more forced fetch.
        clock.t = ANCHOR + timedelta(seconds=6)
        with pytest.raises(UnknownKeyError):
            r.resolve("unknown-after-window", origin.url)
        assert origin.hits() - primed == 2
    finally:
        origin.close()


def test_concurrent_refresh_singleflight() -> None:
    """A concurrent burst of cold resolves for one host coalesces to a single
    outbound GET. The origin holds the leader's fetch on a gate; followers park
    inside the in-flight table until the leader completes."""
    known = make_key()
    origin = CountingOrigin()
    origin.set_wba(wba_file_json([long_jwk(known.x)]))
    origin.gate = threading.Event()
    origin.arrived = queue.Queue()
    try:
        r = WBAKeyResolver(
            http=loopback_client(), scheme="http", ttl=HOUR, now=MutableClock(ANCHOR)
        )

        burst = 12
        barrier = threading.Barrier(burst)
        results: list[bytes | None] = [None] * burst
        errors: list[Exception | None] = [None] * burst

        def worker(i: int) -> None:
            barrier.wait()  # release all workers together
            try:
                results[i] = r.resolve(known.tp, origin.url)
            except Exception as exc:  # recorded per-worker, asserted after join
                errors[i] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(burst)]
        for t in threads:
            t.start()

        # The leader is parked in the origin holding the in-flight slot; followers
        # coalesce onto it. Release only after the leader has arrived.
        assert origin.arrived is not None
        origin.arrived.get(timeout=5)
        origin.gate.set()
        for t in threads:
            t.join(timeout=5)

        assert errors == [None] * burst
        assert results == [known.raw_pub] * burst
        assert origin.hits() == 1
    finally:
        origin.close()
