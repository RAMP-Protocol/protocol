"""Integration suite (TDD red) for the ported STATIC, WELL-KNOWN-KEY, and
WELL-KNOWN-ENDPOINT resolver faces — mirroring sdk/go/helpers
keyresolver_test.go + endpointresolver_test.go 1:1, plus the skip-not-fail
JWKS matrix.

These faces are IO-bound, so every case drives a REAL http.server origin (the
shared harness) through the resolver's default stdlib-urllib transport and
asserts the resolved key/endpoint back out. Only the clock is injected.

RED CONTRACT: the fetching faces + typed error classes live in
``ramp_sdk.resolvers`` (IO kept OUT of ``ramp_sdk.core`` so its httpx-ban guard
stays green) and DO NOT EXIST YET. The import below raises ModuleNotFoundError,
so the whole file is RED at collection until the next atom lands the faces — RED
on the missing faces, not on a fixture error.
"""

from __future__ import annotations

import queue
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest
from resolvers_harness import (
    ANCHOR,
    HOUR,
    MutableClock,
    Origin,
    jwks_entry,
    jwks_key_doc_json,
    make_key,
    manifest_json,
)

# The static face already ships in ramp_sdk.keyresolver; it is exercised here for
# parity with the Go static test.
from ramp_sdk.keyresolver import StaticKeyResolver

# RED: ramp_sdk.resolvers does not exist yet (TDD red). The typed error
# classes and the fetching faces are the ported public surface.
from ramp_sdk.resolvers import (  # type: ignore[import-not-found]
    DirectoryUnavailableError,
    EndpointRefusedError,
    NoEndpointError,
    WellKnownEndpointResolver,
    WellKnownKeyResolver,
)


def test_static_key_resolver_hit_and_unknown_miss() -> None:
    a = make_key()
    b = make_key()
    r = StaticKeyResolver({"a.v1": a.raw_pub})
    assert r.resolve("a.v1") == a.raw_pub
    # A plain unknown key is None (the fall-through miss), not an exception.
    assert r.resolve("missing") is None
    r.put("b.v1", b.raw_pub)
    assert r.resolve("b.v1") == b.raw_pub


def test_wellknown_key_fetch_then_cache() -> None:
    k = make_key()
    origin = Origin()
    origin.set_jwks(jwks_key_doc_json([jwks_entry("ex.v1", k.x)]))
    try:
        r = WellKnownKeyResolver(f"{origin.url}/keys.json", ttl=HOUR)
        assert r.resolve("ex.v1") == k.raw_pub
        # Cached: no second fetch.
        assert r.resolve("ex.v1") == k.raw_pub
        assert origin.jwks_hits() == 1
        # Unknown kid within the cache is None and does not refetch.
        assert r.resolve("nope") is None
        assert origin.jwks_hits() == 1
    finally:
        origin.close()


def test_wellknown_key_ttl_refresh() -> None:
    k = make_key()
    origin = Origin()
    origin.set_jwks(jwks_key_doc_json([jwks_entry("ex.v1", k.x)]))
    try:
        clock = MutableClock(ANCHOR)
        r = WellKnownKeyResolver(f"{origin.url}/keys.json", ttl=timedelta(minutes=1), now=clock)
        assert r.resolve("ex.v1") == k.raw_pub
        clock.t = ANCHOR + timedelta(minutes=2)  # expire the cache
        assert r.resolve("ex.v1") == k.raw_pub
        assert origin.jwks_hits() == 2
    finally:
        origin.close()


def test_wellknown_key_non200_raises_directory_unavailable() -> None:
    origin = Origin()
    origin.set_jwks_status(500)
    try:
        r = WellKnownKeyResolver(f"{origin.url}/keys.json", ttl=HOUR)
        # An outage is a raised DirectoryUnavailableError (fail-closed halt),
        # DISTINCT from a None miss that a composite would treat as "unknown key,
        # fall through".
        with pytest.raises(DirectoryUnavailableError):
            r.resolve("ex.v1")
    finally:
        origin.close()


def test_wellknown_key_skips_malformed_entries_resolves_survivors() -> None:
    # JWKS extraction is skip-not-fail — one malformed key must not kill the
    # whole publisher key set; survivors still resolve, bad entries become misses.
    good = make_key()
    non_ed = make_key()
    origin = Origin()
    origin.set_jwks(
        jwks_key_doc_json(
            [
                {"kty": "OKP", "crv": "Ed25519", "x": make_key().x},  # missing kid → skip
                # non-Ed25519 → skip
                {"kid": "rsa.v1", "kty": "RSA", "crv": "Ed25519", "x": non_ed.x},
                # bad-length x → skip
                {"kid": "short.v1", "kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
                jwks_entry("good.v1", good.x),  # valid survivor
            ]
        )
    )
    try:
        r = WellKnownKeyResolver(f"{origin.url}/keys.json", ttl=HOUR)
        assert r.resolve("good.v1") == good.raw_pub
        # Skipped entries are misses (None), NOT a raised parse failure.
        assert r.resolve("rsa.v1") is None
        assert r.resolve("short.v1") is None
    finally:
        origin.close()


# Every endpoint below is LATE-BOUND to the origin that serves it: an Exchange
# advertises ITSELF, so the value is not known until its server has an address.
# That is not test bookkeeping — it is the endpoint rule. An endpoint on any other
# host is one the resolver refuses to hand back, so a fixed exchange.example string
# served from a loopback port would exercise the refusal path rather than the
# behaviour each of these tests is about.
def test_endpoint_per_host_isolation() -> None:
    a = Origin()
    b = Origin()
    ep_a = f"http://{a.host}/ramp.v1.ExchangeService"
    ep_b = f"http://{b.host}/ramp.v1.ExchangeService"
    a.set_manifest(manifest_json(ep_a))
    b.set_manifest(manifest_json(ep_b))
    try:
        r = WellKnownEndpointResolver(ttl=HOUR, scheme="http")
        assert r.resolve_endpoint(a.host) == ep_a
        assert r.resolve_endpoint(b.host) == ep_b
        # Re-resolving A must never return B's endpoint — the cache is keyed per
        # host and B did not clobber A.
        assert r.resolve_endpoint(a.host) == ep_a
    finally:
        a.close()
        b.close()


def test_endpoint_cache_hit() -> None:
    origin = Origin()
    ep = f"http://{origin.host}/ramp.v1.ExchangeService"
    origin.set_manifest(manifest_json(ep))
    try:
        r = WellKnownEndpointResolver(ttl=HOUR, scheme="http")
        assert r.resolve_endpoint(origin.host) == ep
        assert r.resolve_endpoint(origin.host) == ep
        assert origin.manifest_hits() == 1
    finally:
        origin.close()


def test_endpoint_ttl_refresh() -> None:
    origin = Origin()
    ep = f"http://{origin.host}/ramp.v1.ExchangeService"
    origin.set_manifest(manifest_json(ep))
    try:
        clock = MutableClock(ANCHOR)
        r = WellKnownEndpointResolver(ttl=timedelta(minutes=1), scheme="http", now=clock)
        assert r.resolve_endpoint(origin.host) == ep
        clock.t = ANCHOR + timedelta(minutes=2)
        assert r.resolve_endpoint(origin.host) == ep
        assert origin.manifest_hits() == 2
    finally:
        origin.close()


def test_endpoint_non200_raises_directory_unavailable() -> None:
    origin = Origin()
    origin.set_manifest_status(503)
    try:
        r = WellKnownEndpointResolver(scheme="http")
        with pytest.raises(DirectoryUnavailableError):
            r.resolve_endpoint(origin.host)
    finally:
        origin.close()


def test_endpoint_decode_failure_raises_directory_unavailable() -> None:
    origin = Origin()
    origin.set_manifest("{not json")
    try:
        r = WellKnownEndpointResolver(scheme="http")
        with pytest.raises(DirectoryUnavailableError):
            r.resolve_endpoint(origin.host)
    finally:
        origin.close()


def test_endpoint_missing_field_raises_no_endpoint() -> None:
    origin = Origin()
    origin.set_manifest(manifest_json(None))  # valid manifest, no endpoint
    try:
        r = WellKnownEndpointResolver(scheme="http")
        # NoEndpointError must be DISTINCT from DirectoryUnavailableError: the
        # manifest was reachable and decoded, it simply advertises no endpoint.
        with pytest.raises(NoEndpointError):
            r.resolve_endpoint(origin.host)
        assert origin.manifest_hits() == 1
    finally:
        origin.close()


class _GatedJwksOrigin:
    """A real in-process origin serving ONE JWKS document and counting every fetch,
    with a gate that holds each response in-flight until released (and an ``arrived``
    queue signalling each blocked arrival) so a concurrent burst's single-flight
    coalescing is OBSERVABLE — the JWKS analogue of the WBA-debounce CountingOrigin.

    The shared ``Origin`` harness counts jwks_hits but cannot hold a fetch open, so a
    coalescing test needs this gated variant to park the leader in-flight while its
    followers pile onto the resolver's refresh lock."""

    def __init__(self) -> None:
        self._doc: bytes | None = None
        self._hits_lock = threading.Lock()
        self._hits = 0
        self.gate = threading.Event()
        self.arrived: queue.Queue[bool] = queue.Queue()
        origin = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # BaseHTTPRequestHandler method contract
                origin._record_hit()
                origin.arrived.put(True)
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

    def set_jwks(self, body: str) -> None:
        self._doc = body.encode()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def test_wellknown_key_concurrent_refresh_singleflight() -> None:
    """A concurrent burst of cold resolves for one JWKS URL coalesces to exactly ONE
    upstream fetch (independent of burst size). The origin holds the leader's fetch on
    a gate; followers park on the resolver's refresh lock and, once the leader fills
    the cache, return the cached key without a second fetch.

    Guards the resolver's existing single-flight (WellKnownKeyResolver._refresh holds
    _lock and double-checks freshness) — the same shape asserted for Go and TS. RED if
    single-flight regresses: a burst of N cold resolves would drive N JWKS fetches.
    """
    k = make_key()
    origin = _GatedJwksOrigin()
    origin.set_jwks(jwks_key_doc_json([jwks_entry("ex.v1", k.x)]))
    try:
        r = WellKnownKeyResolver(f"{origin.url}/keys.json", ttl=HOUR, now=MutableClock(ANCHOR))

        burst = 12
        barrier = threading.Barrier(burst)
        results: list[bytes | None] = [None] * burst
        errors: list[Exception | None] = [None] * burst

        def worker(i: int) -> None:
            barrier.wait()  # release all workers together
            try:
                results[i] = r.resolve("ex.v1")
            except Exception as exc:  # recorded per-worker, asserted after join
                errors[i] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(burst)]
        for t in threads:
            t.start()

        # The leader is parked in the origin holding the refresh lock; followers
        # coalesce behind it. Release only after the leader has arrived.
        origin.arrived.get(timeout=5)
        origin.gate.set()
        for t in threads:
            t.join(timeout=5)

        assert errors == [None] * burst
        assert results == [k.raw_pub] * burst
        assert origin.hits() == 1
    finally:
        origin.close()


# The WIRING half of the endpoint rule. Which endpoints the rule refuses is settled
# by the shared vectors (test_host_rule_parity.py and test_endpoint_vet_parity.py);
# what these cases pin is that the resolver actually asks — before it hands
# anything back, and before it caches.
def test_endpoint_on_an_unrelated_host_is_refused() -> None:
    origin = Origin()
    origin.set_manifest(manifest_json("https://cdn.other.example/ramp.v1.ExchangeService"))
    try:
        r = WellKnownEndpointResolver(ttl=HOUR, scheme="http")
        # A VERDICT, not a transport failure: the Exchange answered and the answer
        # is unusable, so a caller classifying retryability reads this as final.
        with pytest.raises(EndpointRefusedError):
            r.resolve_endpoint(origin.host)
    finally:
        origin.close()


def test_endpoint_carrying_credentials_is_refused_with_or_without_a_scheme() -> None:
    origin = Origin()
    try:
        r = WellKnownEndpointResolver(scheme="http")
        for ep in (
            f"http://user:pass@{origin.host}/ramp.v1.ExchangeService",
            # Schemeless. A plain URL parse reads "user" as the scheme and finds no
            # userinfo at all, while the anchor check recovers the host and matches
            # it — so this is the shape a rule that reads the reference twice lets
            # through.
            f"user:pass@{origin.host}/ramp.v1.ExchangeService",
        ):
            origin.set_manifest(manifest_json(ep))
            with pytest.raises(EndpointRefusedError):
                r.resolve_endpoint(origin.host)
    finally:
        origin.close()


def test_a_refused_endpoint_is_not_cached() -> None:
    origin = Origin()
    origin.set_manifest(manifest_json("https://cdn.other.example/ramp.v1.ExchangeService"))
    try:
        r = WellKnownEndpointResolver(ttl=HOUR, scheme="http")
        with pytest.raises(EndpointRefusedError):
            r.resolve_endpoint(origin.host)
        # The Exchange fixes its manifest. A resolver that had cached the refused
        # value would keep refusing for the whole TTL.
        ep = f"http://{origin.host}/ramp.v1.ExchangeService"
        origin.set_manifest(manifest_json(ep))
        assert r.resolve_endpoint(origin.host) == ep
    finally:
        origin.close()


def test_a_host_that_is_not_bare_never_reaches_the_network() -> None:
    origin = Origin()
    origin.set_manifest(manifest_json(f"http://{origin.host}/ramp.v1.ExchangeService"))
    try:
        r = WellKnownEndpointResolver(scheme="http")
        # The fetch URL is built by concatenation, so a smuggled path would choose
        # WHAT gets fetched. Refused before the network, so the origin is never hit.
        #
        # The refusal is the invalid-host fault, NOT EndpointRefusedError: the bad
        # value is the caller's argument, and no manifest was read to have a verdict
        # on.
        for bad in (f"{origin.host}/.well-known/evil.json", f"http://{origin.host}", ""):
            with pytest.raises(ValueError, match="not a usable host"):
                r.resolve_endpoint(bad)
        assert origin.manifest_hits() == 0
    finally:
        origin.close()


# The bare-host check is documented as running BEFORE the allow overlay and before
# the network. Three comments say so and nothing tested it: a resolver that ran the
# overlay first, or built the URL and dialled, would satisfy every other case here.
def test_a_host_that_is_not_bare_is_refused_before_the_overlay_and_the_network() -> None:
    asked: list[str] = []
    fetched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return httpx.Response(200, json={"endpoint": "http://a.example/v1"})

    def allow(host: str) -> bool:
        asked.append(host)
        return True

    r = WellKnownEndpointResolver(
        scheme="http",
        allow=allow,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ValueError, match="not a usable host"):
        r.resolve_endpoint("a.example/.well-known/evil.json")
    assert asked == []
    assert fetched == []
