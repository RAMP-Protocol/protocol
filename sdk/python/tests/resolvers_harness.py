"""Shared served-directory harness for the resolver integration suites.

Per the RAMP testing doctrine the ported resolver faces are IO-BOUND, so the
suites drive them against a REAL in-process ``http.server.ThreadingHTTPServer``
on 127.0.0.1:0 — never a mocked HTTP callable. The WBA suites inject
``loopback_client()`` (a plain, unguarded httpx.Client) so the guarded default
does not refuse the loopback origin; only the clock (and the poll timer/seams for
the WBA poller) are injected for determinism.

This module imports ONLY the existing byte-parity-pinned SDK primitives
(``thumbprint``, ``b64url_nopad``) and never the not-yet-existing
``ramp_sdk.resolvers`` faces, so a RED run points at the missing faces rather
than at this fixture.
"""

from __future__ import annotations

import json
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ramp_sdk.b64 import b64url_nopad
from ramp_sdk.thumbprint import thumbprint

# Well-known paths the origin serves. The WBA directory path is the fixed Web Bot
# Auth path; the JWKS key doc and the endpoint manifest sit on distinct paths so
# the key face (fixed URL) and endpoint face (host-keyed ramp.json) never collide.
WBA_DIR_PATH = "/.well-known/http-message-signatures-directory"
REVOCATION_PATH = "/.well-known/ramp-key-revocations.json"
MANIFEST_PATH = "/.well-known/ramp.json"
JWKS_PATH = "/keys.json"

# The shared anchor sits well inside the validity windows the active-key builders
# emit.
ANCHOR = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)

_FETCH_TIMEOUT_S = 10.0


def loopback_client() -> httpx.Client:
    """An UNGUARDED httpx.Client the resolver suites inject to reach the in-process
    origin.

    The origin listens on 127.0.0.1, which the SDK's default SSRF-guarded transport
    refuses to dial (loopback is a reserved target). Mirroring the Go oracle — whose
    httptest suites inject their own client past the guarded default — the
    integration suites inject this plain client via ``http=`` to REACH the private
    test directory. It is the escape hatch: a maintained httpx.Client with no SSRF
    guard, so 127.0.0.1 is reachable.
    """
    return httpx.Client(follow_redirects=True, timeout=_FETCH_TIMEOUT_S)


@dataclass
class TestKey:
    """A real Ed25519 key: raw 32-byte public key, its base64url ``x``, and its
    RFC 7638 thumbprint (the WBA keyid), derived through the SDK's own primitive."""

    raw_pub: bytes
    x: str
    tp: str


def make_key() -> TestKey:
    """Mint a fresh Ed25519 key and derive its SDK thumbprint."""
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = b64url_nopad(raw)
    return TestKey(raw_pub=raw, x=x, tp=thumbprint(raw))


def rfc3339(instant: datetime) -> str:
    """RFC3339-Z rendering of an aware instant."""
    return instant.astimezone(UTC).isoformat().replace("+00:00", "Z")


def wba_jwk(x: str, not_before: datetime, not_after: datetime) -> dict[str, Any]:
    """One JWK member of a WBA directory, snake_case exactly as the Go oracle
    emits it via protojson (UseProtoNames)."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "x": x,
        "not_before": rfc3339(not_before),
        "not_after": rfc3339(not_after),
    }


def wba_file_json(keys: list[dict[str, Any]], revocation_url: str | None = None) -> str:
    """Serialize a WBAFile carrying keys (and optionally a revocation_url)."""
    doc: dict[str, Any] = {"keys": keys}
    if revocation_url is not None:
        doc["revocation_url"] = revocation_url
    return json.dumps(doc)


def revocation_json(as_of: datetime, revoked: list[str]) -> str:
    """Serialize a KeyRevocationList snapshot (as_of RFC3339-Z + thumbprints)."""
    return json.dumps({"as_of": rfc3339(as_of), "revoked": revoked})


def jwks_entry(kid: str, x: str) -> dict[str, Any]:
    """A valid Ed25519 JWKS entry keyed by kid (the R1 ad-hoc doc shape)."""
    return {"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": x}


def jwks_key_doc_json(entries: list[dict[str, Any]]) -> str:
    """Serialize the ad-hoc kid-carrying JWKS key doc: ``{keys:[{kid,kty,crv,x}]}``."""
    return json.dumps({"keys": entries})


def manifest_json(endpoint: str | None = None) -> str:
    """Serialize a WellKnownManifest projection ({role, endpoint}); omit endpoint
    to model a valid-but-inert manifest."""
    doc: dict[str, Any] = {"role": "ROLE_EXCHANGE"}
    if endpoint is not None:
        doc["endpoint"] = endpoint
    return json.dumps(doc)


@dataclass
class _State:
    wba: str | None = None
    wba_status: int = 0
    rev: str | None = None
    jwks: str | None = None
    jwks_status: int = 0
    jwks_hits: int = 0
    manifest: str | None = None
    manifest_status: int = 0
    manifest_hits: int = 0


def _resolve_route(state: _State, path: str) -> tuple[int, bytes] | None:  # noqa: PLR0911 — flat route table
    if path == WBA_DIR_PATH:
        if state.wba_status != 0:
            return state.wba_status, b""
        if state.wba is None:
            return 404, b""
        return 200, state.wba.encode()
    if path == REVOCATION_PATH:
        if state.rev is None:
            return 404, b""
        return 200, state.rev.encode()
    if path == JWKS_PATH:
        state.jwks_hits += 1
        if state.jwks_status != 0:
            return state.jwks_status, b""
        if state.jwks is None:
            return 404, b""
        return 200, state.jwks.encode()
    if path == MANIFEST_PATH:
        state.manifest_hits += 1
        if state.manifest_status != 0:
            return state.manifest_status, b""
        if state.manifest is None:
            return 404, b""
        return 200, state.manifest.encode()
    return None


class Origin:
    """A real in-process origin serving the WBA directory, revocation snapshot,
    JWKS key doc, and ramp.json manifest. Each doc is independently settable so a
    test can rotate keys, publish a new revocation snapshot, or force a 500."""

    def __init__(self) -> None:
        self._state = _State()
        state = self._state

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hit = _resolve_route(state, self.path.split("?")[0])
                if hit is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                code, body = hit
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:  # silence the test server
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.host = f"127.0.0.1:{self._server.server_address[1]}"
        self.url = f"http://{self.host}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def set_wba(self, body: str) -> None:
        self._state.wba = body

    def set_wba_status(self, code: int) -> None:
        self._state.wba_status = code

    def set_revocation(self, body: str) -> None:
        self._state.rev = body

    def set_jwks(self, body: str) -> None:
        self._state.jwks = body

    def set_jwks_status(self, code: int) -> None:
        self._state.jwks_status = code

    def jwks_hits(self) -> int:
        return self._state.jwks_hits

    def set_manifest(self, body: str) -> None:
        self._state.manifest = body

    def set_manifest_status(self, code: int) -> None:
        self._state.manifest_status = code

    def manifest_hits(self) -> int:
        return self._state.manifest_hits

    def revocation_url(self) -> str:
        return self.url + REVOCATION_PATH

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class MutableClock:
    """A settable ``now`` seam for the non-poller cases: ``t`` is mutated between
    resolves to expire TTLs and cross validity windows."""

    def __init__(self, start: datetime) -> None:
        self.t = start

    def __call__(self) -> datetime:
        return self.t


@dataclass
class DeterministicClock:
    """A deterministic clock for the poller test: ``now()`` is a mutable instant;
    ``after(delay)`` returns a queue that receives a value when ``advance()`` moves
    the clock to or past the scheduled instant. Port of the Go pollClock
    (func() time.Time / func(Duration) <-chan time.Time) — the poller crosses a
    boundary without sleeping."""

    _now: datetime
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _pending: list[tuple[datetime, queue.Queue[datetime]]] = field(default_factory=list)

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def after(self, delay: timedelta) -> queue.Queue[datetime]:
        q: queue.Queue[datetime] = queue.Queue(maxsize=1)
        with self._lock:
            if delay <= timedelta(0):
                q.put(self._now)
                return q
            self._pending.append((self._now + delay, q))
        return q

    def advance(self, delay: timedelta) -> None:
        with self._lock:
            self._now = self._now + delay
            due = [p for p in self._pending if p[0] <= self._now]
            self._pending = [p for p in self._pending if p[0] > self._now]
            fire_at = self._now
        for _, q in due:
            q.put(fire_at)


class PollSignals:
    """Bridges the resolver's on_poll_armed / on_poll_cycle seams to the test, so
    it can wait for the poller to arm its timer, advance the clock, then wait for
    the refresh to complete — port of the Go pollSignals."""

    def __init__(self) -> None:
        self.armed: queue.Queue[bool] = queue.Queue()
        self.cycled: queue.Queue[bool] = queue.Queue()

    def on_armed(self) -> None:
        self.armed.put(True)

    def on_cycled(self) -> None:
        self.cycled.put(True)

    def cross_one(self, clk: DeterministicClock, advance: timedelta) -> None:
        self.armed.get(timeout=5)
        clk.advance(advance)
        self.cycled.get(timeout=5)


# Convenience validity-window builders around the shared anchor.
def active_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR - HOUR, ANCHOR + HOUR)


def expired_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR - 2 * HOUR, ANCHOR - HOUR)


def long_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR - HOUR, ANCHOR + 1000 * HOUR)


NowFn = Callable[[], datetime]
