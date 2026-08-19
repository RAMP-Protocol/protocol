"""The two well-known fetching faces.

``WellKnownKeyResolver`` reads one fixed JWKS URL, keyed by kid; the JWKS doc is
the ad-hoc kid-carrying ``{"keys":[{"kid","kty":"OKP","crv":"Ed25519","x"}]}``
shape (NOT the gen ``JsonWebKey``/``WellKnownManifest`` schemas, which carry no
kid and no JWK-set — decoding through them would resolve ZERO keys). Extraction
is SKIP-NOT-FAIL: a key with an empty kid, a non-OKP/Ed25519 type, or a
wrong-length ``x`` is skipped and one bad key never fails the whole set.

``WellKnownEndpointResolver`` is host-keyed: it fetches
``{scheme}://{host}/.well-known/ramp.json`` and reads the ``endpoint`` field
(ignoring unknown fields). Both port the Go oracle's lazy-fetch + TTL cache +
single-flight coalescing and its fail-closed taxonomy.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from ramp_sdk._hostref import _parse_ref, anchored_parsed
from ramp_sdk.b64 import b64url_decode_strict
from ramp_sdk.hosts import is_bare_host
from ramp_sdk.resolvers._http import default_client, fetch_strict
from ramp_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    EndpointRefusedError,
    NoEndpointError,
)

if TYPE_CHECKING:
    import httpx

_ED25519_PUBLIC_KEY_BYTES = 32
_DEFAULT_TTL = timedelta(minutes=5)


def _endpoint_refusal(host: str, endpoint: str) -> str | None:
    """Why an endpoint a manifest advertises may not be handed back, or None when
    it may.

    The manifest that named this endpoint is served by the very host the call is
    bound for, so the endpoint is only as trustworthy as that host. An Exchange may
    advertise itself or a subdomain of itself, on the same port, and nothing else —
    a dial-time address guard has no objection to an unrelated PUBLIC host, so
    nothing below this catches one.

    Userinfo is refused for a different reason with the same shape: the host
    comparison reads the authority's host and ignores any ``user:password`` before
    it, so an endpoint carrying credentials would pass the host check and then have
    the HTTP client stamp an Authorization header the SDK never chose, on a leg that
    already carries the caller's own signature.

    It runs HERE, in the resolver, rather than in each caller: the check is a
    property of reading an endpoint out of a manifest, not of any one caller's plans
    for it. (The Go oracle keeps the same rule in a shared internal package because
    it has a second call site — a typed client that re-checks an injected resolver's
    answer. This SDK has only the one, so the rule lives with it.)

    Both halves are decided over ONE reading of the reference, by the shared parse
    in :mod:`ramp_sdk._hostref`. That is not tidiness: a value naming no scheme is a
    URL to one parser and a path to another, and the two answers put a credential on
    opposite sides of the check — ``u:p@exchange.example`` is where they part.
    """
    try:
        advertised = _parse_ref(endpoint)
    except ValueError as exc:
        return f"host={host!r} endpoint={endpoint!r}: {exc}"
    if advertised.has_userinfo:
        # Deliberately does not echo the endpoint: it carries the credential.
        return f"host={host!r} advertises an endpoint carrying userinfo"
    try:
        served = _parse_ref(host)
    except ValueError as exc:
        return f"host={host!r}: {exc}"
    if not anchored_parsed(served, advertised):
        return f"host={host!r} advertises endpoint {endpoint!r} on a different host"
    return None


NowFn = Callable[[], datetime]
AllowFn = Callable[[str], bool]


def _now_utc() -> datetime:
    return datetime.now(UTC)


def ed25519_keys_from_jwks(doc: object) -> dict[str, bytes]:
    """Extract the Ed25519 public keys (keyed by kid) from a parsed JWKS doc."""
    out: dict[str, bytes] = {}
    if not isinstance(doc, dict):
        return out
    keys = doc.get("keys")
    if not isinstance(keys, list):
        return out
    for entry in keys:
        extracted = _extract_ed25519(entry)
        if extracted is not None:
            out[extracted[0]] = extracted[1]
    return out


def _extract_ed25519(entry: object) -> tuple[str, bytes] | None:
    if not isinstance(entry, dict):
        return None
    kid = entry.get("kid")
    x = entry.get("x")
    if not isinstance(kid, str) or kid == "" or not isinstance(x, str):
        return None
    if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
        return None
    try:
        # JWK OKP `x` is UNPADDED base64url (RFC 8037); reject padding / the
        # standard alphabet to match Go's go-jose JWKS parse (RawURLEncoding).
        raw = b64url_decode_strict(x)
    except ValueError:
        return None
    if len(raw) != _ED25519_PUBLIC_KEY_BYTES:
        return None
    return kid, raw


class WellKnownKeyResolver:
    """Lazily fetch the JWKS at ``url`` and cache resolved keys with a TTL."""

    def __init__(
        self,
        url: str,
        *,
        ttl: timedelta = _DEFAULT_TTL,
        now: NowFn = _now_utc,
        http: httpx.Client | None = None,
        allow: AllowFn | None = None,
    ) -> None:
        self._url = url
        self._ttl = ttl if ttl > timedelta(0) else _DEFAULT_TTL
        self._now = now
        self._http = http if http is not None else default_client()
        self._allow = allow
        self._lock = threading.Lock()
        self._cache: dict[str, bytes] = {}
        self._cache_exp: datetime | None = None

    def resolve(self, keyid: str) -> bytes | None:
        """Return the public key for ``keyid``, or None (unknown key miss).

        Raises DirectoryUnavailableError on a fetch/decode failure — a fail-closed
        halt DISTINCT from the None miss a composite treats as "fall through".
        """
        if self._allow is not None and not self._allow(keyid):
            return None
        hit = self._cached(keyid)
        if hit is not None:
            return hit
        self._refresh()
        return self._cached(keyid)

    def _cached(self, keyid: str) -> bytes | None:
        exp = self._cache_exp
        if exp is None or self._now() > exp:
            return None
        return self._cache.get(keyid)

    def _refresh(self) -> None:
        with self._lock:
            exp = self._cache_exp
            if exp is not None and self._now() <= exp:
                return  # another thread refreshed while we waited on the lock
            body = fetch_strict(self._http, self._url)
            try:
                parsed = json.loads(body)
            except ValueError as exc:
                raise DirectoryUnavailableError(f"jwks decode {self._url}") from exc
            self._cache = ed25519_keys_from_jwks(parsed)
            self._cache_exp = self._now() + self._ttl


class WellKnownEndpointResolver:
    """Host-keyed resolver of an Exchange domain to its self-advertised endpoint."""

    def __init__(
        self,
        *,
        ttl: timedelta = _DEFAULT_TTL,
        scheme: str = "https",
        now: NowFn = _now_utc,
        http: httpx.Client | None = None,
        allow: AllowFn | None = None,
    ) -> None:
        self._ttl = ttl if ttl > timedelta(0) else _DEFAULT_TTL
        self._scheme = scheme or "https"
        self._now = now
        self._http = http if http is not None else default_client()
        self._allow = allow
        self._cache_lock = threading.Lock()
        self._cache: dict[str, tuple[str, datetime]] = {}
        self._flight_lock = threading.Lock()
        self._flights: dict[str, threading.Lock] = {}

    def resolve_endpoint(self, host: str) -> str:
        """Return the endpoint ``host`` advertises in its well-known manifest.

        Raises NoEndpointError (manifest reachable but inert) or
        DirectoryUnavailableError (unreachable/undecodable) — distinct verdicts.
        """
        # Checked BEFORE the allow overlay and before the cache. The fetch URL is
        # built by concatenation, so a value carrying a path or a query would
        # choose WHAT gets fetched rather than merely where from — and the raw
        # string is the cache key, so admitting one would also put it in a shared
        # map.
        #
        # A fault in the CALLER's value, not a verdict on the Exchange's answer, so
        # it is the same ValueError is_bare_host itself raises for a reference it
        # cannot read at all — the oracle uses one sentinel across both branches
        # here for the same reason. EndpointRefusedError stays what it says: the
        # manifest was read and its answer is unusable.
        if not is_bare_host(host):
            msg = f"hosts: reference is not a usable host: not a bare host: {host!r}"
            raise ValueError(msg)
        if self._allow is not None and not self._allow(host):
            raise NoEndpointError(f"host {host} not allowed")
        cached = self._cached(host)
        if cached is not None:
            return cached
        with self._host_flight(host):
            cached = self._cached(host)
            if cached is not None:
                return cached  # another thread fetched while we waited
            return self._fetch_endpoint(host)

    def _fetch_endpoint(self, host: str) -> str:
        url = f"{self._scheme}://{host}/.well-known/ramp.json"
        body = fetch_strict(self._http, url)
        try:
            doc = json.loads(body)
        except ValueError as exc:
            raise DirectoryUnavailableError(f"manifest decode {url}") from exc
        endpoint = doc.get("endpoint") if isinstance(doc, dict) else None
        if not isinstance(endpoint, str) or endpoint == "":
            raise NoEndpointError(f"host={host}")
        # Vetted BEFORE it is cached, so a refused endpoint is not held for the TTL
        # and then served to every later caller out of memory.
        refusal = _endpoint_refusal(host, endpoint)
        if refusal is not None:
            raise EndpointRefusedError(refusal)
        self._store(host, endpoint)
        return endpoint

    def _cached(self, host: str) -> str | None:
        with self._cache_lock:
            entry = self._cache.get(host)
            if entry is None or self._now() > entry[1]:
                return None
            return entry[0]

    def _store(self, host: str, endpoint: str) -> None:
        with self._cache_lock:
            self._cache[host] = (endpoint, self._now() + self._ttl)

    def _host_flight(self, host: str) -> threading.Lock:
        with self._flight_lock:
            flight = self._flights.get(host)
            if flight is None:
                flight = threading.Lock()
                self._flights[host] = flight
            return flight
