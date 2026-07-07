"""Integration suite (TDD red) for the ported STATIC, WELL-KNOWN-KEY, and
WELL-KNOWN-ENDPOINT resolver faces — mirroring sdk/go/helpers
keyresolver_test.go + endpointresolver_test.go 1:1, plus the R2 skip-not-fail
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

from datetime import timedelta

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

# RED: ramp_sdk.resolvers does not exist yet (TDD red for bsh8k). The typed error
# classes and the fetching faces are the ported public surface.
from ramp_sdk.resolvers import (  # type: ignore[import-not-found]
    DirectoryUnavailableError,
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
    # R2: JWKS extraction is skip-not-fail — one malformed key must not kill the
    # whole publisher key set; survivors still resolve, bad entries become misses.
    good = make_key()
    non_ed = make_key()
    origin = Origin()
    origin.set_jwks(
        jwks_key_doc_json(
            [
                {"kty": "OKP", "crv": "Ed25519", "x": make_key().x},  # missing kid → skip
                {"kid": "rsa.v1", "kty": "RSA", "crv": "Ed25519", "x": non_ed.x},  # non-Ed25519 → skip
                {"kid": "short.v1", "kty": "OKP", "crv": "Ed25519", "x": "AAAA"},  # bad-length x → skip
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


def test_endpoint_per_host_isolation() -> None:
    ep_a = "https://exchange-a.example/ramp.v1.ExchangeService"
    ep_b = "https://exchange-b.example/ramp.v1.ExchangeService"
    a = Origin()
    b = Origin()
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
    ep = "https://exchange.example/ramp.v1.ExchangeService"
    origin = Origin()
    origin.set_manifest(manifest_json(ep))
    try:
        r = WellKnownEndpointResolver(ttl=HOUR, scheme="http")
        assert r.resolve_endpoint(origin.host) == ep
        assert r.resolve_endpoint(origin.host) == ep
        assert origin.manifest_hits() == 1
    finally:
        origin.close()


def test_endpoint_ttl_refresh() -> None:
    ep = "https://exchange.example/ramp.v1.ExchangeService"
    origin = Origin()
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
