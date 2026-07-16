"""Behavior suite for :class:`CachedOfferKeyResolver` — the domain-keyed
offer-signing-key cache that consolidates the Broker's ``offerkeys.Resolver`` and
the MCP shim's ``ExchangeOfferKeyCache``: per-domain TTL cache → WBA-directory fetch
(injected seam) → revocation-aware active-key selection → not_after clamp.

The WBA fetch is injected as a fake per-domain table (no HTTP), the clock is the
shared ``MutableClock``, and revocation is an injected thumbprint predicate — so the
cache, clamp, and screening are exercised deterministically without a network.
"""

from __future__ import annotations

import asyncio
from typing import Any

from resolvers_harness import ANCHOR, HOUR, MutableClock, active_jwk, expired_jwk, make_key
from wire.models import WBAFile

from ramp_sdk.resolvers import CachedOfferKeyResolver


def _directory(keys: list[dict[str, Any]]) -> WBAFile:
    return WBAFile.model_validate({"keys": keys})


class _CountingFetch:
    """An injected directory fetcher over a fixed per-domain table; counts calls."""

    def __init__(self, table: dict[str, WBAFile]) -> None:
        self._table = table
        self.calls = 0

    async def __call__(self, domain: str) -> WBAFile | None:
        self.calls += 1
        return self._table.get(domain)


def test_caches_within_ttl() -> None:
    key = make_key()
    fetch = _CountingFetch({"ex": _directory([active_jwk(key.x)])})
    clock = MutableClock(ANCHOR)
    cache = CachedOfferKeyResolver(fetch=fetch, now=clock, ttl_seconds=60)

    first = asyncio.run(cache.prefetch(["ex"]))
    assert first == {"ex": key.raw_pub}
    # A second prefetch at the same instant is a cache hit — no second fetch.
    second = asyncio.run(cache.prefetch(["ex"]))
    assert second == {"ex": key.raw_pub}
    assert fetch.calls == 1


def test_refetches_after_ttl() -> None:
    key = make_key()
    fetch = _CountingFetch({"ex": _directory([active_jwk(key.x)])})
    clock = MutableClock(ANCHOR)
    cache = CachedOfferKeyResolver(fetch=fetch, now=clock, ttl_seconds=60)

    asyncio.run(cache.prefetch(["ex"]))
    # Advance past the TTL (still inside the key window): the entry is stale → refetch.
    clock.t = ANCHOR + 2 * HOUR / 60  # +2 minutes
    asyncio.run(cache.prefetch(["ex"]))
    assert fetch.calls == 2


def test_clamps_expiry_to_not_after() -> None:
    # The TTL is far longer than the key's remaining window, so the entry must expire
    # at not_after (ANCHOR+1h), NOT at now+TTL — otherwise a key would keep verifying
    # up to a full TTL past its validity window.
    key = make_key()
    fetch = _CountingFetch({"ex": _directory([active_jwk(key.x)])})  # not_after = ANCHOR+1h
    clock = MutableClock(ANCHOR)
    cache = CachedOfferKeyResolver(fetch=fetch, now=clock, ttl_seconds=1_000_000)

    assert asyncio.run(cache.prefetch(["ex"])) == {"ex": key.raw_pub}
    # Just before not_after: still a cache hit.
    clock.t = ANCHOR + HOUR - HOUR / 60
    asyncio.run(cache.prefetch(["ex"]))
    assert fetch.calls == 1
    # At not_after the clamped entry expires → refetch; the key is now outside its
    # window, so it is absent from the result (fail-closed), proving the clamp evicted
    # at not_after rather than at the far-future now+TTL.
    clock.t = ANCHOR + HOUR
    assert asyncio.run(cache.prefetch(["ex"])) == {}
    assert fetch.calls == 2


def test_skips_revoked_key() -> None:
    # The first window-active key is revoked; the cache must serve the next active,
    # non-revoked key — it is on a verification path, so it MUST screen revocation.
    revoked_key = make_key()
    live_key = make_key()
    directory = _directory([active_jwk(revoked_key.x), active_jwk(live_key.x)])
    fetch = _CountingFetch({"ex": directory})
    cache = CachedOfferKeyResolver(
        fetch=fetch,
        now=MutableClock(ANCHOR),
        revoked=lambda tp: tp == revoked_key.tp,
    )
    assert asyncio.run(cache.prefetch(["ex"])) == {"ex": live_key.raw_pub}


def test_absent_when_no_active_key() -> None:
    # An all-retired directory yields no active key: the exchange is simply absent
    # (the Verifier then rejects its offers fail-closed).
    key = make_key()
    fetch = _CountingFetch({"ex": _directory([expired_jwk(key.x)])})
    cache = CachedOfferKeyResolver(fetch=fetch, now=MutableClock(ANCHOR))
    assert asyncio.run(cache.prefetch(["ex"])) == {}


def test_absent_when_fetch_unresolvable() -> None:
    # A fetch that returns None (unreachable/malformed/blocked) leaves the exchange
    # absent rather than crashing the batch.
    fetch = _CountingFetch({})  # "ex" not in the table → None
    cache = CachedOfferKeyResolver(fetch=fetch, now=MutableClock(ANCHOR))
    assert asyncio.run(cache.prefetch(["ex"])) == {}
    assert fetch.calls == 1
