"""Cached, domain-keyed offer-signing-key resolver (DRY-01).

Home of the per-domain TTL cache → WBA-directory fetch → active-key-with-expiry
selection → not_after clamp that the Broker (``offerkeys.Resolver``) and the MCP
shim (``ExchangeOfferKeyCache``) each re-implemented. Consolidating them here means
the clamp — the off-by-one-prone ``min(now + ttl, not_after)`` — lives and is fixed
once.

Selection is REVOCATION-AWARE (:func:`active_ed25519_key_with_expiry_screened`): a
window-active-but-revoked key still listed in a CDN-cached directory is skipped, so
the cache is safe to feed a verification path.

The async prefetch face mirrors ``ExchangeOfferKeyCache``: because
:class:`ramp_sdk.core.Verifier` resolves keys synchronously, the caller prefetches
the keys for the exchanges present in a response, then seeds a
:class:`~ramp_sdk.core.StaticOfferKeyResolver` for the sort. The WBA-directory fetch
is an INJECTED seam (``fetch``) — the app supplies its SSRF-guarded client + URL
builder, a test supplies a directory table with no network — so this type owns only
the cache, selection, and clamp.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime

from wire.models import WBAFile

from ramp_sdk.resolvers.wba import active_ed25519_key_with_expiry_screened

_DEFAULT_TTL_SECONDS = 300

# DirectoryFetch resolves one exchange domain to its WBA directory, or None when the
# directory is unresolvable (unreachable, malformed, blocked). The fetcher MUST
# contain its own failures as None rather than raise, so one bad exchange never
# crashes the prefetch batch — the same fail-closed shape the app fetchers already use.
DirectoryFetch = Callable[[str], Awaitable[WBAFile | None]]


def _default_now() -> datetime:
    return datetime.now(UTC)


def _never_revoked(_thumbprint: str) -> bool:
    return False


class CachedOfferKeyResolver:
    """domain → exchange offer-signing key, via an injected WBA-directory fetch,
    TTL-cached with a not_after clamp and revocation-aware selection."""

    def __init__(
        self,
        *,
        fetch: DirectoryFetch,
        now: Callable[[], datetime] | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        revoked: Callable[[str], bool] | None = None,
    ) -> None:
        """Wire the resolver.

        ``fetch`` resolves a domain to its WBA directory (required). ``now`` is the
        cache-freshness + selection clock (default :func:`datetime.now(UTC)`).
        ``ttl_seconds`` bounds the per-domain cache. ``revoked`` screens a candidate
        key by its RFC 7638 thumbprint — a revoked key is skipped during selection so
        a window-active-but-revoked key is never served; default screens nothing, so
        a verification-path caller SHOULD inject :meth:`WBAKeyResolver.revoked` (or an
        equivalent revoked-set predicate).
        """
        self._fetch = fetch
        self._now = now if now is not None else _default_now
        self._ttl = ttl_seconds
        self._revoked: Callable[[str], bool] = revoked if revoked is not None else _never_revoked
        self._cache: dict[str, tuple[bytes, float]] = {}

    async def prefetch(self, exchanges: Iterable[str]) -> dict[str, bytes]:
        """Return ``{exchange: raw 32-byte key}`` for every resolvable exchange.

        A cache hit within the (clamped) TTL short-circuits; misses are fetched
        concurrently, their active non-revoked key selected, and cached with an expiry
        clamped to ``min(now + ttl, not_after)``. An unresolvable exchange (fetch
        returned None, no active/non-revoked key) is simply absent from the map — the
        Verifier then rejects its offers fail-closed.
        """
        now_dt = self._now()
        now = now_dt.timestamp()
        wanted = {e for e in exchanges if e}
        out: dict[str, bytes] = {}
        misses: list[str] = []
        for ex in wanted:
            hit = self._cache.get(ex)
            if hit is not None and now < hit[1]:
                out[ex] = hit[0]
            else:
                misses.append(ex)
        if not misses:
            return out
        results = await asyncio.gather(*(self._fetch(ex) for ex in misses))
        for ex, wba in zip(misses, results, strict=True):
            if wba is None:
                continue
            selected = active_ed25519_key_with_expiry_screened(wba, now_dt, self._revoked)
            if selected is None:
                continue
            key, not_after = selected
            # Clamp the cache entry to the key's validity window: never serve a key
            # past its not_after, even within the TTL (mirrors the Go resolver's
            # exp = min(now+ttl, not_after)). The read check above then evicts the key
            # at not_after and a refetch fails closed once the key is inactive.
            expiry = min(now + self._ttl, not_after.timestamp())
            self._cache[ex] = (key, expiry)
            out[ex] = key
        return out
