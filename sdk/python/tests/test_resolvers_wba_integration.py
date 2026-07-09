"""Integration suite (TDD red) for the ported WBA key resolver — mirroring
sdk/go/helpers/wbakeyresolver_test.go 1:1 (all 14 tests) plus R3 (malformed
Signature-Agent → unknown). The WBA directory host that Go threads through ctx
(Signature-Agent) is passed EXPLICITLY as the second ``resolve`` argument in the
port: ``resolve(thumbprint, directory)``.

Every case drives a REAL http.server origin (the shared harness) through the
resolver's default stdlib-urllib transport; the clock and the poll-timer seam are
injected so no test sleeps. Per R5 the monotonic guard / as_of clamp /
forward-progress cases run via Resolve + TTL-expiry (NO poller), so a poller-only
guard would fail them — only the poller test exercises the background Run poller,
via the on_poll_armed/on_poll_cycle determinism seams.

RED CONTRACT: ``ramp_sdk.resolvers`` does not exist yet — the file is RED at
collection on the missing faces, not on a fixture error.
"""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from resolvers_harness import (
    ANCHOR,
    HOUR,
    DeterministicClock,
    MutableClock,
    Origin,
    PollSignals,
    active_jwk,
    expired_jwk,
    long_jwk,
    loopback_fetch,
    make_key,
    revocation_json,
    wba_file_json,
    wba_jwk,
)

# RED: the WBA face and its typed sentinels do not exist yet (TDD red for bsh8k).
from ramp_sdk.resolvers import (  # type: ignore[import-not-found]
    DirectoryUnavailableError,
    KeyExpiredError,
    KeyRevokedError,
    UnknownKeyError,
    WBAKeyResolver,
)


def test_wba_active() -> None:
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([active_jwk(k.x)]))
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        assert r.resolve(k.tp, origin.url) == k.raw_pub
    finally:
        origin.close()


def test_wba_key_expired() -> None:
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([expired_jwk(k.x)]))
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        with pytest.raises(KeyExpiredError):
            r.resolve(k.tp, origin.url)
    finally:
        origin.close()


def test_wba_unknown_key() -> None:
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([active_jwk(k.x)]))
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        with pytest.raises(UnknownKeyError):
            r.resolve("absent-thumbprint", origin.url)
    finally:
        origin.close()


def test_wba_key_revoked() -> None:
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([active_jwk(k.x)], origin.revocation_url()))
    origin.set_revocation(revocation_json(ANCHOR, [k.tp]))
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        with pytest.raises(KeyRevokedError):
            r.resolve(k.tp, origin.url)
    finally:
        origin.close()


def test_wba_rotation_self_heal() -> None:
    k1 = make_key()
    k2 = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([active_jwk(k1.x)]))  # prime: only k1
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", ttl=HOUR, now=MutableClock(ANCHOR))
        assert r.resolve(k1.tp, origin.url) == k1.raw_pub
        origin.set_wba(wba_file_json([active_jwk(k1.x), active_jwk(k2.x)]))  # rotate k2 in
        # Cache still holds k1-only, so the k2 lookup must trigger a self-heal
        # re-fetch even before the TTL expires.
        assert r.resolve(k2.tp, origin.url) == k2.raw_pub
    finally:
        origin.close()


def test_wba_revocation_rollback_ignored() -> None:
    # Monotonic guard: an older-as_of snapshot must NOT un-revoke. Runs via
    # Resolve + TTL-expiry (no poller) per R5.
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([long_jwk(k.x)], origin.revocation_url()))
    origin.set_revocation(revocation_json(ANCHOR, [k.tp]))
    try:
        clock = MutableClock(ANCHOR)
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", ttl=HOUR, now=clock)
        with pytest.raises(KeyRevokedError):
            r.resolve(k.tp, origin.url)
        # Publish a rolled-back (older as_of) snapshot that drops the revocation.
        origin.set_revocation(revocation_json(ANCHOR - HOUR, []))
        clock.t = ANCHOR + 2 * HOUR  # expire TTL → re-fetch + revocation refresh
        with pytest.raises(KeyRevokedError):
            r.resolve(k.tp, origin.url)
    finally:
        origin.close()


def test_wba_revocation_forward_progress_applied() -> None:
    # Forward progress: a strictly-newer empty snapshot DOES un-revoke.
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([long_jwk(k.x)], origin.revocation_url()))
    origin.set_revocation(revocation_json(ANCHOR, [k.tp]))
    try:
        clock = MutableClock(ANCHOR)
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", ttl=HOUR, now=clock)
        with pytest.raises(KeyRevokedError):
            r.resolve(k.tp, origin.url)
        origin.set_revocation(revocation_json(ANCHOR + HOUR, []))
        clock.t = ANCHOR + 2 * HOUR  # expire TTL
        assert r.resolve(k.tp, origin.url) == k.raw_pub
    finally:
        origin.close()


def test_wba_first_poll_far_future_as_of_clamp() -> None:
    # A far-future first as_of is clamped to now+skew so a later honest snapshot
    # still applies (first-poll integrity).
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([long_jwk(k.x)], origin.revocation_url()))
    origin.set_revocation(revocation_json(ANCHOR + 10000 * HOUR, []))
    try:
        clock = MutableClock(ANCHOR)
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", ttl=HOUR, now=clock)
        assert r.resolve(k.tp, origin.url) == k.raw_pub  # prime
        clock.t = ANCHOR + 2 * HOUR
        origin.set_revocation(revocation_json(ANCHOR + 2 * HOUR, [k.tp]))
        with pytest.raises(KeyRevokedError):
            r.resolve(k.tp, origin.url)
    finally:
        origin.close()


def test_wba_removal_is_not_revocation() -> None:
    # A key dropped from the directory is unknown, NOT revoked.
    k1 = make_key()
    k2 = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([long_jwk(k1.x)]))
    try:
        clock = MutableClock(ANCHOR)
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", ttl=HOUR, now=clock)
        assert r.resolve(k1.tp, origin.url) == k1.raw_pub
        origin.set_wba(wba_file_json([long_jwk(k2.x)]))  # drop k1
        clock.t = ANCHOR + 2 * HOUR  # expire TTL → re-fetch k1-less directory
        # Removal is a fall-through UnknownKeyError, never a KeyRevokedError.
        with pytest.raises(UnknownKeyError):
            r.resolve(k1.tp, origin.url)
    finally:
        origin.close()


def test_wba_revocation_url_host_not_anchored() -> None:
    # A cross-host revocation_url is skipped; the key stays valid.
    k = make_key()
    evil = Origin()  # would revoke the key if polled
    evil.set_revocation(revocation_json(ANCHOR, [k.tp]))
    origin = Origin()
    origin.set_wba(wba_file_json([active_jwk(k.x)], evil.revocation_url()))  # cross-host
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        # Not anchored → not polled → key resolves.
        assert r.resolve(k.tp, origin.url) == k.raw_pub
    finally:
        origin.close()
        evil.close()


def test_wba_no_signature_agent() -> None:
    # An empty directory (no Signature-Agent) → UnknownKeyError.
    r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
    with pytest.raises(UnknownKeyError):
        r.resolve("any-thumbprint", "")


def test_wba_malformed_signature_agent() -> None:
    # R3: a malformed (non-empty, unparseable) directory ref → UnknownKeyError
    # (fall-through), DISTINCT from a fetch failure. Malformed cannot name a
    # directory, so it is not a fail-closed halt.
    r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
    with pytest.raises(UnknownKeyError):
        r.resolve("any-thumbprint", "http://")


def test_wba_ttl_cache_hit() -> None:
    # A cache hit resolves within TTL even after the origin starts 500ing.
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([wba_jwk(k.x, ANCHOR - HOUR, ANCHOR + 10 * HOUR)]))
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", ttl=HOUR, now=MutableClock(ANCHOR))
        assert r.resolve(k.tp, origin.url) == k.raw_pub
        origin.set_wba_status(500)  # origin now fails; cached hit must still succeed
        assert r.resolve(k.tp, origin.url) == k.raw_pub
    finally:
        origin.close()


def test_wba_fetch_error_directory_unavailable_distinct_from_unknown() -> None:
    # A fetch/500 failure raises DirectoryUnavailableError, which MUST be a
    # distinct class from UnknownKeyError so a composite fails closed rather than
    # falling through.
    origin = Origin()
    origin.set_wba_status(500)
    try:
        r = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        with pytest.raises(DirectoryUnavailableError) as exc:
            r.resolve("any-thumbprint", origin.url)
        assert not isinstance(exc.value, UnknownKeyError)
    finally:
        origin.close()


def test_wba_run_poller_applies_revocation() -> None:
    # The background Run poller applies a newly-published revocation without a
    # directory re-fetch, driven by the deterministic clock + armed/cycle seams
    # (no sleeps).
    k = make_key()
    origin = Origin()
    origin.set_wba(wba_file_json([long_jwk(k.x)], origin.revocation_url()))
    origin.set_revocation(revocation_json(ANCHOR - HOUR, []))  # nothing revoked yet

    poll_interval = timedelta(seconds=10)
    clk = DeterministicClock(_now=ANCHOR)
    signals = PollSignals()
    stop = threading.Event()

    r = WBAKeyResolver(
        http=loopback_fetch,
        scheme="http",
        ttl=100 * HOUR,  # never expires during the test → isolate the poller
        poll_interval=poll_interval,
        now=clk.now,
        after=clk.after,
        on_poll_armed=signals.on_armed,
        on_poll_cycle=signals.on_cycled,
    )
    thread = threading.Thread(target=r.run, args=(stop,), daemon=True)
    thread.start()
    try:
        # Prime the directory + empty revocation snapshot.
        assert r.resolve(k.tp, origin.url) == k.raw_pub

        # Publish a newer snapshot revoking the key, then cross one poll boundary.
        origin.set_revocation(revocation_json(ANCHOR, [k.tp]))
        signals.cross_one(clk, 2 * poll_interval)

        with pytest.raises(KeyRevokedError):
            r.resolve(k.tp, origin.url)
    finally:
        stop.set()
        origin.close()
