"""The WBA identity-directory key resolver + revocation poller.

Ports sdk/go/helpers/wbakeyresolver.go 1:1: resolve a thumbprint (the RFC 9421
keyid, NEVER a kid) against a WBA directory, enforcing the key's [not_before,
not_after) window and the host's revocation snapshot. The directory host that Go
threads through ctx (Signature-Agent) is passed EXPLICITLY as the second
``resolve`` argument. The gen Pydantic schemas decode the WBA docs
(thumbprint-keyed, need no kid); thumbprint reuses the byte-parity-pinned
primitive.

The monotonic revocation guard + far-future as_of clamp + revocation priming
live in the SHARED refresh routine (``_refresh_revocation_for``), invoked by BOTH
the sync directory-fetch path AND the Run poller — never poller-only.
"""

from __future__ import annotations

import queue
import random
import threading
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from pydantic import ValidationError
from wire.models import JsonWebKey, KeyRevocationList, WBAFile

if TYPE_CHECKING:
    import httpx

from ramp_sdk.b64 import b64url_decode
from ramp_sdk.resolvers._http import fetch_soft, fetch_strict, guarded_client
from ramp_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    KeyExpiredError,
    KeyRevokedError,
    RevocationUnevaluatedError,
    UnknownKeyError,
)
from ramp_sdk.thumbprint import thumbprint

_WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
_DEFAULT_TTL = timedelta(hours=1)
_DEFAULT_POLL_INTERVAL = timedelta(seconds=300)
# Throttle for the unknown-thumbprint force-refresh, per directory host. The
# resolver runs BEFORE the ed25519 check and the fetch host is the caller-supplied
# Signature-Agent, so this caps the outbound directory GETs an unauthenticated
# caller can drive by presenting unknown thumbprints (reflection/amplification +
# self-DoS). The SSRF guard blocks private TARGETS, not the fetch RATE.
_DEFAULT_SYNC_DEBOUNCE = timedelta(seconds=5)
# Bounds how far into the future a revocation snapshot's as_of may sit before it
# is clamped, so a compromised origin cannot stamp a far-future baseline that
# permanently freezes later (legitimately earlier) snapshots under the guard.
_AS_OF_SKEW = timedelta(seconds=300)
_ED25519_PUBLIC_KEY_BYTES = 32
# Document-order scan cap for active_ed25519_key: a WBA directory padded with junk
# entries beyond this many keys cannot force unbounded selection work (a DoS cap);
# a valid key listed past the first _DEFAULT_ACTIVE_KEY_SCAN positions is unreachable.
_DEFAULT_ACTIVE_KEY_SCAN = 10

NowFn = Callable[[], datetime]
AfterFn = Callable[[timedelta], "queue.Queue[datetime]"]
Hook = Callable[[], None]


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _default_after(delay: timedelta) -> queue.Queue[datetime]:
    q: queue.Queue[datetime] = queue.Queue(maxsize=1)
    timer = threading.Timer(delay.total_seconds(), lambda: q.put(_now_utc()))
    timer.daemon = True
    timer.start()
    return q


@dataclass
class _DirEntry:
    file: WBAFile
    exp: datetime


@dataclass
class _RevSet:
    thumbprints: set[str]
    as_of: datetime


@dataclass
class _Inflight:
    """A single in-flight directory fetch for one host. Concurrent callers share
    it (singleflight): the leader fetches and publishes ``file`` xor ``error``,
    then sets ``event``; followers wait on ``event`` and read the shared result."""

    event: threading.Event
    file: WBAFile | None = None
    error: Exception | None = None


class WBAKeyResolver:
    """Resolve signing keys from WBA identity directories, matching by RFC 7638
    thumbprint and enforcing validity windows + the host's revocation snapshot."""

    def __init__(
        self,
        *,
        scheme: str = "https",
        ttl: timedelta = _DEFAULT_TTL,
        poll_interval: timedelta = _DEFAULT_POLL_INTERVAL,
        sync_debounce: timedelta = _DEFAULT_SYNC_DEBOUNCE,
        now: NowFn = _now_utc,
        after: AfterFn = _default_after,
        require_revocation: bool = False,
        on_poll_armed: Hook | None = None,
        on_poll_cycle: Hook | None = None,
        # Safe by default: an SSRF-guarded httpx.Client. The directory host is
        # derived from the caller-supplied Signature-Agent and fetched BEFORE the
        # ed25519 check, so an unguarded default would be a pre-auth SSRF lever.
        # ``guarded_client()`` resolves + pins to a checked IP (closing the
        # DNS-rebinding window) and refuses reserved / non-public targets. A
        # deployment that must reach a private directory (tests, on-prem) injects
        # its own httpx.Client here — the escape hatch, mirroring the Go client
        # injection.
        http: httpx.Client | None = None,
    ) -> None:
        self._scheme = scheme or "https"
        self._ttl = ttl if ttl > timedelta(0) else _DEFAULT_TTL
        self._poll_interval = (
            poll_interval if poll_interval > timedelta(0) else _DEFAULT_POLL_INTERVAL
        )
        self._sync_debounce = (
            sync_debounce if sync_debounce > timedelta(0) else _DEFAULT_SYNC_DEBOUNCE
        )
        self._now = now
        self._after = after
        # When set, Resolve fails closed with RevocationUnevaluatedError when a
        # key's directory declares a revocation_url but no snapshot has been
        # fetched (unreachable or not host-anchored) — i.e. revocation could not
        # be evaluated. Default keeps the best-effort behavior.
        self._require_revocation = require_revocation
        self._on_poll_armed = on_poll_armed
        self._on_poll_cycle = on_poll_cycle
        self._http = http if http is not None else guarded_client()
        self._dir_lock = threading.Lock()
        self._dir_cache: dict[str, _DirEntry] = {}
        self._rev_lock = threading.Lock()
        self._revoked: dict[str, _RevSet] = {}
        # _last_sync throttles the unknown-thumbprint force-refresh to one per
        # window per host (anti-amplification); _inflight coalesces a concurrent
        # burst of directory fetches for one host to a single GET (singleflight).
        self._sync_lock = threading.Lock()
        self._last_sync: dict[str, datetime] = {}
        self._inflight_lock = threading.Lock()
        self._inflight: dict[str, _Inflight] = {}

    def resolve(self, keyid: str, directory: str) -> bytes:
        """Resolve ``keyid`` (a thumbprint) against ``directory``.

        Returns the raw Ed25519 public key. Raises UnknownKeyError for an
        unknown/absent/malformed reference (fall-through), and the distinct
        KeyRevokedError / KeyExpiredError / DirectoryUnavailableError for the
        fail-closed verdicts. Under require_revocation, also raises
        RevocationUnevaluatedError when the directory declares a revocation_url
        but no snapshot has landed (revocation could not be evaluated) — DISTINCT
        from KeyRevokedError ("evaluated and revoked").
        """
        if directory == "" or keyid == "":
            raise UnknownKeyError(f"no signature-agent directory for keyid={keyid!r}")
        parsed = _directory_base(directory, self._scheme)
        if parsed is None:
            # A malformed Signature-Agent cannot name a directory: fall-through,
            # NOT a fail-closed DirectoryUnavailableError halt.
            raise UnknownKeyError(f"unparseable signature-agent {directory!r}")
        base, host = parsed
        file = self._wba_file(base, host)
        key = _key_by_thumbprint(file, keyid)
        if key is None:
            # The self-heal force-refresh bypasses the TTL cache — the lever an
            # unauthenticated caller pulls once per unknown thumbprint. Gate it to
            # one fetch per debounce window per host: outside the window the
            # thumbprint is reported unknown WITHOUT a fetch (rotation self-heal
            # still works — the first unknown lookup in each window refetches).
            if not self._begin_sync(host):
                raise UnknownKeyError(f"keyid={keyid!r} host={host!r} (refresh debounced)")
            file = self._sync_refresh(base, host)
            key = _key_by_thumbprint(file, keyid)
            if key is None:
                # Removal is fall-through (unknown), never revocation.
                raise UnknownKeyError(f"keyid={keyid!r} host={host!r}")
        if self._is_revoked(host, keyid):
            raise KeyRevokedError(f"keyid={keyid!r}")
        # Fail-closed on unevaluated revocation: the directory advertises a
        # revocation channel but we hold no snapshot for it, so we cannot assert
        # the key is un-revoked. Only enforced under require_revocation.
        if (
            self._require_revocation
            and file.revocation_url
            and not self._revocation_snapshot_present(host)
        ):
            raise RevocationUnevaluatedError(f"keyid={keyid!r} host={host!r}")
        if not _key_active_at(key, self._now()):
            raise KeyExpiredError(f"keyid={keyid!r}")
        return _public_key_of(key)

    def run(self, stop: threading.Event) -> None:
        """Drive the revocation poller until ``stop`` is set. Each tick refreshes
        every known host's revocation snapshot on a jittered interval."""
        while not stop.is_set():
            timer = self._after(self._jittered_interval())
            _notify(self._on_poll_armed)
            if not _wait_timer(timer, stop):
                return
            self._refresh_all_revocations()
            _notify(self._on_poll_cycle)

    def _wba_file(self, base: str, host: str) -> WBAFile:
        with self._dir_lock:
            entry = self._dir_cache.get(host)
            if entry is not None and self._now() < entry.exp:
                return entry.file
        return self._sync_refresh(base, host)

    def _begin_sync(self, host: str) -> bool:
        """Whether an unknown-thumbprint force-refresh for ``host`` may proceed
        now, recording the attempt when it does — at most one per debounce window
        per host, so N unknown thumbprints for one host drive ONE fetch, not N."""
        now = self._now()
        with self._sync_lock:
            last = self._last_sync.get(host)
            if last is not None and now - last < self._sync_debounce:
                return False
            self._last_sync[host] = now
            return True

    def _sync_refresh(self, base: str, host: str) -> WBAFile:
        """Force-fetch ``host``'s directory, bypassing the TTL cache. A concurrent
        burst for the same host coalesces to ONE in-flight GET: the first caller
        leads the fetch, peers wait on its shared result (singleflight)."""
        with self._inflight_lock:
            pending = self._inflight.get(host)
            if pending is not None:
                leader = False
            else:
                pending = _Inflight(event=threading.Event())
                self._inflight[host] = pending
                leader = True
        if not leader:
            return _await_inflight(pending)
        return self._lead_refresh(base, host, pending)

    def _lead_refresh(self, base: str, host: str, pending: _Inflight) -> WBAFile:
        try:
            file = self._fetch_directory(base)
            with self._dir_lock:
                self._dir_cache[host] = _DirEntry(file=file, exp=self._now() + self._ttl)
            self._refresh_revocation_for(host, file)
            pending.file = file
            return file
        except Exception as exc:  # published to waiters, then re-raised
            pending.error = exc
            raise
        finally:
            with self._inflight_lock:
                self._inflight.pop(host, None)
            pending.event.set()

    def _fetch_directory(self, base: str) -> WBAFile:
        body = fetch_strict(self._http, base + _WBA_DIRECTORY_PATH)
        try:
            return WBAFile.model_validate_json(body)
        except ValidationError as exc:
            raise DirectoryUnavailableError("wba directory decode") from exc

    def _is_revoked(self, host: str, thumbprint_key: str) -> bool:
        with self._rev_lock:
            rev = self._revoked.get(host)
            return rev is not None and thumbprint_key in rev.thumbprints

    def _revocation_snapshot_present(self, host: str) -> bool:
        """Whether a revocation snapshot has EVER been fetched for ``host``.

        DISTINCT from "the snapshot is empty": an empty snapshot means revocation
        WAS evaluated and nothing is revoked, whereas an absent snapshot means
        revocation was never evaluated (revocation_url unreachable / not
        host-anchored / not yet polled)."""
        with self._rev_lock:
            return host in self._revoked

    def revoked(self, key_id: str) -> bool:
        """Whether ``key_id`` (a thumbprint) is in ANY host's fetched revocation
        snapshot, INDEPENDENT of WBA directory membership.

        ``resolve`` gates a key only when the directory lists it (removal is not
        revocation), so a key resolved from another source — e.g. a static
        bootstrap file — is invisible to that path; ``revoked`` is the fail-closed
        hook a composite consults to reject a broker-revoked, directory-absent
        thumbprint. Returns False when no snapshot has been fetched.
        """
        if key_id == "":
            return False
        with self._rev_lock:
            return any(key_id in rev.thumbprints for rev in self._revoked.values())

    def _refresh_revocation_for(self, host: str, file: WBAFile) -> None:
        rev_url = file.revocation_url
        # Anchor the revocation_url to the directory host (SSRF guard): a
        # cross-host revocation_url is skipped, leaving the prior snapshot.
        if not rev_url or not _host_anchored(host, rev_url):
            return
        body = fetch_soft(self._http, rev_url)  # best-effort: a blip keeps prior
        if body is None:
            return
        try:
            snapshot = KeyRevocationList.model_validate_json(body)
        except ValidationError:
            return
        self._apply_revocation(host, snapshot)

    def _apply_revocation(self, host: str, snapshot: KeyRevocationList) -> None:
        as_of = snapshot.as_of
        if as_of is None:
            as_of = datetime.fromtimestamp(0, tz=UTC)
        ceiling = self._now() + _AS_OF_SKEW
        as_of = min(as_of, ceiling)  # clamp a far-future baseline (first-poll integrity)
        thumbprints = set(snapshot.revoked or [])
        with self._rev_lock:
            prev = self._revoked.get(host)
            # Monotonic guard: a snapshot whose as_of is not STRICTLY newer than
            # the one held is a rollback and is ignored — a revoked thumbprint is
            # never silently un-revoked. The first seed is always accepted.
            if prev is not None and as_of <= prev.as_of:
                return
            self._revoked[host] = _RevSet(thumbprints=thumbprints, as_of=as_of)

    def _refresh_all_revocations(self) -> None:
        with self._dir_lock:
            entries = {host: entry.file for host, entry in self._dir_cache.items()}
        for host, file in entries.items():
            self._refresh_revocation_for(host, file)

    def _jittered_interval(self) -> timedelta:
        base = self._poll_interval
        delta = base / 10
        if delta <= timedelta(0):
            return base
        seconds = delta.total_seconds()
        return base + timedelta(seconds=random.uniform(-seconds, seconds))


def active_ed25519_key(
    directory: WBAFile,
    now: datetime,
    max_scan: int = _DEFAULT_ACTIVE_KEY_SCAN,
) -> bytes | None:
    """First window-active, well-formed Ed25519 key (raw 32 bytes) from ``directory``.

    Selects an identity's CURRENT signing key BY DOCUMENT ORDER when its thumbprint
    is not known ahead of time — complementing :meth:`WBAKeyResolver.resolve`, which
    matches a KNOWN thumbprint. Iterates the directory's keys in document order,
    examining AT MOST the first ``max_scan`` (default 10 — a DoS cap so a padded
    directory cannot force unbounded work), and returns the FIRST key that passes
    ALL of: window-active ([not_before, not_after) half-open covers ``now``, both
    bounds RFC 3339-parseable — a missing/unparseable bound makes the key inactive);
    ``kty == "OKP"`` and ``crv == "Ed25519"``; and a present ``x`` that
    base64url-decodes to exactly 32 bytes. Any key failing any check is skipped and
    iteration continues; a valid key listed beyond the first ``max_scan`` positions
    is unreachable. Returns ``None`` when no examined key qualifies. Byte-parity with
    the Go ``ActiveEd25519Key`` / TS ``activeEd25519Key`` oracles.
    """
    selected = _select_active_ed25519_key(directory, now, max_scan)
    return None if selected is None else selected[0]


def active_ed25519_key_with_expiry(
    directory: WBAFile,
    now: datetime,
    max_scan: int = _DEFAULT_ACTIVE_KEY_SCAN,
) -> tuple[bytes, datetime] | None:
    """Like :func:`active_ed25519_key`, but ALSO returns the selected key's expiry.

    Runs the IDENTICAL document-order selection as :func:`active_ed25519_key` and
    returns a ``(raw_public_key, not_after)`` pair for the FIRST qualifying key — the
    raw 32 bytes plus the SAME ``not_after`` the window check parsed, as an aware
    :class:`~datetime.datetime`. A downstream caller (e.g. an offer-key cache) uses
    ``not_after`` to clamp its cache TTL to ``min(now + ttl, not_after)`` so a cached
    key never outlives its validity window. The ``not_after`` is guaranteed
    parseable — selection required it (a key with a missing/unparseable bound is
    inactive and skipped). Returns ``None`` when no examined key qualifies.
    """
    return _select_active_ed25519_key(directory, now, max_scan)


def _select_active_ed25519_key(
    directory: WBAFile,
    now: datetime,
    max_scan: int,
) -> tuple[bytes, datetime] | None:
    """Shared selector for the two active-key faces: the FIRST window-active,
    well-formed Ed25519 key in document order (cap ``max_scan``), as a
    ``(raw_public_key, not_after)`` pair, or ``None``. ``active_ed25519_key`` drops
    the expiry; ``active_ed25519_key_with_expiry`` returns it. ``not_after`` reuses
    the SAME parser :func:`_key_active_at` used, so the two faces never disagree on
    the selected key."""
    for key in (directory.keys or [])[:max_scan]:
        if not _key_active_at(key, now):
            continue
        raw = _public_key_of_safe(key)
        if raw is None:
            continue
        # not_after is guaranteed present + parseable: _key_active_at above rejects
        # any key whose window bounds do not parse, so the selected key always has one.
        not_after = _parse_rfc3339(key.not_after)
        if not_after is None:  # unreachable: _key_active_at required a parseable bound
            continue
        return raw, not_after
    return None


def _await_inflight(pending: _Inflight) -> WBAFile:
    """Block on the leader's in-flight fetch and return its shared result, or
    re-raise the leader's error. The leader publishes ``file`` xor ``error``
    before setting ``event``."""
    pending.event.wait()
    if pending.error is not None:
        raise pending.error
    if pending.file is None:  # unreachable: leader sets file xor error
        raise DirectoryUnavailableError("wba directory in-flight coalescing lost result")
    return pending.file


def _notify(hook: Hook | None) -> None:
    if hook is not None:
        hook()


def _wait_timer(timer: queue.Queue[datetime], stop: threading.Event) -> bool:
    """Block on ``timer`` while remaining responsive to ``stop``. Returns True
    when the timer fired, False when ``stop`` was set first."""
    while not stop.is_set():
        try:
            timer.get(timeout=0.05)
        except queue.Empty:
            continue
        return True
    return False


def _directory_base(ref: str, scheme: str) -> tuple[str, str] | None:
    """Normalize a Signature-Agent value (bare host, host:port, or full URL) into
    a ``scheme://host`` base and its host key, or None when it names no host."""
    candidate = ref if "://" in ref else f"{scheme}://{ref}"
    parts = urllib.parse.urlsplit(candidate)
    if not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}", parts.netloc


def _host_anchored(anchor: str, candidate: str) -> bool:
    """Whether ``candidate``'s host is anchored to ``anchor`` — equal or a
    subdomain (case-insensitive, full-label boundary)."""
    parts = urllib.parse.urlsplit(candidate)
    if not parts.netloc:
        return False
    a = anchor.lower().rstrip(".")
    c = parts.netloc.lower().rstrip(".")
    if a == "":
        return False
    return c == a or c.endswith(f".{a}")


def _key_by_thumbprint(file: WBAFile, keyid: str) -> JsonWebKey | None:
    for key in file.keys or []:
        pub = _public_key_of_safe(key)
        if pub is None:
            continue
        if thumbprint(pub) == keyid:
            return key
    return None


def _public_key_of_safe(key: JsonWebKey) -> bytes | None:
    if (key.kty or "").upper() != "OKP" or (key.crv or "").lower() != "ed25519":
        return None
    try:
        raw = b64url_decode(key.x or "")
    except ValueError:
        return None
    if len(raw) != _ED25519_PUBLIC_KEY_BYTES:
        return None
    return raw


def _public_key_of(key: JsonWebKey) -> bytes:
    raw = _public_key_of_safe(key)
    if raw is None:
        raise DirectoryUnavailableError("wba jwk decode")
    return raw


def _key_active_at(key: JsonWebKey, now: datetime) -> bool:
    """Whether ``now`` is inside ``key``'s [not_before, not_after) half-open
    window. A missing/unparseable bound makes the key inactive."""
    not_before = _parse_rfc3339(key.not_before)
    not_after = _parse_rfc3339(key.not_after)
    if not_before is None or not_after is None:
        return False
    return not_before <= now < not_after


def _parse_rfc3339(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # A naive (offset-less) bound is not a valid RFC 3339 instant. Comparing it
    # against the aware ``now`` in ``_key_active_at`` would raise TypeError and
    # crash the selector; treat it as inactive instead (fail closed). This keeps
    # parity with Go's time.Parse(time.RFC3339) and TS's offset-required parse,
    # both of which reject an offset-less bound as inactive.
    if parsed.tzinfo is None:
        return None
    return parsed
