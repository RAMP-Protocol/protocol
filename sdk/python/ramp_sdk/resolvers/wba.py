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

from pydantic import ValidationError
from wire.models import JsonWebKey, KeyRevocationList, WBAFile

from ramp_sdk.b64 import b64url_decode
from ramp_sdk.resolvers._http import HttpFetch, default_fetch, fetch_soft, fetch_strict
from ramp_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    KeyExpiredError,
    KeyRevokedError,
    UnknownKeyError,
)
from ramp_sdk.thumbprint import thumbprint

_WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
_DEFAULT_TTL = timedelta(hours=1)
_DEFAULT_POLL_INTERVAL = timedelta(seconds=300)
# Bounds how far into the future a revocation snapshot's as_of may sit before it
# is clamped, so a compromised origin cannot stamp a far-future baseline that
# permanently freezes later (legitimately earlier) snapshots under the guard.
_AS_OF_SKEW = timedelta(seconds=300)
_ED25519_PUBLIC_KEY_BYTES = 32

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


class WBAKeyResolver:
    """Resolve signing keys from WBA identity directories, matching by RFC 7638
    thumbprint and enforcing validity windows + the host's revocation snapshot."""

    def __init__(
        self,
        *,
        scheme: str = "https",
        ttl: timedelta = _DEFAULT_TTL,
        poll_interval: timedelta = _DEFAULT_POLL_INTERVAL,
        now: NowFn = _now_utc,
        after: AfterFn = _default_after,
        on_poll_armed: Hook | None = None,
        on_poll_cycle: Hook | None = None,
        http: HttpFetch = default_fetch,
    ) -> None:
        self._scheme = scheme or "https"
        self._ttl = ttl if ttl > timedelta(0) else _DEFAULT_TTL
        self._poll_interval = (
            poll_interval if poll_interval > timedelta(0) else _DEFAULT_POLL_INTERVAL
        )
        self._now = now
        self._after = after
        self._on_poll_armed = on_poll_armed
        self._on_poll_cycle = on_poll_cycle
        self._http = http
        self._dir_lock = threading.Lock()
        self._dir_cache: dict[str, _DirEntry] = {}
        self._rev_lock = threading.Lock()
        self._revoked: dict[str, _RevSet] = {}

    def resolve(self, keyid: str, directory: str) -> bytes:
        """Resolve ``keyid`` (a thumbprint) against ``directory``.

        Returns the raw Ed25519 public key. Raises UnknownKeyError for an
        unknown/absent/malformed reference (fall-through), and the distinct
        KeyRevokedError / KeyExpiredError / DirectoryUnavailableError for the
        fail-closed verdicts.
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
            file = self._sync_refresh(base, host)  # rotation self-heal
            key = _key_by_thumbprint(file, keyid)
            if key is None:
                # Removal is fall-through (unknown), never revocation.
                raise UnknownKeyError(f"keyid={keyid!r} host={host!r}")
        if self._is_revoked(host, keyid):
            raise KeyRevokedError(f"keyid={keyid!r}")
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

    def _sync_refresh(self, base: str, host: str) -> WBAFile:
        file = self._fetch_directory(base)
        with self._dir_lock:
            self._dir_cache[host] = _DirEntry(file=file, exp=self._now() + self._ttl)
        self._refresh_revocation_for(host, file)
        return file

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
        return datetime.fromisoformat(value)
    except ValueError:
        return None
