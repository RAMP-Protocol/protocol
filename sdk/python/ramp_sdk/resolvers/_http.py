"""The one HTTP transport seam the fetching resolvers share.

The resolvers do their network I/O through ``httpx`` — an L2 runtime dependency.
The SDK's trust core (``ramp_sdk.core`` / the signing primitives) stays
dependency-free and IO-free; only these fetching faces take a maintained HTTP
client. httpx owns the response state machine — status codes, redirects, 1xx,
decompression — so this module owns only two things: the SSRF guard (a
connection-level hook) and the fail-closed status→body taxonomy the resolvers
rely on. There is no hand-rolled ``urllib`` handler chain to keep correct.

SSRF CONTRACT (mirrors the Go oracle): the WBA directory host is derived from a
caller-supplied Signature-Agent header and is fetched BEFORE the ed25519
signature check, so an unguarded default transport is a pre-auth SSRF lever
against internal networks. The WBA resolver therefore defaults to a client built
on the SSRF-GUARDED transport (:func:`ssrf_guard`): it resolves the host, rejects
any candidate that is a reserved / non-public address (see
:mod:`ramp_sdk.resolvers._ssrf`), and connects PINNED to a checked IP — closing
the DNS-rebinding window (the peer that is validated is the peer that is dialed,
with no second lookup a rebinding DNS could steer). TLS ``server_hostname`` stays
the original name, so cert/SNI validation is unaffected. A redirect into a
non-http(s) scheme has no httpx transport and is refused
(``httpx.UnsupportedProtocol``); an http(s) redirect re-pins through the same
guarded backend. A deployment that must reach a private directory (tests, on-prem)
injects its own ``httpx.Client`` via the ``http`` seam — the escape hatch,
mirroring the Go client injection. The wellknown resolvers (configured with a
static, non-request-derived URL) default to a plain client, matching the Go oracle
where only the WBA client is guarded.
"""

from __future__ import annotations

import socket

import httpcore
import httpx

from ramp_sdk.resolvers import _ssrf
from ramp_sdk.resolvers.errors import DirectoryUnavailableError

_MAX_DOC_BYTES = 1 << 20  # 1 MiB — well-known documents are small
_TIMEOUT_S = 10.0
_HTTP_OK = 200


class _GuardedBackend(httpcore.SyncBackend):
    """httpcore network backend that pins each dial to an SSRF-checked address.

    Resolving + checking + connecting happen against the SAME getaddrinfo result:
    every candidate is vetted (fail-closed on the whole name — a mixed
    public/reserved result is refused outright, so a rebinding/round-robin trick
    cannot land a later connect on the reserved member), then the connection is
    made to a checked IP LITERAL — httpcore does not re-resolve, so a rebinding
    DNS cannot steer the connect at a reserved address after the check. TLS
    ``start_tls`` still uses the original hostname, so cert/SNI validation is
    unaffected by the IP pinning. Runs on the initial URL and — because httpx
    re-dials every followed redirect through this same backend — on each redirect
    hop too.
    """

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise _ssrf.SsrfError(
                f"refusing to dial {host!r}: resolution failed (SSRF guard)"
            ) from exc
        if not infos:
            raise _ssrf.SsrfError(f"refusing to dial {host!r}: no addresses (SSRF guard)")
        for info in infos:
            ip = info[4][0]
            if _ssrf.blocked_address(ip):
                raise _ssrf.SsrfError(
                    f"refusing to dial non-public address {ip} for host {host!r} (SSRF guard)"
                )
        pinned = infos[0][4][0]  # checked IP literal → no re-resolution at connect
        return super().connect_tcp(pinned, port, timeout, local_address, socket_options)


def ssrf_guard() -> httpx.HTTPTransport:
    """An SSRF-guarded httpx transport, injectable into any ``httpx.Client``.

    DX::

        httpx.Client(transport=ssrf_guard(), follow_redirects=True)

    The guard runs at the connection (dial) seam — where the DNS-rebinding window
    is actually closed — so httpx keeps owning status/redirects/1xx. A blocked
    target raises :class:`~ramp_sdk.resolvers._ssrf.SsrfError` (an ``OSError``).
    """
    transport = httpx.HTTPTransport()
    # httpx.HTTPTransport builds an httpcore ConnectionPool with all the right ssl
    # context/limits; we only swap its network backend so every connection dials
    # through the SSRF check. Set before first use so all connections pick it up.
    transport._pool._network_backend = _GuardedBackend()
    return transport


def guarded_client() -> httpx.Client:
    """The WBA resolver's safe-by-default client: SSRF-guarded, redirect-following."""
    return httpx.Client(transport=ssrf_guard(), follow_redirects=True, timeout=_TIMEOUT_S)


def default_client() -> httpx.Client:
    """The wellknown resolvers' default: a plain (UNGUARDED) client.

    Their URL is a static caller-configured value (not request-derived), so an
    SSRF guard is not warranted — matching the Go oracle, which guards only the
    WBA client.
    """
    return httpx.Client(follow_redirects=True, timeout=_TIMEOUT_S)


def _get_bounded(client: httpx.Client, url: str) -> tuple[int, bytes]:
    """GET ``url`` → (status, body), the body bounded to ``_MAX_DOC_BYTES``.

    Streams so a hostile origin cannot force an unbounded read; a non-2xx returns
    ``(status, b"")`` for the caller to classify. httpx owns redirect following
    and status handling — a non-2xx is an ordinary response, never a crash.
    """
    with client.stream("GET", url) as resp:
        if resp.status_code != _HTTP_OK:
            return resp.status_code, b""
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= _MAX_DOC_BYTES:
                break
        return _HTTP_OK, b"".join(chunks)[:_MAX_DOC_BYTES]


def fetch_strict(client: httpx.Client, url: str) -> bytes:
    """GET ``url``; return the body on 200, else raise DirectoryUnavailableError.

    A transport failure (an ``httpx.HTTPError`` — including a redirect to an
    unsupported scheme — or an ``OSError``, which ``SsrfError`` is) or a non-200
    status is a fail-closed halt: the taxonomy a composite relies on to
    distinguish an outage from an unknown key. A blocked SSRF target surfaces here
    as an outage, never a valid empty doc.
    """
    try:
        status, body = _get_bounded(client, url)
    except (httpx.HTTPError, OSError) as exc:
        raise DirectoryUnavailableError(f"fetch {url}") from exc
    if status != _HTTP_OK:
        raise DirectoryUnavailableError(f"status {status} for {url}")
    return body


def fetch_soft(client: httpx.Client, url: str) -> bytes | None:
    """Best-effort GET: body on 200, else None.

    The revocation refresh uses this so a fetch blip leaves the prior snapshot in
    place (a stale-but-present snapshot is safer than dropping revocations).
    """
    try:
        status, body = _get_bounded(client, url)
    except (httpx.HTTPError, OSError):
        return None
    if status != _HTTP_OK:
        return None
    return body
