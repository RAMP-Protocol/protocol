"""The one HTTP transport seam the fetching resolvers share.

The resolvers do their network I/O through ``httpx`` — an L2 runtime dependency.
The SDK's trust core (``ramp_sdk.core`` / the signing primitives) IMPORTS no
third-party HTTP client and is IO-free; only these fetching faces take a
maintained one. (httpx/httpcore are still HARD package dependencies — the L1 and
L2 tiers ship as one distribution and the version ceilings that guard the
private-internals SSRF seam must bind every install — so "dependency-free"
scopes the CORE IMPORT surface, not the wheel; see pyproject.) httpx owns the
response state machine — status codes, redirects, 1xx,
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

import asyncio
import os
import socket
import threading
from typing import Any

import httpcore
import httpx

from ramp_sdk.resolvers import _ssrf
from ramp_sdk.resolvers.errors import DirectoryUnavailableError

_MAX_DOC_BYTES = 1 << 20  # 1 MiB — well-known documents are small
_TIMEOUT_S = 10.0
_HTTP_OK = 200

# Overall wall-clock budget for ONE guarded GET. httpx's timeout is PER-PHASE
# (connect / read / write / pool) and does NOT cover the getaddrinfo the guarded
# backend runs before handing off to httpcore, so a slow or hostile DNS answer
# could otherwise pin a Resolve call or the revocation poller with no total bound.
# This caps the whole operation: the blocking work runs in a daemon thread the
# caller abandons on timeout (see _call_with_deadline), so a stuck getaddrinfo
# leaks a harmless daemon thread rather than blocking forever. Module-level so a
# test can shrink it. Generous vs _TIMEOUT_S so a genuinely slow-but-alive fetch is
# not cut, yet the previously-unbounded resolution now has a ceiling.
_TOTAL_FETCH_DEADLINE_S = 30.0

# The two orthogonal env flags the ONE guarded-client factory reads. Both default
# off (the guarded posture); an operator opts out of a guard by setting its flag.
# Identical to the Go/TS SDK factories — no deployment-stack allow-list, no config error.
_ENV_SKIP_SSRF = "SKIP_SSRF"  # truthy → drop the dial-time address guard
_ENV_ALLOW_INSECURE = "ALLOW_INSECURE"  # truthy → permit plaintext http (else https-only)


def _env_flag(name: str) -> bool:
    """Read a boolean env flag: True iff the value is ``"true"`` (any case) or
    ``"1"``. Every other value (including unset and ``"0"``) is False."""
    return os.environ.get(name, "").lower() in {"true", "1"}


def _skip_ssrf() -> bool:
    """Whether the dial-time address guard is disabled (SKIP_SSRF)."""
    return _env_flag(_ENV_SKIP_SSRF)


def _allow_insecure() -> bool:
    """Whether plaintext http is permitted (ALLOW_INSECURE); else https-only."""
    return _env_flag(_ENV_ALLOW_INSECURE)


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
        # Every refuse reason raises the SAME generic error (see _ssrf.refusal): it
        # neither echoes the resolved IP nor distinguishes an unresolvable host from
        # a resolved-reserved one, so it cannot be a pre-auth DNS oracle.
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise _ssrf.refusal(host) from exc
        if not infos or any(_ssrf.blocked_address(info[4][0]) for info in infos):
            # Fail closed on a MIXED public/reserved answer too (any-reserved rule).
            raise _ssrf.refusal(host)
        pinned = infos[0][4][0]  # checked IP literal → no re-resolution at connect
        return super().connect_tcp(pinned, port, timeout, local_address, socket_options)


def _install_guarded_backend(
    transport: httpx.HTTPTransport | httpx.AsyncHTTPTransport, backend: object
) -> None:
    """Swap ``transport``'s httpcore network backend for ``backend``, FAILING CLOSED
    if the private seam this depends on has moved.

    The guard attaches via ``transport._pool._network_backend`` — httpx/httpcore
    PRIVATE internals with no stability contract. A future release that renamed
    them would make a bare assignment a silent no-op (Python creates a dead
    attribute, no error) and leave the fetch path UNGUARDED — a pre-auth SSRF
    regression that ships green. So: verify the attribute EXISTS before assigning
    (a rename of ``_pool`` or ``_network_backend`` raises here, loudly, rather than
    dialing unguarded), then verify the swap actually took the object AFTER. The
    upper version pin (pyproject) keeps us on verified internals; this is the
    runtime backstop if the pin is ever loosened past a breaking release.
    """
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError(
            "SSRF guard cannot attach: httpx transport no longer exposes "
            "_pool._network_backend (httpx/httpcore internals changed). Refusing to "
            "return an UNGUARDED client — verify the internals and pin httpx<0.29, httpcore<2."
        )
    pool._network_backend = backend
    if pool._network_backend is not backend:
        raise RuntimeError(
            "SSRF guard install did not take effect: transport._pool._network_backend "
            "did not accept the guarded backend (httpx/httpcore internals changed)."
        )


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
    # Fail-closed if the private seam moved — never return an unguarded transport.
    _install_guarded_backend(transport, _GuardedBackend())
    return transport


def _require_scheme(scheme: str, *, allow_http: bool) -> None:
    """Enforce the uniform scheme policy before a dial: https always, plaintext
    http ONLY under the granted relax. A denied scheme raises the dial-time
    :class:`_ssrf.SsrfError` (never reaching the transport)."""
    lowered = scheme.lower()
    if lowered == "https" or (allow_http and lowered == "http"):
        return
    raise _ssrf.SsrfError(f"refusing to dial non-https scheme {scheme!r} (SSRF guard)")


class _SchemeGuardTransport(httpx.BaseTransport):
    """Wraps a sync transport to gate the request scheme (initial AND each redirect
    hop, since httpx re-dispatches redirects through the same transport) before the
    wrapped transport's dial."""

    def __init__(self, inner: httpx.BaseTransport, *, allow_http: bool) -> None:
        self._inner = inner
        self._allow_http = allow_http

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _require_scheme(request.url.scheme, allow_http=self._allow_http)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def guarded_client(**httpx_kwargs: Any) -> httpx.Client:
    """The ONE public sync guarded-client factory — every consumer's sync client
    for any third-party-influenceable fetch. Two orthogonal env flags drive it:
    SKIP_SSRF toggles the dial-time address guard (default: on), ALLOW_INSECURE
    toggles the scheme guard (default: https-only). The guarded path dials through
    a no-proxy transport (``trust_env=False``), so a set HTTP(S)_PROXY cannot
    tunnel a private target past the dial guard. Extra kwargs pass to
    ``httpx.Client``."""
    httpx_kwargs.setdefault("follow_redirects", True)
    httpx_kwargs.setdefault("max_redirects", _ssrf.MAX_REDIRECTS)  # shared deny-by-default cap
    httpx_kwargs.setdefault("timeout", _TIMEOUT_S)
    httpx_kwargs.setdefault("trust_env", False)  # no env proxy tunnels past the dial guard
    inner = httpx.HTTPTransport() if _skip_ssrf() else ssrf_guard()
    return httpx.Client(
        transport=_SchemeGuardTransport(inner, allow_http=_allow_insecure()), **httpx_kwargs
    )


class _AsyncGuardedBackend(httpcore.AnyIOBackend):
    """Async twin of :class:`_GuardedBackend` — pins each dial to an SSRF-checked
    address on the asyncio event loop.

    Resolves the host via the loop's non-blocking ``getaddrinfo`` (so a slow or
    hostile DNS answer cannot stall the loop), fail-closed vets EVERY resolved
    candidate against :func:`_ssrf.blocked_address` (a mixed public/reserved
    result is refused outright), then connects to a CHECKED IP LITERAL — httpcore
    does not re-resolve, so a rebinding DNS cannot steer the connect at a reserved
    address after the check. TLS ``start_tls`` still uses the original hostname,
    so cert/SNI validation is unaffected. Runs on the initial URL and on every
    followed redirect hop (httpx re-dials each through this same backend). This is
    the connect-time closure of the DNS-rebinding window the async path previously
    lacked, bringing it to parity with the Go dialer's dial-time check.
    """

    # timeout is httpcore's AsyncNetworkBackend.connect_tcp override contract, not
    # a knob of ours to redesign as asyncio.timeout — hence the ASYNC109 waiver.
    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ASYNC109
        loop = asyncio.get_running_loop()
        # Bound the resolution: httpx's per-phase timeout does not cover our
        # getaddrinfo, so cap it explicitly (an overall wall-clock budget) — a slow
        # or hostile DNS answer cannot stall the loop past the deadline. Every refuse
        # reason raises the SAME generic error (no resolved IP, no NXDOMAIN-vs-private
        # distinction) so it cannot be a pre-auth DNS oracle.
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP),
                timeout=_TOTAL_FETCH_DEADLINE_S,
            )
        except OSError as exc:  # OSError covers TimeoutError (asyncio.wait_for) too
            raise _ssrf.refusal(host) from exc
        if not infos or any(_ssrf.blocked_address(info[4][0]) for info in infos):
            # Fail closed on a MIXED public/reserved answer too (any-reserved rule).
            raise _ssrf.refusal(host)
        pinned = infos[0][4][0]  # checked IP literal → no re-resolution at connect
        return await super().connect_tcp(pinned, port, timeout, local_address, socket_options)


def async_ssrf_guard() -> httpx.AsyncHTTPTransport:
    """An SSRF-guarded async httpx transport, injectable into any ``httpx.AsyncClient``.

    The async twin of :func:`ssrf_guard`: the guard runs at the connection (dial)
    seam — where the DNS-rebinding window is actually closed — so httpx keeps
    owning status/redirects/1xx. A blocked target raises
    :class:`~ramp_sdk.resolvers._ssrf.SsrfError` (an ``OSError``).
    """
    transport = httpx.AsyncHTTPTransport()
    # Fail-closed if the private seam moved — never return an unguarded transport.
    _install_guarded_backend(transport, _AsyncGuardedBackend())
    return transport


class _AsyncSchemeGuardTransport(httpx.AsyncBaseTransport):
    """Async twin of :class:`_SchemeGuardTransport`: gates the request scheme on the
    initial dial and every redirect hop before the wrapped async transport dials."""

    def __init__(self, inner: httpx.AsyncBaseTransport, *, allow_http: bool) -> None:
        self._inner = inner
        self._allow_http = allow_http

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _require_scheme(request.url.scheme, allow_http=self._allow_http)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def guarded_async_client(**httpx_kwargs: Any) -> httpx.AsyncClient:
    """The ONE public async guarded-client factory — the async twin of
    :func:`guarded_client` for third-party-influenceable fetches (a broker-relayed
    exchange domain, a signed-URL content origin). The same two orthogonal env
    flags drive it: SKIP_SSRF toggles the dial-time address guard (default: on),
    ALLOW_INSECURE toggles the scheme guard (default: https-only). The guarded path
    dials through a no-proxy transport (``trust_env=False``). Extra keyword
    arguments pass through to ``httpx.AsyncClient``."""
    httpx_kwargs.setdefault("follow_redirects", True)
    httpx_kwargs.setdefault("max_redirects", _ssrf.MAX_REDIRECTS)  # shared deny-by-default cap
    httpx_kwargs.setdefault("timeout", _TIMEOUT_S)
    httpx_kwargs.setdefault("trust_env", False)  # no env proxy tunnels past the dial guard
    inner = httpx.AsyncHTTPTransport() if _skip_ssrf() else async_ssrf_guard()
    return httpx.AsyncClient(
        transport=_AsyncSchemeGuardTransport(inner, allow_http=_allow_insecure()), **httpx_kwargs
    )


def default_client() -> httpx.Client:
    """The wellknown resolvers' default: a plain (UNGUARDED) client.

    Their URL is a static caller-configured value (not request-derived), so an
    SSRF guard is not warranted — matching the Go oracle, which guards only the
    WBA client.
    """
    return httpx.Client(
        follow_redirects=True, max_redirects=_ssrf.MAX_REDIRECTS, timeout=_TIMEOUT_S
    )


def _call_with_deadline(fn: Any, deadline_s: float, url: str) -> tuple[int, bytes]:
    """Run ``fn`` under an OVERALL wall-clock budget and return its result.

    The blocking work (getaddrinfo + the httpx stream) runs in a DAEMON thread; if
    it has not finished within ``deadline_s`` the caller returns with a
    ``TimeoutError`` (an ``OSError``, so it flows through fetch_strict/fetch_soft's
    transport-failure arms) and the stuck thread is abandoned — a hostile DNS /
    origin cannot pin the caller past the budget. A daemon thread never blocks
    interpreter exit, so an abandoned getaddrinfo leaks harmlessly.
    """
    box: dict[str, Any] = {}
    done = threading.Event()

    def _worker() -> None:
        try:
            box["value"] = fn()
        except Exception as exc:  # captured and re-raised on the caller thread
            box["error"] = exc
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True).start()
    if not done.wait(deadline_s):
        raise TimeoutError(f"guarded fetch exceeded {deadline_s}s budget for {url}")
    if "error" in box:
        raise box["error"]
    result: tuple[int, bytes] = box["value"]
    return result


def _stream_bounded(client: httpx.Client, url: str) -> tuple[int, bytes]:
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


def _get_bounded(client: httpx.Client, url: str) -> tuple[int, bytes]:
    """GET ``url`` → (status, body) under the overall wall-clock budget.

    Wraps :func:`_stream_bounded` in :func:`_call_with_deadline` so the whole GET —
    including the getaddrinfo the guarded backend runs, which httpx's per-phase
    timeout does not cover — is bounded by ``_TOTAL_FETCH_DEADLINE_S``.
    """
    return _call_with_deadline(lambda: _stream_bounded(client, url), _TOTAL_FETCH_DEADLINE_S, url)


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
