"""The one HTTP transport seam the fetching resolvers share.

Transport-neutral per the SDK dependency policy (pyproject: "No httpx extra —
the consumer owns its HTTP client"): the resolvers accept an injected HTTP
callable and default to a stdlib ``urllib.request`` implementation (zero new
runtime deps). Integration tests point the default at a REAL in-process
``http.server`` — the callable is never mocked; only the clock/poll seams are.

SSRF CONTRACT (mirrors the Go oracle): the WBA directory host is derived from a
caller-supplied Signature-Agent header and is fetched BEFORE the ed25519
signature check, so an unguarded default transport is a pre-auth SSRF lever
against internal networks. The WBA resolver therefore defaults to the SSRF-GUARDED
:func:`guarded_fetch` (not :func:`default_fetch`): it resolves the host, rejects
any candidate that is a reserved / non-public address (see
:mod:`ramp_sdk.resolvers._ssrf`), and connects PINNED to a checked IP with the
``Host`` header / TLS ``server_hostname`` kept as the original name — closing the
DNS-rebinding window (a public A record that re-resolves to 169.254.x is rejected
at connect time, not merely at an earlier lookup). A deployment that must reach a
private directory (tests, on-prem) injects its own callable via the ``http`` seam
— the escape hatch, mirroring the Go client injection. The wellknown resolvers
(configured with a static, non-request-derived URL) keep the plain
:func:`default_fetch`, matching the Go oracle where only the WBA client is guarded.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from ramp_sdk.resolvers._ssrf import SsrfError, allowed_scheme, blocked_address
from ramp_sdk.resolvers.errors import DirectoryUnavailableError

# An injected HTTP GET returning (status, body). Transport failures raise an
# OSError-family exception (urllib.error.URLError subclasses OSError; SsrfError
# is an OSError); a non-2xx HTTP status is returned as (status, b"") for the
# caller to classify.
HttpFetch = Callable[[str], "tuple[int, bytes]"]

_MAX_DOC_BYTES = 1 << 20  # 1 MiB — well-known documents are small
_TIMEOUT_S = 10.0
_HTTP_OK = 200


def _checked_addrinfo(host: str, port: int) -> list[tuple]:
    """Resolve ``host`` and reject if ANY candidate is a non-public address.

    Fail-closed on the whole name (not per-candidate): a name that resolves to a
    mix of public and reserved addresses is refused outright, so a rebinding /
    round-robin trick cannot land a later connect on the reserved member. Returns
    the getaddrinfo list (each entry's sockaddr[0] is a literal IP, already
    validated) for the caller to pin against.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise SsrfError(f"refusing to dial {host!r}: resolution failed (SSRF guard)") from exc
    if not infos:
        raise SsrfError(f"refusing to dial {host!r}: no addresses (SSRF guard)")
    for info in infos:
        ip = info[4][0]
        if blocked_address(ip):
            raise SsrfError(
                f"refusing to dial non-public address {ip} for host {host!r} (SSRF guard)"
            )
    return infos


class _GuardedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose ``connect()`` pins to a pre-checked resolved IP.

    Resolving + checking + connecting happen in one step against the SAME
    getaddrinfo result, so the peer that is validated is the peer that is dialed
    — there is no second lookup that a rebinding DNS could steer at a reserved
    address. The wire ``Host`` header is left as the original name by the caller
    (urllib sets it from the URL), so name-based virtual hosting still works.
    """

    def connect(self) -> None:
        infos = _checked_addrinfo(self.host, self.port)
        self.sock = _connect_pinned(infos, self.timeout, self.source_address)


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection variant of :class:`_GuardedHTTPConnection`.

    The TLS handshake's ``server_hostname`` (SNI + cert verification) is pinned
    to the original hostname while the socket is connected to a checked IP, so
    certificate validation is unaffected by the IP pinning.
    """

    def connect(self) -> None:
        infos = _checked_addrinfo(self.host, self.port)
        sock = _connect_pinned(infos, self.timeout, self.source_address)
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


def _connect_pinned(infos: list[tuple], timeout, source_address) -> socket.socket:
    """Open a TCP socket to the first checked candidate, trying each in turn."""
    last: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            if timeout is not None and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last = exc
            if sock is not None:
                sock.close()
    if last is not None:
        raise last
    raise SsrfError("no address to connect to (SSRF guard)")


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request):  # type: ignore[override]
        return self.do_open(_GuardedHTTPConnection, req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request):  # type: ignore[override]
        return self.do_open(_GuardedHTTPSConnection, req, context=self._context)


_MAX_REDIRECTS = 5


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-vet every redirect target's scheme before it is followed.

    A denylist of dangerous schemes is unwinnable (ftp/ftps/telnet/gopher/file/
    data/…), so the guard is deny-by-default: a 3xx to anything other than
    http/https is refused with an :class:`SsrfError`. The redirect is followed
    through the SAME guarded opener, so its resolved address is re-checked on
    connect (closing the rebinding window on the new host too). Mirrors the Go
    oracle's ``CheckRedirect`` (scheme allowlist + bounded hop count).
    """

    max_repeats = _MAX_REDIRECTS
    max_redirections = _MAX_REDIRECTS

    def redirect_request(  # type: ignore[override]  # noqa: PLR0913 — signature fixed by HTTPRedirectHandler
        self, req, fp, code, msg, headers, newurl
    ):
        scheme = urllib.parse.urlsplit(newurl).scheme
        if not allowed_scheme(scheme):
            raise SsrfError(f"refusing redirect to non-http(s) scheme {scheme!r} (SSRF guard)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_guarded_opener() -> urllib.request.OpenerDirector:
    # Deny-by-default transport: install ONLY the http/https handlers plus the
    # re-vetting redirect handler. Constructed via OpenerDirector directly (not
    # build_opener) so the stdlib's FTPHandler / FileHandler / DataHandler are
    # NOT merged in — a redirect (or a caller URL) to ftp://, file://, data:…
    # has no handler and is refused, rather than opening a fresh unguarded
    # window on a URL the guard never vetted.
    #
    # HTTPDefaultErrorHandler is REQUIRED even though we drop the transport
    # handlers above: HTTPErrorProcessor only *dispatches* a non-2xx response to
    # parent.error(); HTTPDefaultErrorHandler is the terminal handler that turns
    # it into an HTTPError. Without it a 404/500 finds no http_error_default,
    # error() returns None, open() returns None, and `with None as resp` raises a
    # TypeError — which is NOT an OSError, so it escapes the fetch_strict/soft
    # taxonomy and breaks the revocation poller's soft-fail. With it, a non-2xx
    # raises HTTPError → caught below → returned as (status, b""), matching
    # default_fetch exactly.
    context = ssl.create_default_context()
    opener = urllib.request.OpenerDirector()
    for handler in (
        _GuardedHTTPHandler(),
        _GuardedHTTPSHandler(context=context),
        _GuardedRedirectHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


_GUARDED_OPENER = _build_guarded_opener()


def default_fetch(url: str) -> tuple[int, bytes]:
    """Default transport: a bounded stdlib ``urllib.request`` GET (UNGUARDED).

    Used by the wellknown resolvers, whose URL is a static caller-configured value
    (not request-derived), so an SSRF guard is not warranted. The WBA resolver —
    whose directory host IS caller-supplied and fetched pre-auth — defaults to
    :func:`guarded_fetch` instead.
    """
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            status = int(resp.status)
            body: bytes = resp.read(_MAX_DOC_BYTES)
            return status, body
    except urllib.error.HTTPError as exc:
        return int(exc.code), b""


def guarded_fetch(url: str) -> tuple[int, bytes]:
    """SSRF-guarded transport: the WBA resolver's default.

    Resolves the host, rejects any reserved / non-public candidate, and pins the
    connection to a checked IP (closing the DNS-rebinding window: the peer that is
    validated is the peer that is dialed, with no second lookup a rebinding DNS
    could steer). A blocked target raises
    :class:`~ramp_sdk.resolvers._ssrf.SsrfError` (an ``OSError``), which the
    ``fetch_strict`` / ``fetch_soft`` transport-failure arms map to
    ``DirectoryUnavailableError`` / a dropped refresh. Inject a custom ``http``
    callable to reach a private directory (tests, on-prem).

    The initial URL's scheme is vetted deny-by-default (http/https only) before
    any dial; every redirect target is re-vetted by the guarded opener.
    """
    scheme = urllib.parse.urlsplit(url).scheme
    if not allowed_scheme(scheme):
        raise SsrfError(f"refusing to dial non-http(s) scheme {scheme!r} (SSRF guard)")
    req = urllib.request.Request(url, method="GET")
    try:
        with _GUARDED_OPENER.open(req, timeout=_TIMEOUT_S) as resp:
            status = int(resp.status)
            body: bytes = resp.read(_MAX_DOC_BYTES)
            return status, body
    except urllib.error.HTTPError as exc:
        return int(exc.code), b""
    except urllib.error.URLError as exc:
        # urllib wraps the connect-time SsrfError from the guarded connection in a
        # URLError; surface the precise SsrfError so a blocked target is a clear,
        # SSRF-labelled failure (still an OSError, so fetch_strict/soft map it the
        # same way). Non-guard transport errors propagate unchanged.
        if isinstance(exc.reason, SsrfError):
            raise exc.reason from exc
        raise


def fetch_strict(fetch: HttpFetch, url: str) -> bytes:
    """GET ``url``; return the body on 200, else raise DirectoryUnavailableError.

    A transport failure or a non-200 status is a fail-closed halt — the taxonomy
    a composite relies on to distinguish an outage from an unknown key.
    """
    try:
        status, body = fetch(url)
    except OSError as exc:
        raise DirectoryUnavailableError(f"fetch {url}") from exc
    if status != _HTTP_OK:
        raise DirectoryUnavailableError(f"status {status} for {url}")
    return body


def fetch_soft(fetch: HttpFetch, url: str) -> bytes | None:
    """Best-effort GET: body on 200, else None.

    The revocation refresh uses this so a fetch blip leaves the prior snapshot in
    place (a stale-but-present snapshot is safer than dropping revocations).
    """
    try:
        status, body = fetch(url)
    except OSError:
        return None
    if status != _HTTP_OK:
        return None
    return body
