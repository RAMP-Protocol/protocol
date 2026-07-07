"""The one HTTP transport seam the fetching resolvers share.

Transport-neutral per the SDK dependency policy (pyproject: "No httpx extra —
the consumer owns its HTTP client"): the resolvers accept an injected HTTP
callable and default to a stdlib ``urllib.request`` implementation (zero new
runtime deps). Integration tests point the default at a REAL in-process
``http.server`` — the callable is never mocked; only the clock/poll seams are.

SSRF CONTRACT (mirrors the Go oracle): the resolver exposes the injection point;
the SSRF guard (private/link-local rejection) stays with the application, which
injects a hardened callable when the URL is derived from request input.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable

from ramp_sdk.resolvers.errors import DirectoryUnavailableError

# An injected HTTP GET returning (status, body). Transport failures raise an
# OSError-family exception (urllib.error.URLError subclasses OSError); a non-2xx
# HTTP status is returned as (status, b"") for the caller to classify.
HttpFetch = Callable[[str], "tuple[int, bytes]"]

_MAX_DOC_BYTES = 1 << 20  # 1 MiB — well-known documents are small
_TIMEOUT_S = 10.0
_HTTP_OK = 200


def default_fetch(url: str) -> tuple[int, bytes]:
    """Default transport: a bounded stdlib ``urllib.request`` GET."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            status = int(resp.status)
            body: bytes = resp.read(_MAX_DOC_BYTES)
            return status, body
    except urllib.error.HTTPError as exc:
        return int(exc.code), b""


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
