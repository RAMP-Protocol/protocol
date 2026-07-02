"""sdk/python httpx CLIENT binding — the OPT-IN outbound-sign face over the core.

The MCP shim (src/mcp) is a CLIENT: it auto-signs every outbound httpx POST to the
Broker (RFC 9421) and receives offers. This binding is the SigningTransport analogue
of the Go RoundTripper client sign face: it wraps an outbound request and signs it
via the core/L1 sign seam over the EXACT body bytes (RFC 9530 Content-Digest), and a
returned offer is verified through the core Verifier (in the app, not here).

It is OPT-IN: ``httpx`` is an extra dependency of this binding, NOT of the core. The
binding composes the shipped L1 ``httpsig.sign_request`` (the byte oracle); it adds
NO new crypto. Framework (httpx) integration is a thin add over ``sign_outbound`` —
kept minimal here so the smoke exercises the sign seam MCP actually adopts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ramp_sdk.httpsig import sign_request

if TYPE_CHECKING:
    from collections.abc import Callable

# Default proof window (seconds) for the created/expires params when the caller does
# not inject an explicit window.
_DEFAULT_TTL_SEC = 600


@dataclass(frozen=True)
class SignedOutbound:
    """The signed outbound request: the RFC 9421 headers to attach to the httpx send."""

    method: str
    url: str
    body: bytes
    headers: dict[str, str]


class SigningTransport:
    """Signs outbound requests via the core sign seam (RFC 9421 over exact body bytes).

    The signer seed + keyid are injected; the clock is injectable for determinism.
    ``sign_outbound`` returns the request plus the Content-Digest / Signature-Input /
    Signature headers — the seam MCP wires into its httpx transport.
    """

    def __init__(
        self,
        *,
        signer_seed: bytes,
        keyid: str,
        now: Callable[[], float] | None = None,
        ttl_sec: int = _DEFAULT_TTL_SEC,
    ) -> None:
        self._signer_seed = signer_seed
        self._keyid = keyid
        self._now = now or time.time
        self._ttl_sec = ttl_sec

    def sign_outbound(
        self,
        *,
        method: str,
        url: str,
        body: bytes,
        authorization: str,
    ) -> SignedOutbound:
        """Sign an outbound request; return it with the RFC 9421 headers attached.

        Authorization is always bound — pass an empty string to pin its absence
        (mirror the L1 sign_request contract).
        """
        created = int(self._now())
        expires = created + self._ttl_sec
        signed = sign_request(
            method=method,
            url=url,
            body=body,
            authorization=authorization,
            signer_seed=self._signer_seed,
            keyid=self._keyid,
            created=created,
            expires=expires,
        )
        headers = {
            "content-digest": signed.content_digest,
            "signature-input": signed.signature_input,
            "signature": signed.signature,
        }
        return SignedOutbound(method=method, url=url, body=body, headers=headers)
