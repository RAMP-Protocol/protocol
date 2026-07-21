"""sdk/python outbound-sign face — TRANSPORT-NEUTRAL, the client analogue of the
Go RoundTripper sign face.

``SigningTransport.sign_outbound`` assembles the RFC 9421 headers for one outbound
request (RFC 9530 Content-Digest over the EXACT body bytes) via the shipped L1
``httpsig.sign_request`` byte oracle; it adds NO new crypto and performs NO IO. It
is NOT an HTTP client binding: it imports no httpx and wraps no transport — the
consumer (e.g. the app MCP shim, src/mcp) owns the actual httpx transport and
applies the returned headers itself. A returned offer is verified through the core
Verifier (in the app, not here).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ramp_sdk.httpsig import sign_request
from ramp_sdk.window import Window, clock_window

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
        signature_agent: str = "",
        window: Window | None = None,
    ) -> None:
        """``signature_agent`` is the signer's own WBA directory URL.

        Signature-Agent is a COVERED wire component: the sign seam always binds
        its value (empty included) into the signature base, and when non-empty
        the header itself is attached so the verifier resolves the signer's
        keys against that directory. Always-stamp-when-configured is the client
        shape — Python has no relay path, so the Go relay's set-if-absent guard
        (core.WithSignatureAgent) has no analogue here.
        """
        self._signer_seed = signer_seed
        self._keyid = keyid
        self._now = now or time.time
        self._ttl_sec = ttl_sec
        self._signature_agent = signature_agent
        # Source (created, expires) from an injected Window, defaulting to a
        # clock_window over now/ttl_sec. clock_window int()-truncates to whole
        # seconds, so the @signature-params bytes stay byte-identical to the
        # historical inline ``int(self._now())`` mint.
        self._window = window or clock_window(self._now, self._ttl_sec)

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
        created, expires = self._window()
        signed = sign_request(
            method=method,
            url=url,
            body=body,
            authorization=authorization,
            signer_seed=self._signer_seed,
            keyid=self._keyid,
            created=created,
            expires=expires,
            signature_agent=self._signature_agent,
        )
        headers = {
            "content-digest": signed.content_digest,
            "signature-input": signed.signature_input,
            "signature": signed.signature,
        }
        # The covered set binds signature-agent unconditionally (empty included);
        # the header itself travels only when a directory is configured.
        if self._signature_agent:
            headers["signature-agent"] = self._signature_agent
        return SignedOutbound(method=method, url=url, body=body, headers=headers)
