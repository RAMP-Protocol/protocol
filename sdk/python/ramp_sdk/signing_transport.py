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

from ramp_sdk.core import sign_offer_acceptance_jcs
from ramp_sdk.httpsig import sign_request
from ramp_sdk.pop import sign_agent_binding
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
    ``sign_outbound`` returns the request plus EVERY covered header at the value that
    entered the signature base — Content-Digest / Signature-Input / Signature, and
    Authorization / Signature-Agent whose values may be empty. The seam MCP wires into
    its httpx transport.
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
        its value (empty included) into the signature base, and the header is
        always attached carrying that same value — empty included. Binding it
        without sending it is not binding it, because the verifier rebuilds the
        base from the request it received and refuses one whose covered name has
        nothing on the wire under it. When non-empty it is also how the verifier
        resolves the signer's keys against that directory.

        Always-stamp is the client shape — Python has no relay path, so the Go
        relay's set-if-absent guard (core.WithSignatureAgent) has no analogue
        here.
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

    def sign_offer_acceptance(
        self,
        *,
        offer_sig: str,
        requester_id: str,
        requester_domain: str,
        idempotency_key: str,
    ) -> tuple[str, str]:
        """Sign the detached acceptance a purchase carries; return ``(hex_signature, alg)``.

        It signs with the REQUEST signer's key, and there is deliberately no option for a
        separate acceptance key. The protocol carries one agent identity:
        ``agent_identity_hash`` is defined as the thumbprint of the agent's request-signing
        key, an Exchange verifies the detached acceptance against the key registered for
        the caller its request signature identified, and the delivery URL is bound to that
        same thumbprint. A second key would be refused at execute, and any URL it did
        produce could never be fetched — the presented key would not match the binding.

        It lives on the transport so the key stays in one place: the client composes this
        seam and never handles key material, which is the shape the Go oracle has, where
        the acceptance is signed by passing the injected Signer itself.
        """
        return sign_offer_acceptance_jcs(
            seed=self._signer_seed,
            offer_sig=offer_sig,
            requester_id=requester_id,
            requester_domain=requester_domain,
            idempotency_key=idempotency_key,
        )

    def sign_agent_binding(self, *, url: str, window: Window) -> tuple[str, str, str]:
        """Mint the proof of possession for one bound delivery GET; return the agent-key
        header value, the Signature-Input and the Signature.

        The SAME key as the request signer, for the same reason as
        :meth:`sign_offer_acceptance`: the delivery URL is bound to the thumbprint of the
        agent's request-signing key, so a proof minted under any other key presents an
        identity the URL was not issued to.
        """
        created, expires = window()
        return sign_agent_binding(
            url=url, signer_seed=self._signer_seed, created=created, expires=expires
        )

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
        # EVERY covered header, at exactly the value that entered the signature base —
        # empty values included. See docs/design-history.md,
        # "A covered header the peer never receives is not bound", for why binding one
        # without sending it is not binding it.
        #
        # Taken straight off ``signed``, never re-read from the arguments: the primitive
        # echoes what it bound, so there is one place the emitted value can come from and
        # no way for the two to drift.
        return SignedOutbound(
            method=method,
            url=url,
            body=body,
            headers={
                "content-digest": signed.content_digest,
                "signature-input": signed.signature_input,
                "signature": signed.signature,
                "authorization": signed.authorization,
                "signature-agent": signed.signature_agent,
            },
        )
