"""The RAMP client: the six verbs an agent needs, over the Connect-unary JSON transport.

Python port of sdk/go/connect (Client + BrokerClient). The transports differ — Go keeps
full connect-go, this speaks the unary JSON form — but that is an implementation
difference, not an API difference: the verbs carry the same names and the same contracts,
and the fail-closed offer verification is the SAME core Verifier, never a second
verification path.

ASYNC is the core, per the SDK's resolved surface decision; :mod:`ramp_sdk.sync` is the
blocking facade over a synchronous httpx client, not an ``asyncio.run`` wrapper — that
breaks inside a running loop.

The tiers this composes are synchronous by design: the offer Verifier, its key resolver
and the well-known endpoint resolver all block on httpx. They are reached through
``asyncio.to_thread`` rather than grown async twins, for two reasons. Both resolvers are
lock-guarded and cache, so the steady state costs no threads at all. And an async twin of
each would be a Python-only public face with no Go or TypeScript counterpart — surface the
parity map would have to carry forever for a seam a thread already crosses correctly.

It owns NO state. The signer, the keys, the HTTP client, the endpoint resolver and the
verification policy are all injected.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import httpx

from ramp_sdk.resolvers import _ssrf, guarded_async_client
from ramp_sdk.window import clock_window

from . import _verbs
from ._call import (
    DEFAULT_CALL_TIMEOUT_SEC,
    DEFAULT_MAX_RPC_READ_BYTES,
    Validation,
    as_call_error,
)
from ._read import (
    IDENTITY_ENCODING,
    bounded_chunks,
    refuse_unrequested_encoding,
    rpc_headers,
)
from ._verbs import ClientConfig
from .content import (
    DEFAULT_CONTENT_TIMEOUT_SEC,
    DEFAULT_MAX_CONTENT_BYTES,
    DEFAULT_PROOF_WINDOW_SEC,
    MAX_ERROR_BODY_BYTES,
    Content,
    edge_refusal,
    proof_headers,
    read_content,
    redact_url,
    transport_failure,
)
from .errors import NOT_CANONICAL_WIRE_NAMING, CallError, CallErrorKind
from .route import EndpointResolver

if TYPE_CHECKING:
    from wire.models import DisputeResponse, TransactionResponse, UsageReportResponse

    from ramp_sdk.core import DiscoveryResult, VerifiedOffer

__all__ = [
    "DEFAULT_CALL_TIMEOUT_SEC",
    "DEFAULT_CONTENT_TIMEOUT_SEC",
    "DEFAULT_MAX_CONTENT_BYTES",
    "DEFAULT_MAX_RPC_READ_BYTES",
    "DEFAULT_PROOF_WINDOW_SEC",
    "NOT_CANONICAL_WIRE_NAMING",
    "BrokerClient",
    "CallError",
    "CallErrorKind",
    "Client",
    "ClientConfig",
    "Content",
    "EndpointResolver",
    "Validation",
]


class _Face:
    """What the async verbs share: the config, the two transports and the send.

    TWO transports, mirroring the Go client. The configured home Exchange and the Broker
    are reached over a plain one — an operator that points the SDK at a private origin
    chose that address. The offer-derived legs get an address-guarded one, because there
    the caller named a domain, a manifest named the endpoint, and a signed call now goes
    wherever that pointed. Sharing one guarded client for everything looked safer and was
    not: it refused a home Exchange Go and TypeScript reach, and injecting a client to get
    that back disarmed the guard on the leg that needed it.

    A client the SDK built is closed with it; one a caller injected is theirs to close.
    """

    def __init__(
        self,
        config: ClientConfig,
        http: httpx.AsyncClient | None,
        guarded: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._owns = http is None
        self._http = http if http is not None else httpx.AsyncClient(
            follow_redirects=False, trust_env=False
        )
        # An injected client carries BOTH legs: a caller that replaced the transport
        # replaced it, and quietly routing half the calls somewhere else would make the
        # injection a lie.
        self._guarded = guarded if guarded is not None else (
            self._http if not self._owns else guarded_async_client(follow_redirects=False)
        )

    async def aclose(self) -> None:
        """Close the transports this client built. An injected one is left alone."""
        if not self._owns:
            return
        await self._http.aclose()
        if self._guarded is not self._http:
            await self._guarded.aclose()

    async def __aenter__(self) -> _Face:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    def _refuse_if_closed(self, op: str) -> None:
        """A call on a client that has been closed is the caller's own mistake, and it is
        still a call that did not happen — so it is reported the way every other one is.
        httpx raises a bare RuntimeError here, which is not a failure this package says it
        raises."""
        if self._http.is_closed or self._guarded.is_closed:
            raise CallError(
                CallErrorKind.NOT_SENT, op, cause="the client has been closed"
            )

    async def _send(self, plan: _verbs.Plan) -> tuple[int, str]:
        """Send one RPC and read its answer under the cap.

        Streamed, so the cap bounds the READ. httpx buffers a whole response before
        ``.content`` exists and decompresses on the way, so a check afterwards measures an
        allocation that already happened — two hundred kilobytes of gzip reach two hundred
        megabytes before it could fire. These peers include one an offer named.
        """
        self._refuse_if_closed(plan.op)
        http = self._guarded if plan.guarded else self._http
        try:
            async with http.stream(
                "POST",
                plan.url,
                content=plan.body,
                headers=rpc_headers(plan),
                timeout=plan.timeout,
                follow_redirects=False,
            ) as response:
                refuse_unrequested_encoding(plan.op, response)
                read = bounded_chunks(plan.op, plan.max_bytes, response.status_code)
                async for chunk in response.aiter_bytes():
                    read.add(chunk)
                return response.status_code, read.text()
        except httpx.HTTPError as exc:
            raise as_call_error(plan.op, exc) from exc
        except _ssrf.SsrfError as exc:
            # The guard's refusal is an OSError, not an httpx error, so it would otherwise
            # escape untyped and break the contract this package states.
            #
            # UNREACHABLE, not NOT_SENT, because that is what the oracle answers: in Go the
            # same refusal comes out of the RoundTripper, so the client reads it as a dial
            # that did not happen — measured, not assumed. Nothing was sent either way, and
            # a caller who retries gets the identical refusal.
            raise CallError(CallErrorKind.UNREACHABLE, plan.op, cause=str(exc)) from exc


class Client(_Face):
    """The agent-facing Exchange client.

    Built against the agent's HOME Exchange — the one its account lives on. Discovery and
    purchase go there. A usage report or a dispute does NOT: those reach the Exchange that
    ISSUED the offer, resolved per call from that Exchange's own manifest, over a
    separately guarded transport.
    """

    def __init__(
        self, config: ClientConfig, *, http: httpx.AsyncClient | None = None
    ) -> None:
        super().__init__(config, http)

    async def discover(self, query: dict[str, Any]) -> DiscoveryResult:
        """Issue DiscoverResources and return one group per requested URI, each carrying
        the fail-closed {verified, rejected} split.

        EVERY returned offer is verified against the exchange offer-signing key before it
        is handed back. Neither an unverifiable nor a doctored offer is silently dropped —
        it lands in ``rejected`` with a reason. A URI the responder GROUPED and left empty
        keeps its group, carrying the typed reason, so a refusal is an answer rather than
        an absence.
        """
        plan = _verbs.plan_discover(self._config, query)
        status, body = await self._send(plan)
        return await asyncio.to_thread(
            _verbs.finish_discover, self._config, plan, status, body
        )

    async def execute(
        self, offer: VerifiedOffer, *, idempotency_key: str | None = None
    ) -> TransactionResponse:
        """Commit to a VERIFIED offer and return the transaction response."""
        plan = _verbs.plan_execute(self._config, offer, idempotency_key)
        status, body = await self._send(plan)
        return _verbs.finish_execute(plan, status, body)

    async def report_usage(
        self, report: dict[str, Any], *, idempotency_key: str | None = None
    ) -> UsageReportResponse:
        """File a usage report with the Exchange that ISSUED the offer."""
        plan = await asyncio.to_thread(
            _verbs.plan_report_usage, self._config, report, idempotency_key
        )
        status, body = await self._send(plan)
        return _verbs.finish_report_usage(plan, status, body)

    async def dispute(
        self, request: dict[str, Any], *, idempotency_key: str | None = None
    ) -> DisputeResponse:
        """File a dispute with the Exchange that issued the offer."""
        plan = await asyncio.to_thread(
            _verbs.plan_dispute, self._config, request, idempotency_key
        )
        status, body = await self._send(plan)
        return _verbs.finish_dispute(plan, status, body)

    async def fetch(self, signed_url: str) -> Content:
        """Retrieve the content a signed delivery URL names, presenting proof of
        possession of the agent key that URL is bound to.

        This is the LOW-TIER fetch: follow one signed URL, present the key, return the
        bytes. It does not discover, select, buy or report — that orchestration is a
        separate, higher tier. It takes no idempotency key: a fetch is a GET against an
        already-issued URL, and nothing on this path mutates state.

        The URL is taken as given. Whether it is one this agent bought, and whether its
        agent_id matches this agent's key, are the CALLER's checks — the SDK exports
        ``verify_ed25519_signed_url`` and ``verify_agent_binding`` for exactly that, and
        running them first turns an edge 403 into a local answer.
        """
        headers, timeout, max_bytes = _fetch_inputs(self._config, signed_url)
        op = "fetch content"
        self._refuse_if_closed(op)
        try:
            # Redirects are REFUSED. Following one would either replay a proof bound to
            # the old URL, which the edge's own check rejects, or hand a fresh proof of
            # possession of the agent's key to whatever host the first hop named.
            #
            # Streamed for the reason the RPC legs are: the cap has to bound the read, and
            # a delivery edge is a host another party named.
            async with self._guarded.stream(
                "GET",
                signed_url,
                headers={**headers, **IDENTITY_ENCODING},
                timeout=timeout,
                follow_redirects=False,
            ) as response:
                refuse_unrequested_encoding(op, response)
                if not response.is_success:
                    # A refusal body is a small JSON object carrying a reason token. It is
                    # TRUNCATED rather than refused: past the reason bound there is nothing
                    # left to read, and an edge that answers with a huge error body should
                    # still get its refusal reported rather than swapped for a size
                    # complaint.
                    refusal = b""
                    async for chunk in response.aiter_bytes():
                        refusal += chunk
                        if len(refusal) >= MAX_ERROR_BODY_BYTES:
                            break
                    raise edge_refusal(response, refusal[:MAX_ERROR_BODY_BYTES])
                read = bounded_chunks(op, max_bytes, response.status_code)
                async for chunk in response.aiter_bytes():
                    read.add(chunk)
                return read_content(signed_url, response, read.body())
        except httpx.HTTPError as exc:
            raise transport_failure(exc) from exc
        except _ssrf.SsrfError as exc:
            # UNREACHABLE for the reason _send records: it is what Go answers, because the
            # refusal reaches it through the transport.
            raise CallError(CallErrorKind.UNREACHABLE, op, cause=redact_url(exc)) from exc


class BrokerClient(_Face):
    """The Broker client.

    A SEPARATE class rather than a second surface on the exchange client because the two
    speak to different parties. A Broker is not an Exchange: it fans a query out across
    Exchanges it knows and relays back what they offered, so its address is the Broker's,
    not any Exchange's. Hanging both off one base URL would mean one of the two was always
    pointed at the wrong party.

    It takes the same config, but only the parts a discovery call has any use for do
    anything, and one needs care: ``requester`` is REQUIRED, not optional. A Broker
    resolves the calling agent from it and declines a request that names none, so
    :meth:`resolve` refuses locally rather than spending a round trip to be told.
    """

    def __init__(
        self, config: ClientConfig, *, http: httpx.AsyncClient | None = None
    ) -> None:
        super().__init__(config, http)

    async def resolve(self, request: dict[str, Any]) -> DiscoveryResult:
        """Run discovery through the Broker, which fans out to the Exchanges it knows."""
        plan = _verbs.plan_resolve(self._config, request)
        status, body = await self._send(plan)
        return await asyncio.to_thread(
            _verbs.finish_resolve, self._config, plan, status, body
        )


def _fetch_inputs(
    config: ClientConfig, signed_url: str
) -> tuple[dict[str, str], float, int]:
    """The proof headers, the deadline and the body cap for one delivery fetch.

    The deadline covers proof minting as well as the round trip: minting may call out to a
    custody backend bounded only by that backend's own client, and a timeout covering the
    round trip alone would leave "bounds one content fetch" untrue against a degraded
    custody service. A batch pays that cost once per item.
    """
    if config.signer is None:
        raise CallError(
            CallErrorKind.NOT_SIGNABLE,
            "fetch content",
            cause=(
                "no signer configured; a bound fetch proves possession of the agent key "
                "— the same key the request is signed with"
            ),
        )
    window = config.proof_window or clock_window(_now, DEFAULT_PROOF_WINDOW_SEC)
    headers = proof_headers(
        signed_url,
        signer=config.signer,
        window=window,
        request_id=config.request_id,
    )
    return (
        headers,
        config.content_timeout_sec or DEFAULT_CONTENT_TIMEOUT_SEC,
        config.max_content_bytes or DEFAULT_MAX_CONTENT_BYTES,
    )


def _now() -> float:
    return time.time()
