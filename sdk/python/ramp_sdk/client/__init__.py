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

from ramp_sdk.resolvers import guarded_async_client
from ramp_sdk.window import clock_window

from . import _verbs
from ._call import (
    DEFAULT_CALL_TIMEOUT_SEC,
    DEFAULT_MAX_RPC_READ_BYTES,
    Validation,
    as_call_error,
)
from ._verbs import ClientConfig
from .content import (
    DEFAULT_CONTENT_TIMEOUT_SEC,
    DEFAULT_MAX_CONTENT_BYTES,
    DEFAULT_PROOF_WINDOW_SEC,
    Content,
    proof_headers,
    read_content,
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
    """What the async client and the sync facade share: the config and the http client."""

    def __init__(self, config: ClientConfig, http: Any) -> None:
        self._config = config
        self._http = http


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
        # The guarded client by default. A RAMP call carries a signature, and the
        # offer-derived leg dials a host another party named, so the address pin is the
        # profile rather than an option; a caller that must reach a private origin injects
        # its own client, which is one decision recorded in one place.
        super().__init__(config, http or guarded_async_client(follow_redirects=False))

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
        try:
            # Redirects are REFUSED. Following one would either replay a proof bound to
            # the old URL, which the edge's own check rejects, or hand a fresh proof of
            # possession of the agent's key to whatever host the first hop named.
            response = await self._http.get(
                signed_url, headers=headers, timeout=timeout, follow_redirects=False
            )
        except httpx.HTTPError as exc:
            raise transport_failure(exc) from exc
        return read_content(signed_url, response, max_bytes)

    async def _send(self, plan: _verbs.Plan) -> tuple[int, str]:
        try:
            response = await self._http.post(
                plan.url,
                content=plan.body,
                headers=plan.headers,
                timeout=plan.timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise as_call_error(plan.op, exc) from exc
        return _bounded(plan, response)


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
        super().__init__(config, http or guarded_async_client(follow_redirects=False))

    async def resolve(self, request: dict[str, Any]) -> DiscoveryResult:
        """Run discovery through the Broker, which fans out to the Exchanges it knows."""
        plan = _verbs.plan_resolve(self._config, request)
        try:
            response = await self._http.post(
                plan.url,
                content=plan.body,
                headers=plan.headers,
                timeout=plan.timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise as_call_error(plan.op, exc) from exc
        status, body = _bounded(plan, response)
        return await asyncio.to_thread(
            _verbs.finish_resolve, self._config, plan, status, body
        )


def _bounded(plan: _verbs.Plan, response: httpx.Response) -> tuple[int, str]:
    """Read one answer under the configured cap.

    The bound is what stops a peer — including one an offer named — spending the caller's
    memory on its behalf. httpx has already buffered the body, so this reports the
    overrun; it does not prevent the read, which is what a streaming client would do and
    what the RPC legs' small payloads do not warrant.
    """
    raw = response.content
    if len(raw) > plan.max_bytes:
        raise CallError(
            CallErrorKind.TOO_LARGE,
            plan.op,
            status=response.status_code,
            cause=f"body exceeds the {plan.max_bytes} byte cap",
        )
    return response.status_code, raw.decode("utf-8", errors="replace")


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
