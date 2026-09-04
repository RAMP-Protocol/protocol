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

from ramp_sdk.resolvers import _ssrf, guarded_async_client, guarded_client
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
    require_dialable_scheme,
    rpc_headers,
)
from ._verbs import ClientConfig, _with_requirements_reader
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
from .route import EndpointResolver, RegistrationRequirementsReader

if TYPE_CHECKING:
    from wire.models import (
        DisputeResponse,
        GetAccountStatusResponse,
        PushResourcesResponse,
        RefreshCatalogResponse,
        RegisterResponse,
        RemoveResourcesResponse,
        TransactionResponse,
        UsageReportResponse,
    )

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
    "CatalogClient",
    "Client",
    "ClientConfig",
    "Content",
    "EndpointResolver",
    "RegistrationRequirementsReader",
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
        self._config, self._requirements_http = _with_requirements_reader(config)

    async def aclose(self) -> None:
        """Close the transports this client built. An injected one is left alone."""
        # Independent of the RPC legs above: this client is built here whenever the
        # caller injected no reader, whether or not it injected an RPC transport, so it
        # is closed on its own terms rather than behind that ownership question.
        if self._requirements_http is not None:
            self._requirements_http.close()
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
        # The scheme, before the transport — which an injected client replaces. Only the
        # guarded legs: the configured home Exchange is the operator's own address.
        if plan.guarded:
            require_dialable_scheme(plan.op, plan.url)
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

    async def register(self, request: dict[str, Any]) -> RegisterResponse:
        """Create this agent's account at the Exchange the request names.

        Takes no idempotency key: the message carries none, because registering again
        returns the same account handle. The plan runs in a thread because it signs and,
        when the caller left ``terms_digest`` unset, reads the Exchange's published
        requirements from a freshly fetched manifest.
        """
        plan = await asyncio.to_thread(_verbs.plan_register, self._config, request)
        status, body = await self._send(plan)
        return _verbs.finish_register(plan, status, body)

    async def get_account_status(
        self, request: dict[str, Any]
    ) -> GetAccountStatusResponse:
        """Read whether this agent's account at the named Exchange is active.

        An empty ``billing_ref`` in the answer is a NORMAL answer: no account there yet.
        """
        plan = await asyncio.to_thread(
            _verbs.plan_get_account_status, self._config, request
        )
        status, body = await self._send(plan)
        return _verbs.finish_get_account_status(plan, status, body)

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
        # A delivery URL always names a host another party chose.
        require_dialable_scheme(op, signed_url)
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
                # A 3xx reached this client only because the dial refused to follow it,
                # so it is a server that did not answer rather than one that declined —
                # the class every failure taxonomy here already documents for a redirect.
                # Checked BEFORE the refusal reader, which would otherwise promote a token
                # out of the redirect body.
                if response.is_redirect:
                    raise CallError(
                        CallErrorKind.UNREACHABLE,
                        op,
                        status=response.status_code,
                        cause="peer answered with a redirect, which this client does not follow",
                    )
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


class CatalogClient(_Face):
    """The publisher-facing Catalog client: push, remove and refresh the catalog entries a
    publisher, or a contributor it authorised, supplies to an Exchange.

    A SEPARATE class, as the Broker's is, and for a related reason: the address is a
    different one. An Exchange advertises CatalogService at its manifest's
    ``catalog_endpoint``, distinct from the ExchangeService endpoint the agent client
    dials, and the caller is a different party holding a different key — a contributor's,
    named by ``caller_id``, never an agent's. The publisher chose the Exchange, so the
    origin is configuration and every call runs on the plain transport — the posture of
    the agent client's home Exchange, not of its offer-derived leg.

    It takes the same config; ``signer`` is what a real push needs (an Exchange refuses an
    unsigned catalog call), and the agent-only parts — the requester, the verifier, the
    endpoint resolver, the proof window — are inert here rather than errors.
    """

    def __init__(
        self, config: ClientConfig, *, http: httpx.AsyncClient | None = None
    ) -> None:
        super().__init__(config, http)

    async def push_resources(self, request: dict[str, Any]) -> PushResourcesResponse:
        """Push or update catalog entries."""
        plan = await asyncio.to_thread(_verbs.plan_push_resources, self._config, request)
        status, body = await self._send(plan)
        return _verbs.finish_push_resources(plan, status, body)

    async def remove_resources(self, request: dict[str, Any]) -> RemoveResourcesResponse:
        """Remove the catalog entries the request's paths name."""
        plan = await asyncio.to_thread(_verbs.plan_remove_resources, self._config, request)
        status, body = await self._send(plan)
        return _verbs.finish_remove_resources(plan, status, body)

    async def refresh_catalog(self, request: dict[str, Any]) -> RefreshCatalogResponse:
        """Ask the Exchange to refresh the tenant's catalog from its configured sources."""
        plan = await asyncio.to_thread(_verbs.plan_refresh_catalog, self._config, request)
        status, body = await self._send(plan)
        return _verbs.finish_refresh_catalog(plan, status, body)


def _fetch_inputs(
    config: ClientConfig, signed_url: str
) -> tuple[dict[str, str], float, int]:
    """The proof headers, what is LEFT of the deadline, and the body cap for one fetch.

    The deadline covers proof minting as well as the round trip. Minting may call out to a
    custody backend bounded only by that backend's own client, so a timeout applied to the
    round trip alone leaves "bounds one content fetch" untrue against a degraded custody
    service — the call simply takes as long as signing takes, and then starts its own full
    budget on top. Measured before this: a 0.5 s budget against a 3 s signer completed at
    3.0 s.

    So the clock starts here and what is returned is the REMAINDER. A budget already spent
    on signing is not signable in time, which is the answer Go gives for the same condition
    — its Fetch runs one context across both halves, and a ProofSigner that never answers
    returns FetchNotSignable on the configured deadline.

    It does not INTERRUPT minting: ``sign_agent_binding`` takes no deadline, so a signer
    that never returns still never returns. What this bounds is the total, which is the
    property that was untrue — the round trip used to start a fresh full budget on top of
    whatever signing had already spent. The TypeScript client's RPC leg is bounded the same
    way and for the same reason.
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
    budget = config.content_timeout_sec or DEFAULT_CONTENT_TIMEOUT_SEC
    started = time.monotonic()
    window = config.proof_window or clock_window(_now, DEFAULT_PROOF_WINDOW_SEC)
    headers = proof_headers(
        signed_url,
        signer=config.signer,
        window=window,
        request_id=config.request_id,
    )
    remaining = budget - (time.monotonic() - started)
    if remaining <= 0:
        raise CallError(
            CallErrorKind.NOT_SIGNABLE,
            "fetch content",
            cause=f"minting the proof of possession took the whole {budget}s budget",
        )
    return (headers, remaining, config.max_content_bytes or DEFAULT_MAX_CONTENT_BYTES)


def _now() -> float:
    return time.time()
