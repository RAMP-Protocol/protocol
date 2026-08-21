"""The blocking facade over the RAMP client — for scripts, notebooks and synchronous apps.

Same verbs, same names, same contracts as :mod:`ramp_sdk.client`; the only difference is
that nothing is awaited. It is backed by a SYNCHRONOUS httpx client rather than
``asyncio.run`` around the async core, which is the whole point: ``asyncio.run`` raises
inside an already-running loop, so a facade built that way is unusable in exactly the
place a caller would reach for it by accident.

Every line of protocol — the envelope stamping, the routing, the request check, the
signing, the decode, the offer verification — is the shared one. What this module holds is
the send, and nothing else. That is what keeps the two faces from becoming two dialects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from ramp_sdk.client import _fetch_inputs, _verbs
from ramp_sdk.client._call import as_call_error
from ramp_sdk.client._read import (
    IDENTITY_ENCODING,
    bounded_chunks,
    refuse_unrequested_encoding,
    rpc_headers,
)
from ramp_sdk.client._verbs import ClientConfig
from ramp_sdk.client.content import (
    MAX_ERROR_BODY_BYTES,
    Content,
    edge_refusal,
    read_content,
    redact_url,
    transport_failure,
)
from ramp_sdk.client.errors import CallError, CallErrorKind
from ramp_sdk.resolvers import _ssrf, guarded_client

if TYPE_CHECKING:
    from wire.models import DisputeResponse, TransactionResponse, UsageReportResponse

    from ramp_sdk.core import DiscoveryResult, VerifiedOffer

__all__ = ["BrokerClient", "Client", "ClientConfig"]


class _Face:
    """What the blocking verbs share: the config, the two transports and the send.

    The same split as the async face, for the same reason: the configured home Exchange
    and the Broker over a plain transport, the offer-derived legs over an address-guarded
    one. See :class:`ramp_sdk.client._Face`.
    """

    def __init__(
        self,
        config: ClientConfig,
        http: httpx.Client | None,
        guarded: httpx.Client | None = None,
    ) -> None:
        self._config = config
        self._owns = http is None
        self._http = http if http is not None else httpx.Client(
            follow_redirects=False, trust_env=False
        )
        # An injected client carries BOTH legs: a caller that replaced the transport
        # replaced it, and quietly routing half the calls somewhere else would make the
        # injection a lie.
        self._guarded = guarded if guarded is not None else (
            self._http if not self._owns else guarded_client(follow_redirects=False)
        )

    def close(self) -> None:
        """Close the transports this client built. An injected one is left alone."""
        if not self._owns:
            return
        self._http.close()
        if self._guarded is not self._http:
            self._guarded.close()

    def __enter__(self) -> _Face:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _send(self, plan: _verbs.Plan) -> tuple[int, str]:
        """Send one RPC and read its answer under the cap. The async twin's own docstring
        carries the reasoning; only the iteration differs."""
        http = self._guarded if plan.guarded else self._http
        try:
            with http.stream(
                "POST",
                plan.url,
                content=plan.body,
                headers=rpc_headers(plan),
                timeout=plan.timeout,
                follow_redirects=False,
            ) as response:
                refuse_unrequested_encoding(plan.op, response)
                read = bounded_chunks(plan.op, plan.max_bytes, response.status_code)
                for chunk in response.iter_bytes():
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
    """The blocking Exchange client. See :class:`ramp_sdk.client.Client` for the contract."""

    def __init__(self, config: ClientConfig, *, http: httpx.Client | None = None) -> None:
        super().__init__(config, http)

    def discover(self, query: dict[str, Any]) -> DiscoveryResult:
        plan = _verbs.plan_discover(self._config, query)
        status, body = self._send(plan)
        return _verbs.finish_discover(self._config, plan, status, body)

    def execute(
        self, offer: VerifiedOffer, *, idempotency_key: str | None = None
    ) -> TransactionResponse:
        plan = _verbs.plan_execute(self._config, offer, idempotency_key)
        status, body = self._send(plan)
        return _verbs.finish_execute(plan, status, body)

    def report_usage(
        self, report: dict[str, Any], *, idempotency_key: str | None = None
    ) -> UsageReportResponse:
        plan = _verbs.plan_report_usage(self._config, report, idempotency_key)
        status, body = self._send(plan)
        return _verbs.finish_report_usage(plan, status, body)

    def dispute(
        self, request: dict[str, Any], *, idempotency_key: str | None = None
    ) -> DisputeResponse:
        plan = _verbs.plan_dispute(self._config, request, idempotency_key)
        status, body = self._send(plan)
        return _verbs.finish_dispute(plan, status, body)

    def fetch(self, signed_url: str) -> Content:
        headers, timeout, max_bytes = _fetch_inputs(self._config, signed_url)
        op = "fetch content"
        try:
            # Redirects are REFUSED, and the body is STREAMED under the cap, for the
            # reasons the async face records.
            with self._guarded.stream(
                "GET",
                signed_url,
                headers={**headers, **IDENTITY_ENCODING},
                timeout=timeout,
                follow_redirects=False,
            ) as response:
                refuse_unrequested_encoding(op, response)
                if not response.is_success:
                    refusal = b""
                    for chunk in response.iter_bytes():
                        refusal += chunk
                        if len(refusal) >= MAX_ERROR_BODY_BYTES:
                            break
                    raise edge_refusal(response, refusal[:MAX_ERROR_BODY_BYTES])
                read = bounded_chunks(op, max_bytes, response.status_code)
                for chunk in response.iter_bytes():
                    read.add(chunk)
                return read_content(signed_url, response, read.body())
        except httpx.HTTPError as exc:
            raise transport_failure(exc) from exc
        except _ssrf.SsrfError as exc:
            # UNREACHABLE for the reason _send records: it is what Go answers, because the
            # refusal reaches it through the transport.
            raise CallError(CallErrorKind.UNREACHABLE, op, cause=redact_url(exc)) from exc


class BrokerClient(_Face):
    """The blocking Broker client. See :class:`ramp_sdk.client.BrokerClient`."""

    def __init__(self, config: ClientConfig, *, http: httpx.Client | None = None) -> None:
        super().__init__(config, http)

    def resolve(self, request: dict[str, Any]) -> DiscoveryResult:
        plan = _verbs.plan_resolve(self._config, request)
        status, body = self._send(plan)
        return _verbs.finish_resolve(self._config, plan, status, body)
