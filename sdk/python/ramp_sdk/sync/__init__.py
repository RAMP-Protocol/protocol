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
from ramp_sdk.client._verbs import ClientConfig
from ramp_sdk.client.content import Content, read_content, transport_failure
from ramp_sdk.client.errors import CallError, CallErrorKind
from ramp_sdk.resolvers import guarded_client

if TYPE_CHECKING:
    from wire.models import DisputeResponse, TransactionResponse, UsageReportResponse

    from ramp_sdk.core import DiscoveryResult, VerifiedOffer

__all__ = ["BrokerClient", "Client", "ClientConfig"]


class Client:
    """The blocking Exchange client. See :class:`ramp_sdk.client.Client` for the contract."""

    def __init__(self, config: ClientConfig, *, http: httpx.Client | None = None) -> None:
        self._config = config
        self._http = http or guarded_client(follow_redirects=False)

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
        try:
            # Redirects are REFUSED, for the reason the async face records: following one
            # either replays a proof bound to the old URL or mints a fresh one for a host
            # the first hop chose.
            response = self._http.get(
                signed_url, headers=headers, timeout=timeout, follow_redirects=False
            )
        except httpx.HTTPError as exc:
            raise transport_failure(exc) from exc
        return read_content(signed_url, response, max_bytes)

    def _send(self, plan: _verbs.Plan) -> tuple[int, str]:
        try:
            response = self._http.post(
                plan.url,
                content=plan.body,
                headers=plan.headers,
                timeout=plan.timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise as_call_error(plan.op, exc) from exc
        return _bounded(plan, response)


class BrokerClient:
    """The blocking Broker client. See :class:`ramp_sdk.client.BrokerClient`."""

    def __init__(self, config: ClientConfig, *, http: httpx.Client | None = None) -> None:
        self._config = config
        self._http = http or guarded_client(follow_redirects=False)

    def resolve(self, request: dict[str, Any]) -> DiscoveryResult:
        plan = _verbs.plan_resolve(self._config, request)
        try:
            response = self._http.post(
                plan.url,
                content=plan.body,
                headers=plan.headers,
                timeout=plan.timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise as_call_error(plan.op, exc) from exc
        status, body = _bounded(plan, response)
        return _verbs.finish_resolve(self._config, plan, status, body)


def _bounded(plan: _verbs.Plan, response: httpx.Response) -> tuple[int, str]:
    """Read one answer under the configured cap. The async twin's own copy carries the
    reasoning; this is the same rule reached through the blocking client."""
    raw = response.content
    if len(raw) > plan.max_bytes:
        raise CallError(
            CallErrorKind.TOO_LARGE,
            plan.op,
            status=response.status_code,
            cause=f"body exceeds the {plan.max_bytes} byte cap",
        )
    return response.status_code, raw.decode("utf-8", errors="replace")
