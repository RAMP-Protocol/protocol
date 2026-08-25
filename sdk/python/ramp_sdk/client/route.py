"""Routing a call to the Exchange that ISSUED an offer. Python port of sdk/go/connect/route.go.

There are three kinds of destination, and the difference decides how much checking a call
needs. The Broker and the home Exchange come from the client's own configuration and are
trusted as far as that configuration is. The Exchange a usage report goes to is named
inside an OFFER, which arrived over the network — so an actor who can influence an offer
can influence that address.

A signature covers the DOMAIN; it says nothing about where that domain's endpoint lives,
or where its DNS points. That is why the address is resolved from the Exchange's own
manifest and then checked, rather than taken on trust or, worse, read from configuration.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ramp_sdk._endpoint_rule import endpoint_refusal
from ramp_sdk._hostref import _redact_userinfo as redact_userinfo
from ramp_sdk.hosts import is_bare_host
from ramp_sdk.resolvers.errors import EndpointRefusedError, NoEndpointError

from .errors import CallError, CallErrorKind, not_sent


@runtime_checkable
class EndpointResolver(Protocol):
    """Turns a signed exchange domain into the origin that Exchange advertises for itself.

    A Protocol so a test can drive reporting without standing up a manifest server — and,
    more to the point, so this module has no way to accept a report endpoint from
    configuration.

    An implementation's FAILURE decides how a caller is told to react, so it is part of the
    contract rather than an implementation detail. A failure that is a VERDICT — the host
    is unusable, the host is not allowed, the manifest advertises no endpoint, or it
    advertises one that must not be used — MUST raise
    :class:`~ramp_sdk.resolvers.errors.NoEndpointError`,
    :class:`~ramp_sdk.resolvers.errors.EndpointRefusedError`, or the ``ValueError``
    ``is_bare_host`` raises; those surface as ``NOT_SENT``, which tells the caller not to
    retry. Anything else is read as a transport failure and reported as ``UNREACHABLE``,
    i.e. worth retrying. An implementation that raises a bare exception for a refusal
    therefore has its final answer retried indefinitely.
    """

    def resolve_endpoint(self, host: str) -> str: ...  # pragma: no cover - protocol


def vet_exchange_endpoint(
    resolver: EndpointResolver | None, exchange_domain: str, op: str
) -> str:
    """Resolve an exchange domain to an origin a signed call may be sent to, or refuse.

    It names the check that declined, and classifies it by CAUSE. "The Exchange said no",
    "we could not reach it" and "we refused to dial it" are three different outcomes
    calling for three different responses, and only the class tells them apart: a verdict
    is final, a transport failure is worth retrying.

    One function so the vetting reads in one place: the checks are the part that grows,
    and seeing them together is what makes it evident that no branch falls through to the
    send.
    """
    if resolver is None:
        raise not_sent(op, "no endpoint resolver configured")
    if not exchange_domain:
        raise not_sent(op, "no exchange domain to route to; it comes from the signed offer")
    # A plain hostname, checked here even if the caller checked it. The resolver builds its
    # URL by concatenating this value, so a path or query smuggled through would choose
    # what gets fetched; this module owns the call and cannot rely on every present and
    # future caller having vetted it.
    try:
        bare = is_bare_host(exchange_domain)
    except ValueError as exc:
        raise not_sent(
            op, f"exchange {redact_userinfo(exchange_domain)!r} is not a usable domain: {exc}"
        ) from exc
    if not bare:
        raise not_sent(
            op,
            f"exchange {redact_userinfo(exchange_domain)!r} is not a bare domain, "
            "refusing to resolve it",
        )

    try:
        endpoint = resolver.resolve_endpoint(exchange_domain)
    except Exception as exc:  # an injected resolver may raise anything
        # Classified by CAUSE, not by position. Reaching the manifest is a network
        # operation, and a DNS blip or a 500 from an otherwise healthy Exchange is
        # TRANSIENT — reporting it as a refusal would tell a caller "we declined to send
        # this, do not retry" and permanently drop a usage report over a momentary outage.
        # Only a verdict is a refusal: the value was not a usable host, the host was not
        # allowed, the manifest was read and advertises no endpoint at all, or it
        # advertises one the resolver will not hand back.
        #
        # ValueError is in the set because the resolver checks the host itself too, and a
        # value that is not a host will not become one on a later attempt. This module
        # checks it before resolving, so the SDK's own resolver never reaches here that
        # way — an injected one can.
        kind = (
            CallErrorKind.NOT_SENT
            if isinstance(exc, NoEndpointError | EndpointRefusedError | ValueError)
            else CallErrorKind.UNREACHABLE
        )
        raise CallError(
            kind, op, cause=f"resolve exchange {exchange_domain!r}: {exc}"
        ) from exc

    # Re-checked here even though the SDK's own resolver already refuses such an endpoint.
    # The resolver is an injectable seam — its own docs offer it so a caller can drive
    # reporting without a manifest server — and this module cannot make a SIGNED call
    # conditional on a stranger's implementation having remembered the rule. The cost is
    # string work on a path that just did a network fetch.
    #
    # The SAME predicate both times, deliberately. Stated twice it drifts, and a
    # half-mirrored version of this rule is how a signed call ends up carrying credentials
    # the SDK never chose.
    refusal = endpoint_refusal(exchange_domain, endpoint)
    if refusal is not None:
        raise not_sent(
            op,
            f"refusing to send a signed call to the endpoint exchange "
            f"{redact_userinfo(exchange_domain)!r} advertises: {refusal}",
        )
    return endpoint
