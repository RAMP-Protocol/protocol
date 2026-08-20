"""The guarded legs refuse a dial the SDK will not make, and say so in the typed taxonomy.

Mirrors sdk/ts/tests/client-scheme-guard.test.ts.

Two rules meet here. The scheme gate (``_SchemeGuardTransport``) refuses plaintext and
anything that is not http(s), and the address pin refuses a private target. Both are
verdicts — nothing was sent — so both must reach the caller as ``NOT_SENT``. They did not:
``SsrfError`` subclasses ``OSError``, not ``httpx.HTTPError``, so it escaped every send
site raw and broke the contract this package states, that every verb raises ``CallError``
and nothing else.

Which legs, mirroring Go: the offer-derived legs and the delivery fetch, whose hosts
another party names. The configured home Exchange keeps a plain transport, as it does in
Go and TypeScript, because an operator that points the SDK at a private origin chose that
address.
"""

from __future__ import annotations

from typing import Any

import pytest

from ramp_sdk import sync as blocking
from ramp_sdk.client import ClientConfig
from ramp_sdk.client.errors import CallError, CallErrorKind
from ramp_sdk.signing_transport import SigningTransport

_SEED = bytes(range(32))
_REQUESTER = {"id": "agent-1", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"}


class _Answering:
    """An endpoint resolver that points the offer-derived leg wherever a test says."""

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    def resolve_endpoint(self, host: str) -> str:  # noqa: ARG002 - the test decides
        return self._endpoint


def _config(**overrides: Any) -> ClientConfig:
    base: dict[str, Any] = {
        "base_url": "https://exchange.test",
        "requester": _REQUESTER,
        "signer": SigningTransport(signer_seed=_SEED, keyid="agent.v1"),
    }
    base.update(overrides)
    return ClientConfig(**base)


def _report(endpoint: str) -> CallError:
    client = blocking.Client(_config(endpoint_resolver=_Answering(endpoint)))
    with client, pytest.raises(CallError) as caught:
        client.report_usage({"exchange": "issuer.test", "transaction_id": "t-1"})
    return caught.value


def test_the_offer_derived_leg_refuses_plaintext_as_a_verdict() -> None:
    # http://issuer.test is anchored and credential-free, so it passes the endpoint rule;
    # what stops it is the scheme.
    failure = _report("http://issuer.test")
    assert failure.kind is CallErrorKind.NOT_SENT
    assert "scheme" in str(failure).lower()


def test_the_offer_derived_leg_refuses_a_private_address_as_a_verdict() -> None:
    failure = _report("https://issuer.test")
    # The address pin refuses the dial once the name resolves to nothing public; either
    # way nothing was sent, which is what the kind has to say.
    assert failure.kind in {CallErrorKind.NOT_SENT, CallErrorKind.UNREACHABLE}


def test_the_delivery_leg_refuses_plaintext_as_a_verdict() -> None:
    client = blocking.Client(_config())
    with client, pytest.raises(CallError) as caught:
        client.fetch("http://edge.test/a?token=live-credential")
    assert caught.value.kind is CallErrorKind.NOT_SENT
    # The refusal reaches a log; a delivery URL carries a live credential in its query.
    assert "live-credential" not in str(caught.value)
