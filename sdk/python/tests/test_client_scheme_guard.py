"""The guarded legs refuse a dial the SDK will not make, and say so in the typed taxonomy.

Mirrors sdk/ts/tests/client-scheme-guard.test.ts.

Two rules meet here. The scheme gate (``_SchemeGuardTransport``) refuses plaintext and
anything that is not http(s), and the address pin refuses a private target. Both used to
escape untyped: ``SsrfError`` subclasses ``OSError``, not ``httpx.HTTPError``, so it went
past every send site raw and broke the contract this package states, that every verb
raises ``CallError`` and nothing else.

They report UNREACHABLE, which is what the oracle answers — measured, not assumed: in Go
the same refusal comes out of the RoundTripper, so the client reads it as a dial that did
not happen. Nothing was sent either way, and a caller who retries gets the identical
refusal.

Which legs, mirroring Go: the offer-derived legs and the delivery fetch, whose hosts
another party names. The configured home Exchange keeps a plain transport, as it does in
Go and TypeScript, because an operator that points the SDK at a private origin chose that
address.
"""

from __future__ import annotations

import contextlib
from typing import Any

import httpx
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


def test_the_offer_derived_leg_refuses_plaintext() -> None:
    # http://issuer.test is anchored and credential-free, so it passes the endpoint rule;
    # what stops it is the scheme.
    failure = _report("http://issuer.test")
    assert failure.kind is CallErrorKind.UNREACHABLE
    assert "scheme" in str(failure).lower()


def test_the_offer_derived_leg_refuses_a_private_address() -> None:
    failure = _report("https://issuer.test")
    assert failure.kind is CallErrorKind.UNREACHABLE


def test_the_delivery_leg_refuses_plaintext() -> None:
    client = blocking.Client(_config())
    with client, pytest.raises(CallError) as caught:
        client.fetch("http://edge.test/a?token=live-credential")
    assert caught.value.kind is CallErrorKind.UNREACHABLE
    # The refusal reaches a log; a delivery URL carries a live credential in its query.
    assert "live-credential" not in str(caught.value)


# The scheme check has to sit ABOVE the transport, because the transport is replaceable.
# _SchemeGuardTransport is where the policy lives, and an injected client replaces it —
# deliberately, since an injected client carries both legs. Measured before this: a signed
# usage report reached http://issuer.test with the signature header attached.
class _Recording:
    """An injected client with no scheme policy of its own — the documented `http=` seam."""

    def __init__(self) -> None:
        self.url: str | None = None

    def client(self) -> httpx.Client:
        def respond(request: httpx.Request) -> httpx.Response:
            self.url = str(request.url)
            return httpx.Response(200, json={"ver": "1.0", "report_id": "r"})

        return httpx.Client(transport=httpx.MockTransport(respond))


class _Plaintext:
    def resolve_endpoint(self, host: str) -> str:
        return f"http://{host}"


def test_an_injected_client_cannot_carry_a_signed_report_over_plaintext() -> None:
    recorder = _Recording()
    client = blocking.Client(
        _config(endpoint_resolver=_Plaintext()), http=recorder.client()
    )
    with client, pytest.raises(CallError) as caught:
        client.report_usage({"exchange": "issuer.test", "transaction_id": "t-1"})
    assert caught.value.kind is CallErrorKind.UNREACHABLE
    assert recorder.url is None, "the injected client was reached over plaintext"


def test_an_injected_client_cannot_carry_a_delivery_proof_over_plaintext() -> None:
    recorder = _Recording()
    client = blocking.Client(_config(), http=recorder.client())
    with client, pytest.raises(CallError) as caught:
        client.fetch("http://edge.test/a?token=live-credential")
    assert caught.value.kind is CallErrorKind.UNREACHABLE
    assert recorder.url is None
    # The refusal reaches a log; a delivery URL's query is the credential.
    assert "live-credential" not in str(caught.value)


def test_but_the_home_exchange_keeps_its_latitude() -> None:
    # The operator configured that address. Same split as TypeScript's unaryCall and Go's
    # NewGuardedTransport: only the legs whose host another party named are gated.
    recorder = _Recording()
    client = blocking.Client(_config(base_url="http://exchange.test"), http=recorder.client())
    with client, contextlib.suppress(CallError):
        client.discover({"exchange": "exchange.test"})
    assert recorder.url is not None, "the home leg was refused before it dialed"
    assert recorder.url.startswith("http://exchange.test")
