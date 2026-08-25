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

import asyncio
import contextlib
from typing import Any

import httpx
import pytest

from ramp_sdk import sync as blocking
from ramp_sdk.client import Client as AsyncClient
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

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.url = str(request.url)
        return httpx.Response(200, json={"ver": "1.0", "report_id": "r"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._respond))

    def async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._respond))


class _Face:
    """One client face, driven synchronously so both read the same in a test.

    The pre-flight is written twice — once in the async client, once in the blocking facade
    over it — so a test that drives only one of them gates only half of it. Mutating either
    async site used to leave the whole suite green, and the async client is the documented
    core; the facade is the wrapper. Parametrizing is what keeps the pair from drifting
    again, rather than a second set of tests somebody has to remember to add to.
    """

    def __init__(self, name: str, is_async: bool) -> None:
        self.name = name
        self.is_async = is_async

    def injected(self, config: ClientConfig, recorder: _Recording) -> Any:
        if self.is_async:
            return AsyncClient(config, http=recorder.async_client())
        return blocking.Client(config, http=recorder.client())

    def run(self, call: Any) -> Any:
        # The blocking face has already raised by the time this is entered — the call is
        # evaluated as the argument — and the async face raises out of asyncio.run. Both
        # land inside the caller's pytest.raises either way.
        return asyncio.run(call) if self.is_async else call


_FACES = [_Face("async", True), _Face("sync", False)]
_FACE_IDS = [f.name for f in _FACES]


class _Plaintext:
    def resolve_endpoint(self, host: str) -> str:
        return f"http://{host}"


@pytest.mark.parametrize("face", _FACES, ids=_FACE_IDS)
def test_an_injected_client_cannot_carry_a_signed_report_over_plaintext(face: _Face) -> None:
    recorder = _Recording()
    client = face.injected(_config(endpoint_resolver=_Plaintext()), recorder)
    with pytest.raises(CallError) as caught:
        face.run(client.report_usage({"exchange": "issuer.test", "transaction_id": "t-1"}))
    assert caught.value.kind is CallErrorKind.UNREACHABLE
    assert recorder.url is None, "the injected client was reached over plaintext"


@pytest.mark.parametrize("face", _FACES, ids=_FACE_IDS)
def test_an_injected_client_cannot_carry_a_delivery_proof_over_plaintext(face: _Face) -> None:
    recorder = _Recording()
    client = face.injected(_config(), recorder)
    with pytest.raises(CallError) as caught:
        face.run(client.fetch("http://edge.test/a?token=live-credential"))
    assert caught.value.kind is CallErrorKind.UNREACHABLE
    assert recorder.url is None
    # The refusal reaches a log; a delivery URL's query is the credential.
    assert "live-credential" not in str(caught.value)


@pytest.mark.parametrize("face", _FACES, ids=_FACE_IDS)
def test_but_the_home_exchange_keeps_its_latitude(face: _Face) -> None:
    # The operator configured that address. Same split as TypeScript's unaryCall and Go's
    # NewGuardedTransport: only the legs whose host another party named are gated.
    #
    # This is the only case that catches the gate firing too WIDELY, and it has to run on
    # both faces for the same reason the two above do: dropping the guarded-leg condition in
    # the async client alone would otherwise refuse an address the operator chose and
    # nothing would say so.
    recorder = _Recording()
    client = face.injected(_config(base_url="http://exchange.test"), recorder)
    with contextlib.suppress(CallError):
        face.run(client.discover({"exchange": "exchange.test"}))
    assert recorder.url is not None, "the home leg was refused before it dialed"
    assert recorder.url.startswith("http://exchange.test")
