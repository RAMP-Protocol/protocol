"""The RAMP client's verbs (Python side) — mirror of sdk/ts/tests/client.test.ts.

Driven through an INJECTED httpx transport rather than a socket: what is under test is the
protocol behaviour — the URL, the envelope, the routing, the verification and the failure
taxonomy — not httpx.

BOTH faces run every case. The async client is the core and the sync module is a facade
over a blocking httpx client, and the whole point of that arrangement is that they cannot
disagree; parametrizing the suite over the two is what holds it.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ramp_sdk.sync as sync_client
from ramp_sdk.client import Client, ClientConfig, NOT_CANONICAL_WIRE_NAMING
from ramp_sdk.client import BrokerClient
from ramp_sdk.client.errors import CallError, CallErrorKind
from ramp_sdk.core import Mode, StaticOfferKeyResolver, Verifier, sign_offer_jcs
from ramp_sdk.resolvers.errors import NoEndpointError
from ramp_sdk.signing_transport import SigningTransport

REQUESTER = {"id": "agent-1", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"}
AGENT_SEED = bytes(range(32))
_NOW = 1_700_000_000


class Recorder:
    """An httpx transport that records what it was handed and answers a fixed body."""

    def __init__(self, answer: Any, status: int = 200) -> None:
        self.answer = answer
        self.status = status
        self.seen: list[httpx.Request] = []

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        return httpx.Response(self.status, json=self.answer)

    def sync(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._respond))

    def async_(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._respond))

    def body(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.seen[index].content)


class Face:
    """One client face, driven synchronously so both read the same in a test."""

    def __init__(self, name: str, is_async: bool) -> None:
        self.name = name
        self._async = is_async

    def client(self, config: ClientConfig, recorder: Recorder) -> Any:
        if self._async:
            return Client(config, http=recorder.async_())
        return sync_client.Client(config, http=recorder.sync())

    def broker(self, config: ClientConfig, recorder: Recorder) -> Any:
        if self._async:
            return BrokerClient(config, http=recorder.async_())
        return sync_client.BrokerClient(config, http=recorder.sync())

    def run(self, call: Any) -> Any:
        return asyncio.run(call) if self._async else call


FACES = [Face("async", True), Face("sync", False)]
_IDS = [f.name for f in FACES]


def _signed_offer(exchange: str = "exchange.test") -> tuple[dict[str, Any], bytes]:
    """A signed offer plus the raw public key that verifies it."""
    seed = bytes([7]) * 32
    offer: dict[str, Any] = {
        "offer_id": "offer-1",
        "exchange": exchange,
        "expires_at": "2099-01-01T00:00:00Z",
    }
    signature, algorithm = sign_offer_jcs(seed=seed, offer=offer)
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return {**offer, "signature": signature, "signature_algorithm": algorithm}, public


def _config(**overrides: Any) -> ClientConfig:
    base = {
        "base_url": "https://exchange.test",
        "requester": REQUESTER,
        "signer": SigningTransport(signer_seed=AGENT_SEED, keyid="agent.v1"),
    }
    base.update(overrides)
    return ClientConfig(**base)  # type: ignore[arg-type]


def _verifier(public: bytes, exchange: str = "exchange.test") -> Verifier:
    return Verifier(
        mode=Mode.STRICT,
        resolver=StaticOfferKeyResolver({exchange: public}),
        now=lambda: _NOW,
    )


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_addresses_the_connect_unary_path_and_stamps_the_envelope(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "exchange": "exchange.test"})
    client = face.client(_config(), rec)

    face.run(client.discover({"exchange": "exchange.test", "uris": ["https://site.test/a"]}))

    request = rec.seen[0]
    assert str(request.url) == "https://exchange.test/ramp.v1.ExchangeService/DiscoverResources"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["connect-protocol-version"] == "1"
    # The signing face runs over the exact body bytes.
    assert "signature-input" in request.headers
    body = rec.body()
    assert body["ver"] == "1.0"
    assert body["requester"] == REQUESTER
    # The recipient is the caller's to state. A value the transport filled in from the
    # address it was already dialling would restate the dial target, not check it.
    assert body["exchange"] == "exchange.test"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_value_the_caller_set_wins_and_the_caller_message_is_untouched(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "exchange": "exchange.test"})
    mine = {"id": "someone-else", "domain": "other.test", "type": "REQUESTER_TYPE_AGENT"}
    query = {"ver": "9.9", "exchange": "exchange.test", "requester": mine}
    client = face.client(_config(), rec)

    face.run(client.discover(query))

    body = rec.body()
    assert body["ver"] == "9.9"
    assert body["requester"] == mine
    assert query == {"ver": "9.9", "exchange": "exchange.test", "requester": mine}


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_every_requested_uri_keeps_its_group_and_its_reason(face: Face) -> None:
    offer, public = _signed_offer()
    rec = Recorder(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            "offer_groups": [
                {"uri": "https://site.test/a", "offers": [offer]},
                {
                    "uri": "https://site.test/b",
                    "absence_reason": "OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT",
                },
            ],
        }
    )
    client = face.client(_config(verifier=_verifier(public)), rec)

    result = face.run(client.discover({"exchange": "exchange.test"}))

    assert len(result.groups) == 2
    assert len(result.groups[0].result.verified) == 1
    # The refusal is an ANSWER: the agent can tell "acquire an entitlement and retry" from
    # "give up" only because the reason survived.
    assert result.groups[1].absence_reason == "OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT"
    assert result.exchange == "exchange.test"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_grouped_and_flat_lists_are_alternatives_never_both(face: Face) -> None:
    offer, public = _signed_offer()
    rec = Recorder(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            "offer_groups": [{"uri": "https://site.test/a", "offers": [offer]}],
            "offers": [offer],  # the same offer, mirrored
        }
    )
    client = face.client(_config(verifier=_verifier(public)), rec)

    result = face.run(client.discover({"exchange": "exchange.test"}))

    assert len(result.groups) == 1
    assert len(result.verified()) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_flat_answer_is_attributed_only_for_a_single_uri_query(face: Face) -> None:
    offer, public = _signed_offer()
    answer = {"ver": "1.0", "exchange": "exchange.test", "offers": [offer]}

    single = face.run(
        face.client(_config(verifier=_verifier(public)), Recorder(answer)).discover(
            {"exchange": "exchange.test", "uris": ["https://site.test/a"]}
        )
    )
    assert single.groups[0].uri == "https://site.test/a"

    multi = face.run(
        face.client(_config(verifier=_verifier(public)), Recorder(answer)).discover(
            {"exchange": "exchange.test", "uris": ["https://site.test/a", "https://site.test/b"]}
        )
    )
    # The SDK does not invent an attribution the wire never made.
    assert multi.groups[0].uri == ""


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_offer_whose_key_does_not_resolve_is_rejected_not_dropped(face: Face) -> None:
    offer, _ = _signed_offer()
    rec = Recorder(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            "offer_groups": [{"uri": "https://site.test/a", "offers": [offer]}],
        }
    )
    client = face.client(_config(), rec)

    result = face.run(client.discover({"exchange": "exchange.test"}))

    assert result.groups[0].result.verified == []
    assert len(result.groups[0].result.rejected) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_wire_offer_carrying_emitted_zero_values_still_verifies(face: Face) -> None:
    """The emitted wire form is NOT the signed form, and the client inverts it.

    A RAMP Exchange serves proto-JSON with EmitUnpopulated, so what arrives carries
    zero-valued scalars and empty repeateds the signature never covered. Verifying the
    wire object as-is fails every genuine offer.
    """
    offer, public = _signed_offer()
    wire = {**offer, "ext_critical": [], "attestations": [], "previews": []}
    rec = Recorder(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            "offer_groups": [{"uri": "https://site.test/a", "offers": [wire]}],
        }
    )
    client = face.client(_config(verifier=_verifier(public)), rec)

    result = face.run(client.discover({"exchange": "exchange.test"}))

    assert len(result.groups[0].result.verified) == 1, (
        result.groups[0].result.rejected[0].reason if result.groups[0].result.rejected else ""
    )


# ---------------------------------------------------------------------------
# reading an answer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_camel_case_body_is_refused_rather_than_parsed_away(face: Face) -> None:
    # What a stock connect-go server serves: no snake_case codec registered. The generated
    # model would ignore offerGroups and answer an empty, successful result.
    rec = Recorder(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            "offerGroups": [{"uri": "https://site.test/a", "offers": []}],
        }
    )
    client = face.client(_config(), rec)

    with pytest.raises(CallError) as excinfo:
        face.run(client.discover({"exchange": "exchange.test"}))

    assert excinfo.value.kind is CallErrorKind.MALFORMED
    assert excinfo.value.reason_of() == NOT_CANONICAL_WIRE_NAMING


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_connect_error_envelope_becomes_the_typed_failure(face: Face) -> None:
    rec = Recorder(
        {
            "code": "permission_denied",
            "message": "balance too low",
            "details": [
                {
                    "type": "ramp.v1.ErrorDetail",
                    "value": "aWdub3JlZA",
                    "debug": {
                        "domain": "ramp.v1.ExchangeService",
                        "message": "balance too low",
                        "transactionDenial": {"reason": "DENIAL_REASON_INSUFFICIENT_BALANCE"},
                    },
                }
            ],
        },
        status=403,
    )
    client = face.client(_config(), rec)

    with pytest.raises(CallError) as excinfo:
        face.run(client.discover({"exchange": "exchange.test"}))

    err = excinfo.value
    assert err.kind is CallErrorKind.REFUSED
    assert err.status == 403
    assert err.reason_of() == "permission_denied"
    assert err.detail is not None
    assert err.detail.transaction_denial.reason.value == "DENIAL_REASON_INSUFFICIENT_BALANCE"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_peer_that_never_reached_a_verdict_is_unreachable(face: Face) -> None:
    rec = Recorder({"code": "unavailable", "message": "draining"}, status=503)
    client = face.client(_config(), rec)

    with pytest.raises(CallError) as excinfo:
        face.run(client.discover({"exchange": "exchange.test"}))
    assert excinfo.value.kind is CallErrorKind.UNREACHABLE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_redirect_is_reported_rather_than_followed(face: Face) -> None:
    rec = Recorder({"code": "unknown"}, status=302)
    client = face.client(_config(), rec)

    with pytest.raises(CallError) as excinfo:
        face.run(client.discover({"exchange": "exchange.test"}))
    # Unreachable, not refused: this client did not follow the hop, so the call never
    # reached a server that could decline it — and a redirect body carries nothing to read
    # as a verdict, even when it happens to look like a Connect envelope.
    assert excinfo.value.kind is CallErrorKind.UNREACHABLE
    assert excinfo.value.status == 302
    # One request: the hop was not taken.
    assert len(rec.seen) == 1


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


def _verified(public: bytes, offer: dict[str, Any]) -> Any:
    result = _verifier(public).sort([offer])
    assert result.verified, result.rejected[0].reason if result.rejected else "no offer"
    return result.verified[0]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_sends_the_reflected_offer_and_a_verifying_acceptance(face: Face) -> None:
    from ramp_sdk.core import verify_offer_acceptance_jcs

    offer, public = _signed_offer()
    rec = Recorder({"ver": "1.0"})
    client = face.client(_config(), rec)

    face.run(client.execute(_verified(public, offer), idempotency_key="idem-1"))

    body = rec.body()
    assert str(rec.seen[0].url).endswith("/ramp.v1.ExchangeService/ExecuteTransaction")
    assert body["idempotency_key"] == "idem-1"
    item = body["items"][0]
    assert item["offer"] == offer
    # An Exchange checks this, so a request without a verifying acceptance can only ever
    # be refused — asserting it is what makes the verb useful rather than merely sent.
    agent_public = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
    assert verify_offer_acceptance_jcs(
        pubkey_b64=base64.b64encode(agent_public).decode(),
        signature_hex=item["agent_acceptance"]["signature"],
        offer_sig=offer["signature"],
        requester_id=REQUESTER["id"],
        requester_domain=REQUESTER["domain"],
        idempotency_key="idem-1",
    )
    # The request-level acceptance travels beside the per-item one. The wire
    # payload must spell exactly what was signed, and the signature must verify
    # the way a receiving Exchange would check it.
    from ramp_sdk.core import verify_request_acceptance_jcs

    request_acceptance = body["agent_request_acceptance"]
    assert request_acceptance["payload"] == {
        "items": [{"offer_sig": offer["signature"], "exchange": "exchange.test"}],
        "requester_id": REQUESTER["id"],
        "requester_domain": REQUESTER["domain"],
        "idempotency_key": "idem-1",
    }
    assert request_acceptance["signature_algorithm"] == "EdDSA"
    assert verify_request_acceptance_jcs(
        pubkey_b64=base64.b64encode(agent_public).decode(),
        signature_hex=request_acceptance["signature"],
        items=[(offer["signature"], "exchange.test")],
        requester_id=REQUESTER["id"],
        requester_domain=REQUESTER["domain"],
        idempotency_key="idem-1",
    )


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_omits_request_acceptance_when_the_offer_names_no_exchange(face: Face) -> None:
    # An offer with no exchange cannot appear in a request-acceptance item (the
    # item requires a recipient), so the client sends the request without the
    # field. A wire-valid offer always names its exchange, so this path exists
    # only for offers that bypass the strict checks — surfaced here the same way
    # the unsigned-offer test does, through a verification-off Verifier, with
    # request validation off for the same reason.
    offer, _public = _signed_offer(exchange="")
    surfaced = Verifier(
        mode=Mode.OFF, resolver=StaticOfferKeyResolver({}), now=lambda: _NOW
    ).sort([offer]).verified[0]
    rec = Recorder({"ver": "1.0"})
    client = face.client(_config(validation="off"), rec)

    face.run(client.execute(surfaced, idempotency_key="idem-1"))

    assert "agent_request_acceptance" not in rec.body()


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_mints_a_fresh_idempotency_key_when_none_is_pinned(face: Face) -> None:
    offer, public = _signed_offer()
    rec = Recorder({"ver": "1.0"})
    client = face.client(_config(), rec)
    verified = _verified(public, offer)

    face.run(client.execute(verified))
    face.run(client.execute(verified))

    # A fresh key per call: reusing one would read to the server as a replay of the same
    # purchase, which is a decision only the caller may make.
    assert rec.body(0)["idempotency_key"] != rec.body(1)["idempotency_key"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_refuses_locally_without_a_requester_or_a_seed(face: Face) -> None:
    offer, public = _signed_offer()
    verified = _verified(public, offer)
    rec = Recorder({})

    no_requester = face.client(_config(requester=None), rec)
    with pytest.raises(CallError) as first:
        face.run(no_requester.execute(verified))
    assert first.value.kind is CallErrorKind.MALFORMED

    # One agent identity: the acceptance is signed with the request signer's own key, so
    # there is no second key to be missing.
    unsigned = face.client(_config(signer=None), rec)
    with pytest.raises(CallError) as second:
        face.run(unsigned.execute(verified))
    assert second.value.kind is CallErrorKind.NOT_SIGNABLE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_refuses_an_unsigned_offer_that_verification_off_can_surface(face: Face) -> None:
    off = Verifier(mode=Mode.OFF, resolver=StaticOfferKeyResolver({}), now=lambda: _NOW)
    unsigned = off.sort([{"offer_id": "no-signature"}]).verified[0]
    client = face.client(_config(), Recorder({}))

    with pytest.raises(CallError) as excinfo:
        face.run(client.execute(unsigned))
    assert excinfo.value.kind is CallErrorKind.MALFORMED


# ---------------------------------------------------------------------------
# the offer-derived leg
# ---------------------------------------------------------------------------


class _Resolver:
    def resolve_endpoint(self, host: str) -> str:
        return f"https://api.{host}"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_usage_report_goes_to_the_exchange_the_report_names(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "report_id": "r-1"})
    client = face.client(_config(endpoint_resolver=_Resolver()), rec)

    face.run(client.report_usage({"exchange": "issuer.test", "transaction_id": "t-1"}))

    # Never the configured home Exchange: the destination came off the signed message.
    assert str(rec.seen[0].url) == "https://api.issuer.test/ramp.v1.ExchangeService/ReportUsage"
    body = rec.body()
    assert body["ver"] == "1.0"
    assert isinstance(body["idempotency_key"], str)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_idempotency_key_the_caller_already_set_is_kept(face: Face) -> None:
    rec = Recorder({"ver": "1.0"})
    client = face.client(_config(endpoint_resolver=_Resolver()), rec)

    face.run(client.report_usage({"exchange": "issuer.test", "idempotency_key": "mine"}))

    # Discarding it would turn each of the caller's retries into a fresh report, which is
    # the double-counting the field exists to prevent.
    assert rec.body()["idempotency_key"] == "mine"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_dispute_is_routed_the_same_way(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "dispute_id": "d-1"})
    client = face.client(_config(endpoint_resolver=_Resolver()), rec)

    face.run(
        client.dispute(
            {
                "exchange": "issuer.test",
                "transaction_id": "t-1",
                "report_id": "r-1",
                "reason": "DISPUTE_REASON_DELIVERY_FAILED",
            }
        )
    )

    assert str(rec.seen[0].url).endswith("/ramp.v1.ExchangeService/DisputeTransaction")


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("exchange", ["", "issuer.test/path", "https://issuer.test"])
def test_only_a_bare_domain_is_resolved_and_nothing_is_sent(face: Face, exchange: str) -> None:
    rec = Recorder({})
    client = face.client(_config(endpoint_resolver=_Resolver()), rec)

    with pytest.raises(CallError) as excinfo:
        face.run(client.report_usage({"exchange": exchange}))

    assert excinfo.value.kind is CallErrorKind.NOT_SENT
    assert rec.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_resolver_verdict_is_final_and_its_transport_failure_is_not(face: Face) -> None:
    class Verdict:
        def resolve_endpoint(self, host: str) -> str:
            raise NoEndpointError(f"{host} advertises no endpoint")

    class Flaky:
        def resolve_endpoint(self, host: str) -> str:  # noqa: ARG002
            raise httpx.ConnectError("connection refused")

    with pytest.raises(CallError) as verdict:
        face.run(
            face.client(_config(endpoint_resolver=Verdict()), Recorder({})).report_usage(
                {"exchange": "issuer.test"}
            )
        )
    assert verdict.value.kind is CallErrorKind.NOT_SENT

    # A momentary outage must not read as "we declined to send this, do not retry" — that
    # would permanently drop a usage report.
    with pytest.raises(CallError) as flaky:
        face.run(
            face.client(_config(endpoint_resolver=Flaky()), Recorder({})).report_usage(
                {"exchange": "issuer.test"}
            )
        )
    assert flaky.value.kind is CallErrorKind.UNREACHABLE


# ---------------------------------------------------------------------------
# the broker face, outbound validation, fetch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_broker_refuses_locally_with_no_requester(face: Face) -> None:
    broker = face.broker(_config(requester=None, base_url="https://broker.test"), Recorder({}))
    with pytest.raises(CallError) as excinfo:
        face.run(broker.resolve({}))
    assert excinfo.value.kind is CallErrorKind.MALFORMED


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_whole_call_absence_reason_is_an_answer_not_a_failure(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "absence_reason": "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"})
    broker = face.broker(_config(base_url="https://broker.test"), rec)

    result = face.run(broker.resolve({"uris": ["https://site.test/a"]}))

    assert str(rec.seen[0].url) == "https://broker.test/ramp.v1.BrokerService/Resolve"
    assert result.absence_reason == "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"
    assert result.groups == []
    # A DiscoveryResponse names no single Exchange; each offer carries its own.
    assert result.exchange == ""


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_request_the_server_could_only_reject_is_refused_before_it_is_sent(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "exchange": "exchange.test"})
    client = face.client(_config(), rec)

    # ResourceQuery.exchange is required: the contract makes every addressed request name
    # its recipient, so a query without one has exactly one possible answer.
    with pytest.raises(CallError) as excinfo:
        face.run(client.discover({}))
    assert excinfo.value.kind is CallErrorKind.MALFORMED
    assert rec.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_validation_off_sends_it_anyway(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "exchange": "exchange.test"})
    client = face.client(_config(validation="off"), rec)

    face.run(client.discover({}))

    assert len(rec.seen) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_fetch_refuses_without_the_key_the_url_is_bound_to(face: Face) -> None:
    # The delivery URL is bound to the thumbprint of the request-signing key, so the
    # signer IS the key a bound fetch proves possession of.
    client = face.client(_config(signer=None), Recorder({}))
    with pytest.raises(CallError) as excinfo:
        face.run(client.fetch("https://edge.test/x"))
    assert excinfo.value.kind is CallErrorKind.NOT_SIGNABLE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_fetch_presents_the_proof_and_returns_the_bytes(face: Face) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-ramp-agent-key"]
        assert request.headers["signature-input"].startswith("sig1=")
        return httpx.Response(
            200,
            content=b"the bytes",
            headers={"content-type": "text/plain; charset=utf-8"},
        )

    transport = httpx.MockTransport(respond)
    config = _config()
    client = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )

    content = face.run(client.fetch("https://edge.test/x?sig=abc"))

    assert content.body == b"the bytes"
    # The charset belongs to whoever decodes the bytes; the content carries the media type.
    assert content.mime_type == "text/plain"
    assert content.url == "https://edge.test/x?sig=abc"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_edge_refusal_carries_its_typed_reason(face: Face) -> None:
    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(403, json={"error": "denied", "reason": "url_expired"})

    transport = httpx.MockTransport(respond)
    config = _config()
    client = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )

    with pytest.raises(CallError) as excinfo:
        face.run(client.fetch("https://edge.test/x"))

    err = excinfo.value
    assert err.kind is CallErrorKind.REFUSED
    assert err.reason_of() == "url_expired"
    assert err.detail is not None
    assert (
        err.detail.retrieval_auth_failure.reason.value
        == "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED"
    )


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_untokenlike_edge_reason_falls_back_to_the_failure_class(face: Face) -> None:
    """The refusal body is written by the host just fetched from, so a value that is not
    token-shaped must not render as though the SDK had said it."""

    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(403, json={"reason": "Access denied by our WAF. Contact support."})

    transport = httpx.MockTransport(respond)
    config = _config()
    client = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )

    with pytest.raises(CallError) as excinfo:
        face.run(client.fetch("https://edge.test/x"))

    assert excinfo.value.reason_of() == "refused"
    assert excinfo.value.detail is None


# The protocol carries ONE agent identity: agent_identity_hash is the thumbprint of the
# request-signing key and the delivery URL is bound to it, so a proof minted under any
# other key presents an identity the URL was not issued to and the edge refuses it. This
# asserts the key the client actually proves possession of.
#
# Mirrors sdk/ts/tests/client.test.ts "proves possession of the SIGNER's key".
@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_fetch_proves_possession_of_the_signers_key_not_a_second_one(face: Face) -> None:
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    expected = base64.urlsafe_b64encode(
        Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
    ).rstrip(b"=").decode()

    recorder = Recorder({"https://edge.test/x": (200, "body", {"content-type": "text/plain"})})
    client = face.client(_config(), recorder)
    face.run(client.fetch("https://edge.test/x"))

    presented = recorder.seen[0].headers.get("x-ramp-agent-key")
    assert presented, "no proof header reached the edge"
    assert presented == expected, (
        "the delivery proof was minted under a key other than the request signer's"
    )


# reset_at is handed back as the peer spelled it, because it is the one member the parse
# cannot return unchanged: Pydantic reads it into a datetime and re-renders it, and that
# round trip is not the identity — ".123Z" comes back ".123000Z", nanosecond precision is
# truncated, "+00:00" becomes "Z". TypeScript validates it as a plain string and hands back
# what it was given, so the peer's own spelling is what the two agree on.
@pytest.mark.parametrize(
    "reset_at",
    [
        "2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00.123Z",
        "2099-01-01T00:00:00.123456789Z",
        "2099-01-01T00:00:00+00:00",
    ],
)
def test_a_rate_limit_is_handed_back_as_the_peer_sent_it(reset_at: str) -> None:
    from ramp_sdk.client import _verbs

    plan = _verbs.Plan(
        op="discover", url="u", body=b"", headers={}, timeout=1.0, max_bytes=1 << 20, sent={}
    )
    body = json.dumps(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            "rate_limit": {"reset_at": reset_at, "remaining": 5},
        }
    )
    result = _verbs.finish_discover(_verbs.ClientConfig(base_url="https://e.test"), plan, 200, body)
    assert result.rate_limit is not None
    assert result.rate_limit["reset_at"] == reset_at


# Every OTHER member comes from the parse, which is what the other two SDKs answer with —
# Go hands back the decoded message and TypeScript's schema coerces and strips the same two
# ways. Answering from the wire made Python the odd one of the three: it said "300" where
# they said 300, and kept a vendor key they both dropped.
def test_a_rate_limits_other_members_are_the_decoded_ones() -> None:
    from ramp_sdk.client import _verbs

    plan = _verbs.Plan(
        op="discover", url="u", body=b"", headers={}, timeout=1.0, max_bytes=1 << 20, sent={}
    )
    body = json.dumps(
        {
            "ver": "1.0",
            "exchange": "exchange.test",
            # proto3 JSON lets an int32 travel as a string, so this needs no hostile peer.
            "rate_limit": {"limit": "300", "remaining": 299, "vendor_extra": "x"},
        }
    )
    result = _verbs.finish_discover(_verbs.ClientConfig(base_url="https://e.test"), plan, 200, body)
    assert result.rate_limit is not None
    assert result.rate_limit["limit"] == 300, "a string-spelled int32 reached the caller"
    assert result.rate_limit["remaining"] == 299
    assert "vendor_extra" not in result.rate_limit, "an undeclared member reached the caller"
