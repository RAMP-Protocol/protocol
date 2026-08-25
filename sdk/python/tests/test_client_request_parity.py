"""Client-request parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors the sdk/ts sibling sdk/ts/tests/client-request.parity.test.ts and the Go leg
sdk/go/connect/client_request_corpus_test.go.

"The same verbs, with the same names" is the whole claim the three clients make to each
other, and neither half of it is visible from the exported surface the parity map
compares. A client can export ``report_usage`` and address the wrong RPC — a Connect unary
path is ``/<fully-qualified service>/<method>``, so a different method name reaches a
different endpoint, or none. And it can overwrite an idempotency key the caller supplied,
which turns each of their retries into a second report; the key identifies the ACTION, not
the attempt.

The body's BYTES are deliberately not pinned. Go serializes through protojson and this
client builds the object directly, so the same message legitimately renders differently.
What the corpus records is the envelope PROJECTION, which is the part that is a decision
rather than an encoding.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from conftest import GO_CONNECT_TESTDATA, load_json
from ramp_sdk.client import BrokerClient, Client, ClientConfig
from ramp_sdk.core import Mode, StaticOfferKeyResolver, Verifier, sign_offer_jcs
from ramp_sdk.idempotency import validate_idempotency_key
from ramp_sdk.signing_transport import SigningTransport

_VECTORS = load_json(GO_CONNECT_TESTDATA / "client-request-vectors.json")["vectors"]

_AGENT_SEED = bytes(range(32))
_EXCHANGE_SEED = bytes([7]) * 32
_REQUESTER = {"id": "agent-1", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"}
_ISSUER = "issuer.test"
_NOW = 1_700_000_000
#: The one key the corpus records verbatim; a minted key is fresh per call.
_PINNED = "idem-pinned-1"


class _Resolver:
    def resolve_endpoint(self, host: str) -> str:
        return f"https://api.{host}"


def _capture() -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ver": "1.0", "exchange": "exchange.test"})

    return httpx.AsyncClient(transport=httpx.MockTransport(respond)), seen


def _config() -> ClientConfig:
    return ClientConfig(
        base_url="https://exchange.test",
        requester=_REQUESTER,
        signer=SigningTransport(signer_seed=_AGENT_SEED, keyid="agent.v1"),
        endpoint_resolver=_Resolver(),
    )


def _verified_offer() -> Any:
    offer: dict[str, Any] = {
        "offer_id": "offer-good",
        "exchange": "exchange.test",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    signature, algorithm = sign_offer_jcs(seed=_EXCHANGE_SEED, offer=offer)
    signed = {**offer, "signature": signature, "signature_algorithm": algorithm}
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public = Ed25519PrivateKey.from_private_bytes(_EXCHANGE_SEED).public_key().public_bytes_raw()
    verifier = Verifier(
        mode=Mode.STRICT,
        resolver=StaticOfferKeyResolver({"exchange.test": public}),
        now=lambda: _NOW,
    )
    result = verifier.sort([signed])
    assert result.verified, result.rejected[0].reason if result.rejected else "no offer"
    return result.verified[0]


def _call(name: str) -> httpx.Request:
    """Run the verb a vector names and return what went on the wire."""
    http, seen = _capture()
    config = _config()
    if name.startswith("discover"):
        query: dict[str, Any] = {"exchange": "exchange.test"}
        if name == "discover_caller_ver_wins":
            query["ver"] = "9.9"
        asyncio.run(Client(config, http=http).discover(query))
    elif name.startswith("report_usage"):
        report: dict[str, Any] = {"exchange": _ISSUER, "transaction_id": "t-1"}
        if name == "report_usage_caller_key_wins":
            report["idempotency_key"] = _PINNED
        asyncio.run(Client(config, http=http).report_usage(report))
    elif name.startswith("dispute"):
        asyncio.run(
            Client(config, http=http).dispute(
                {
                    "exchange": _ISSUER,
                    "transaction_id": "t-1",
                    "report_id": "r-1",
                    "reason": "DISPUTE_REASON_DELIVERY_FAILED",
                },
                idempotency_key=_PINNED,
            )
        )
    elif name.startswith("execute"):
        asyncio.run(
            Client(config, http=http).execute(_verified_offer(), idempotency_key=_PINNED)
        )
    elif name == "resolve":
        asyncio.run(BrokerClient(config, http=http).resolve({}))
    else:  # pragma: no cover - a vector this replay does not know how to drive
        pytest.fail(f"no Python driver for vector {name!r}")
    return seen[0]


def test_client_request_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


def test_one_verb_addresses_one_rpc() -> None:
    """The ``verb`` column, which is the whole claim the three clients make to each other.

    "The same verbs, with the same names" only means something if a verb names ONE RPC. A
    client can export ``report_usage`` and address DisputeTransaction; the per-vector path
    assertion below cannot see that, because it compares each vector to its own recorded
    path. Grouping by verb is what catches one verb reaching two methods.
    """
    paths: dict[str, set[str]] = {}
    for vector in _VECTORS:
        paths.setdefault(vector["verb"], set()).add(vector["path"])
    ambiguous = {verb: sorted(p) for verb, p in paths.items() if len(p) > 1}
    assert not ambiguous, f"a verb addressing more than one RPC: {ambiguous}"


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_the_verb_addresses_the_same_rpc_and_stamps_the_same_envelope(
    vector: dict[str, Any],
) -> None:
    request = _call(vector["name"])
    body = json.loads(request.content)

    # A different method name reaches a different RPC, or none.
    assert request.url.path == vector["path"]
    assert body.get("ver") == vector["ver"]
    assert (body.get("requester") or {}).get("id", "") == vector["requester_id"]

    key = body.get("idempotency_key", "")
    if vector["key_minted"]:
        # A minted key's VALUE is fresh per call and so is not recorded; what the corpus
        # pins is that one was minted, and it must be a key the protocol accepts.
        assert key, "no idempotency key was minted"
        validate_idempotency_key(key)
        return
    assert key == vector["idempotency_key"], (
        "the caller's own idempotency key was not carried; discarding it turns each of "
        "their retries into a second action"
    )
