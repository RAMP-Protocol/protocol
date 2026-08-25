"""Data a peer controls produces a typed failure, never a raw exception.

Mirrors sdk/ts/tests/hostile-response-data.test.ts.

Both languages document that every verb raises exactly one failure type. Three places
broke that, and each is reached from bytes a peer chose:

* a ``debug`` projection that is a well-formed object but not an ErrorDetail — read on
  EVERY non-2xx, which is exactly where a hostile peer operates;
* a ``debug`` projection nested deeper than the reader's recursion allows;
* a ``details`` member that is not a list of entries at all;
* an offer-key resolver that raises, which the shipped resolvers do on a network failure;
* a wire key naming an inherited object member (``__proto__``, ``constructor``).

The third is TypeScript-only — Python's dict lookup has no prototype chain — but the
first two are shared, so the assertions are.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ramp_sdk.core import Mode, Verifier
from ramp_sdk.errordetail import error_detail_from, reason

_HOSTILE = {"domain": 123, "message": ["not", "a", "string"]}
_GOOD = {
    "domain": "d",
    "message": "m",
    "transactionDenial": {"reason": "DENIAL_REASON_INSUFFICIENT_BALANCE"},
}


def _envelope(*debugs: dict[str, Any]) -> dict[str, Any]:
    return {"details": [{"type": "ramp.v1.ErrorDetail", "debug": d} for d in debugs]}


def test_a_debug_projection_that_does_not_decode_is_not_an_answer() -> None:
    # It reached the reader off a refusal the peer just sent. Raising here would replace
    # the typed failure the caller is about to receive with an untyped one.
    assert error_detail_from(_envelope(_HOSTILE)) is None


def test_and_the_scan_keeps_going_past_it() -> None:
    # `details` is a list; an entry that does not decode says nothing about the next.
    detail = error_detail_from(_envelope(_HOSTILE, _GOOD))
    assert detail is not None
    assert detail.domain == "d"
    assert reason(detail) is not None


class _Raising:
    """The shape the shipped resolvers take on a network failure."""

    def resolve(self, exchange: str) -> bytes | None:
        raise RuntimeError(f"key endpoint unreachable for {exchange}")


def test_a_raising_key_resolver_rejects_one_offer_not_the_whole_answer() -> None:
    # On a Broker fan-out the exchange comes off a relayed offer, so one Exchange whose
    # key endpoint hangs would otherwise deny the agent every offer in the response — and
    # as an untyped exception out of a call that promises a typed one. Go returns the
    # resolver's error as that offer's rejection reason and moves on.
    verifier = Verifier(mode=Mode.STRICT, resolver=_Raising(), now=lambda: 1_700_000_000)
    result = verifier.sort(
        [{"exchange": "a.test", "signature": "00"}, {"exchange": "b.test", "signature": "00"}]
    )
    assert not result.verified
    assert len(result.rejected) == 2
    assert "key endpoint unreachable" in result.rejected[0].reason


# A real ErrorDetail nests two deep. The bound is the same 32 the protocol sets for a third
# party's JSON in AccountRegistration.data_schema, so one number covers "how deep may a
# stranger's document be".
@pytest.mark.parametrize(
    ("depth", "readable"),
    [(2, True), (30, True), (1200, False), (20_000, False)],
)
def test_a_debug_projection_deeper_than_the_bound_is_not_an_answer(
    depth: int, readable: bool
) -> None:
    nested: dict[str, Any] = {}
    cursor = nested
    for _ in range(depth):
        cursor["a_b"] = {}
        cursor = cursor["a_b"]
    detail = error_detail_from(_envelope({**_GOOD, "extra": nested}))
    assert (detail is not None) is readable, (
        f"depth {depth}: recursing to the interpreter's limit raises out of a reader that "
        "promises a value"
    )


@pytest.mark.parametrize("details", [None, 5, True, "a string"])
def test_a_details_member_that_is_not_a_list_of_entries(details: Any) -> None:
    # `details` is the peer's. Iterating a value that is not a list raised TypeError out of
    # the reader, on the path every non-2xx takes.
    assert error_detail_from({"details": details}) is None


def test_a_call_on_a_closed_client_is_a_typed_refusal() -> None:
    # httpx raises a bare RuntimeError here. Nothing was sent, which is what NOT_SENT means.
    from ramp_sdk import sync as blocking
    from ramp_sdk.client import ClientConfig
    from ramp_sdk.client.errors import CallError, CallErrorKind
    from ramp_sdk.signing_transport import SigningTransport

    config = ClientConfig(
        base_url="https://exchange.test",
        requester={"id": "a", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"},
        signer=SigningTransport(signer_seed=bytes(range(32)), keyid="agent.v1"),
    )
    client = blocking.Client(config)
    client.close()
    for call in (lambda: client.discover({"exchange": "e.test"}),
                 lambda: client.fetch("https://edge.test/x")):
        with pytest.raises(CallError) as caught:
            call()
        assert caught.value.kind is CallErrorKind.NOT_SENT


def _response_nesting(total: int) -> str:
    """A CONFORMANT ResourceResponse body whose deepest container is ``total`` deep.

    The root object is one, ``ext`` is two, and each further object adds one.

    ``ext`` is the carrier because it is a ``google.protobuf.Struct``: how deep it goes is
    the peer's choice and nothing in the contract bounds it, which is what makes this the
    reachable shape rather than a contrived one. A bare array is malformed at every depth,
    so a test built on one asserts a typed failure the schema produces on its own — true
    whatever the bound is set to, which is how this pair of assertions used to pass with the
    number mutated to anything at all.
    """
    nested: dict[str, Any] = {}
    cursor = nested
    for _ in range(total - 2):
        cursor["k"] = {}
        cursor = cursor["k"]
    return json.dumps({"ver": "1.0", "exchange": "e.test", "ext": nested})


def test_a_body_at_the_depth_bound_is_read() -> None:
    from ramp_sdk._jsondepth import _MAX_BODY_DEPTH
    from ramp_sdk.client._call import decode
    from wire.models import ResourceResponse

    msg = decode("discover", 200, _response_nesting(_MAX_BODY_DEPTH), ResourceResponse)
    assert msg.exchange == "e.test"


# One container past the bound, refused FOR ITS DEPTH rather than for anything else about
# it — which is what makes the number load-bearing. Both status bands, because the parse
# runs before the status is consulted: this is reachable on the SUCCESS path too, not only
# where a hostile peer is expected.
@pytest.mark.parametrize("status", [200, 500])
def test_a_body_one_past_the_depth_bound_is_refused_for_its_depth(status: int) -> None:
    from ramp_sdk._jsondepth import _MAX_BODY_DEPTH
    from ramp_sdk.client._call import decode
    from ramp_sdk.client.errors import CallError

    from wire.models import ResourceResponse

    with pytest.raises(CallError) as caught:
        decode("discover", status, _response_nesting(_MAX_BODY_DEPTH + 1), ResourceResponse)
    assert f"deeper than {_MAX_BODY_DEPTH}" in str(caught.value)


# The parse ABOVE the normalizer, which an earlier round left unguarded. json.loads
# descends recursively and raises RecursionError on a deep document — not a ValueError, so
# the handler never caught it, and not a failure this package says it raises. A 40 KB body,
# far under the 1 MiB read cap, threw an untyped exception out of every verb.
@pytest.mark.parametrize("status", [200, 500])
def test_a_body_deep_enough_to_exhaust_the_parser_is_still_typed(status: int) -> None:
    from ramp_sdk.client._call import decode
    from ramp_sdk.client.errors import CallError
    from wire.models import ResourceResponse

    body = "[" * 20_000 + "]" * 20_000
    with pytest.raises(CallError):
        decode("discover", status, body, ResourceResponse)


# The delivery leg's own reader of a peer's bytes, which the response reader's guard did
# not cover. Driven through the FULL verb rather than the reader, because what broke was the
# contract the verb states: every one of them raises CallError and nothing else. The body is
# 2400 bytes, well under the 4 KiB refusal cap — the cap bounds the SIZE and says nothing
# about the nesting, and how much nesting a parser survives is a property of the release
# rather than a verdict. Measured: this raised RecursionError out of Client.fetch on one
# supported interpreter and decoded fine on the next.
def test_a_deeply_nested_refusal_body_is_a_typed_failure_with_no_token() -> None:
    from ramp_sdk import sync as blocking
    from ramp_sdk.client import ClientConfig
    from ramp_sdk.client.errors import CallError, CallErrorKind
    from ramp_sdk.signing_transport import SigningTransport

    # A WELL-FORMED refusal carrying a token the SDK would otherwise repeat, with the
    # nesting beside it. That is what separates the guard from the absence of one: drop the
    # guard and this body still parses on a release whose limit it does not reach, and the
    # token comes back.
    depth = 1200
    hostile = ('{"reason":"url_expired","x":' + "[" * depth + "]" * depth + "}").encode()
    assert len(hostile) < 4 << 10, "the point is that the size cap does not bound the nesting"

    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(403, content=hostile)

    config = ClientConfig(
        base_url="https://exchange.test",
        requester={"id": "a", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"},
        signer=SigningTransport(signer_seed=bytes(range(32)), keyid="agent.v1"),
    )
    client = blocking.Client(config, http=httpx.Client(transport=httpx.MockTransport(respond)))
    with pytest.raises(CallError) as caught:
        client.fetch("https://edge.test/x")
    # The edge said no, so the class is the SDK's own — and the token, which is the one part
    # of a refusal the SDK does not own, is absent rather than invented.
    assert caught.value.kind is CallErrorKind.REFUSED
    assert caught.value.reason is None


def test_the_depth_bound_admits_every_real_message() -> None:
    """The bound has to be above the contract, or it refuses conformant answers.

    The deepest instance in the whole conformance corpus is 5 containers; the bound is 32,
    the number the protocol already sets for a stranger's JSON.
    """
    import pathlib

    from ramp_sdk._jsondepth import _MAX_BODY_DEPTH, _raw_nesting_depth

    corpus = pathlib.Path(__file__).resolve().parents[3] / "conformance" / "corpus" / "cases.json"
    deepest = max(
        _raw_nesting_depth(json.dumps(case["json"]).encode())
        for case in json.loads(corpus.read_text())
    )
    assert deepest < _MAX_BODY_DEPTH, (
        f"the deepest contract instance nests {deepest} and the bound is {_MAX_BODY_DEPTH}"
    )
