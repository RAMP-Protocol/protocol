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

from typing import Any

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
