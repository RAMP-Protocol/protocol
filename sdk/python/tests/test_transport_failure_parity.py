"""Transport-failure parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors sdk/ts/tests/transport-failure.parity.test.ts and the Go leg
sdk/go/connect/transport_failure_corpus_test.go.

The connect-error corpus records what a RAMP SERVICE says when it refuses. This one
records the other half: what reaches a client when the answer did not come from the
service at all — a load balancer draining, a gateway with no upstream, a proxy returning
its own HTML page. None of those is a Connect envelope.

The distinction is the point. "The Exchange declined this" is final; "nothing answered" is
transient. Report a momentary 502 as a refusal and a caller stops retrying a usage report
that would have succeeded a second later — the outcome the routing module argues at length
must not happen. connect-go already decides this by deriving the code from the HTTP status,
and the corpus is captured from a real client rather than transcribing that table.
"""

from __future__ import annotations

from typing import Any

import pytest

from conftest import GO_CONNECT_TESTDATA, load_json
from ramp_sdk.client._call import decode
from ramp_sdk.client.errors import CallError, CallErrorKind
from wire.models import ResourceResponse

_VECTORS: list[dict[str, Any]] = load_json(
    GO_CONNECT_TESTDATA / "transport-failure-vectors.json"
)["transport_failures"]


def test_transport_failure_vector_set_covers_both_sides() -> None:
    assert _VECTORS
    kinds = {v["kind"] for v in _VECTORS}
    assert "unreachable" in kinds, "no transient vector — half the distinction is unasserted"
    assert kinds - {"unreachable"}, "no final vector — the other half is unasserted"


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_an_answer_that_did_not_come_from_the_service(vector: dict[str, Any]) -> None:
    with pytest.raises(CallError) as caught:
        decode("discover", vector["status"], vector["body"], ResourceResponse)
    failure = caught.value

    assert failure.kind is CallErrorKind[vector["kind"].upper()], (
        f"{vector['name']}: classed {failure.kind.name}, oracle says {vector['kind']}"
    )
    assert failure.reason == vector["reason"]
    # The label and the consequence are pinned together: comparing only the string would
    # still pass if the two classes swapped meanings.
    assert (failure.kind is CallErrorKind.UNREACHABLE) is vector["retryable"]


# A redirect this client refused to follow. Every leg refuses, so a 3xx reaching the decode
# means the server did not answer the call rather than declining it — which is what all
# three failure taxonomies already document a redirect as. It is not in the captured corpus
# because connect-go never sees one: its transport follows redirects, so the row is
# unreachable there rather than decided.
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_refused_redirect_is_unreachable_not_refused(status: int) -> None:
    with pytest.raises(CallError) as caught:
        decode("discover", status, "", ResourceResponse)
    assert caught.value.kind is CallErrorKind.UNREACHABLE
