"""A recipient the wire will not carry is refused locally, without echoing a credential.

``is_bare_domain`` answers False for a value carrying userinfo — a verdict, not a parse
error — so the value reaches the message and would be echoed whole unless the refusal
redacts it. The routing check next door already redacts; this pins the catalog leg to the
same rule, in the language the Go oracle is mirrored into.

The other cases are the ones the ROUTING predicate would have waved through. Each is a
usable host and none is a value ``exchange`` may hold, so vetting with the wider rule
signed and sent a request the recipient could only refuse.

Mirrors sdk/ts/tests/catalog-recipient-redaction.test.ts.
"""

import asyncio

import pytest

from ramp_sdk.client import CatalogClient, ClientConfig
from ramp_sdk.client.errors import CallError

CREDENTIAL = "s3cr3t"
WITH_USERINFO = f"publisher:{CREDENTIAL}@exchange.test"


class _NeverSends:
    """The request must be refused before anything is sent.

    Modelled on the two members the client actually reaches — ``is_closed``, which it
    checks first, and ``stream``, which is its only send path. A double that stubs
    neither fails with an AttributeError on the way in, which looks like a refusal but
    is not one: it can never distinguish "refused before sending" from "sent".
    """

    is_closed = False

    def stream(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("the request must be refused before it is sent")


def _push(exchange: str) -> None:
    client = CatalogClient(ClientConfig(base_url="https://exchange.test"), http=_NeverSends())
    asyncio.run(
        client.push_resources(
            {
                "exchange": exchange,
                "tenant_id": "t",
                "caller_id": "c",
                "entries": [{"domain": "publisher.test", "path": "/x"}],
            }
        )
    )


def test_recipient_refusal_redacts_a_credential() -> None:
    with pytest.raises(CallError) as excinfo:
        _push(WITH_USERINFO)

    text = str(excinfo.value)
    assert CREDENTIAL not in text, f"the refusal repeats the credential: {text}"
    assert "[redacted]" in text, f"the refusal does not name the redaction: {text}"


@pytest.mark.parametrize(
    "exchange",
    ["_x.exchange.test", "exchange.test.", "[::1]:443", "https://exchange.test", "exchange.test/x"],
)
def test_a_recipient_the_wire_refuses_is_refused_before_signing(exchange: str) -> None:
    with pytest.raises(CallError, match="is not a bare domain"):
        _push(exchange)


@pytest.mark.parametrize("exchange", ["exchange.test", "exchange.test:8443", "edge"])
def test_a_conformant_recipient_is_not_refused(exchange: str) -> None:
    """The other half, or the check above would pass on a predicate that refuses all.

    A port is part of a bare domain and a single-label host is one. The send itself is
    what the double refuses, so reaching it is the assertion.
    """
    with pytest.raises(AssertionError, match="must be refused before it is sent"):
        _push(exchange)
