"""The delivery leg refuses a URL it cannot use, before anything is spent on it.

Mirrors the checks sdk/ts/client/content.ts and sdk/go/resolvers/contentfetch.go already
made and Python did not.

Two refusals. A value that is not a URL is a caller error, and this is the only place it
can be named — everything downstream treats the string as opaque bytes. A URL that does
not RE-SERIALIZE to itself is the subtler one: the proof covers ``@target-uri`` verbatim
while the request line carries whatever the transport re-serializes, and the signed-URL
contract treats scheme/host/path as opaque, so an Exchange can legitimately mint a URL the
two disagree on. The signature then cannot verify and the edge answers an undifferentiated
403, so naming the cause locally is the difference between a diagnosable failure and a
mystery.

Neither message may echo the URL: its query IS a live credential.
"""

from __future__ import annotations

import pytest

from ramp_sdk.client.content import vet_signed_url
from ramp_sdk.client.errors import CallError, CallErrorKind

_CREDENTIAL = "live-credential-value"


def test_a_usable_url_passes() -> None:
    vet_signed_url(f"https://edge.test/a?sig=aA-_1.~&token={_CREDENTIAL}")


@pytest.mark.parametrize(
    ("name", "url"),
    [
        ("not a url at all", "not-a-url"),
        ("no host", f"/relative/path?token={_CREDENTIAL}"),
        ("no scheme", f"edge.test/a?token={_CREDENTIAL}"),
        # httpx percent-encodes the space, so what reaches the request line is not what
        # the proof covered.
        ("not round-trip stable", f"https://edge.test/a b?token={_CREDENTIAL}"),
    ],
)
def test_an_unusable_url_is_refused_without_echoing_it(name: str, url: str) -> None:
    with pytest.raises(CallError) as caught:
        vet_signed_url(url)
    assert caught.value.kind is CallErrorKind.MALFORMED, name
    assert _CREDENTIAL not in str(caught.value), f"{name}: the refusal echoed the credential"


# The DELIVERY leg's redirect class, which was fixed on the RPC leg only. Worse than a wrong
# class: the refusal reader ran first and promoted a token out of the redirect body, so a 302
# carrying {"reason":"moved"} surfaced as though the edge had named a typed refusal.
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_delivery_redirect_is_unreachable_and_promotes_no_token(status: int) -> None:
    import httpx

    from ramp_sdk import sync as blocking
    from ramp_sdk.client import ClientConfig
    from ramp_sdk.signing_transport import SigningTransport

    def respond(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"location": "https://elsewhere.test/x", "content-type": "application/json"},
            json={"reason": "moved"},
        )

    config = ClientConfig(
        base_url="https://exchange.test",
        requester={"id": "a", "domain": "agent.test", "type": "REQUESTER_TYPE_AGENT"},
        signer=SigningTransport(signer_seed=bytes(range(32)), keyid="agent.v1"),
    )
    client = blocking.Client(config, http=httpx.Client(transport=httpx.MockTransport(respond)))
    with client, pytest.raises(CallError) as caught:
        client.fetch("https://edge.test/x")
    assert caught.value.kind is CallErrorKind.UNREACHABLE
    assert caught.value.reason is None, "a token was promoted out of a redirect body"
