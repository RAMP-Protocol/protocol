"""A recipient carrying userinfo is refused without repeating the credential.

``is_bare_host`` answers False for such a value — a verdict, not a parse error — so
the value reaches the message and would be echoed whole unless the refusal redacts
it. The routing check next door already redacts; this pins the catalog leg to the
same rule, in the language the Go oracle is mirrored into.
"""

import asyncio

import pytest

from ramp_sdk.client import CatalogClient, ClientConfig

CREDENTIAL = "s3cr3t"
WITH_USERINFO = f"publisher:{CREDENTIAL}@exchange.test"


class _NeverSends:
    """The request must be refused before anything is sent."""

    async def post(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
        raise AssertionError("the request must be refused before it is sent")


def test_recipient_refusal_redacts_a_credential() -> None:
    client = CatalogClient(ClientConfig(base_url="https://exchange.test"), http=_NeverSends())

    with pytest.raises(Exception) as excinfo:  # noqa: PT011 — the SDK's own CallError
        asyncio.run(
            client.push_resources(
                {
                    "exchange": WITH_USERINFO,
                    "tenant_id": "t",
                    "caller_id": "c",
                    "entries": [{"domain": "publisher.test", "path": "/x"}],
                }
            )
        )

    text = str(excinfo.value)
    assert CREDENTIAL not in text, f"the refusal repeats the credential: {text}"
    assert "[redacted]" in text, f"the refusal does not name the redaction: {text}"
