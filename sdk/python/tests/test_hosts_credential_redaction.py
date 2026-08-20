"""No refusal message carries a credential.

Mirrors the TypeScript sibling sdk/ts/tests/hosts-credential-redaction.test.ts.

The endpoint rule refuses a credential and says so WITHOUT naming the value, because
the value is the credential. That intent only holds if it survives every other way
the same reference can be refused: a control character, a backslash in the userinfo,
a malformed escape. Each of those is a parse failure, and a parse failure that named
the reference put the credential back into the message — into the logs of every
consumer resolving a manifest whose operator mistyped one.

The redaction lives in the parse's error constructor rather than in the rule, so it
also covers ``host_of`` and ``host_anchored``, which this SDK exports.

Message text is deliberately per-language — the shared corpus records a verdict and
never a message — so this is a behavioural test in each port rather than a vector.
The Go oracle still echoes here; that divergence is intentional and is not a parity
break.
"""

from __future__ import annotations

import httpx
import pytest

from ramp_sdk.hosts import host_anchored, host_of
from ramp_sdk.resolvers import WellKnownEndpointResolver
from ramp_sdk.resolvers.wellknown import _endpoint_refusal

_SECRET = "s3cr3t"  # noqa: S105 - a test fixture, not a credential

# Every shape that refuses a credential-bearing reference. The first parses and is
# refused BY THE RULE; the rest fail to parse, which is the path that leaked.
_CREDENTIAL_REFS = [
    f"https://u:{_SECRET}@exchange.example/v1",
    f"https://u:{_SECRET}@exchange.example\n/v1",
    f"https://u:{_SECRET}\\@evil.example/v1",
    f"https://u%zz:{_SECRET}@exchange.example/v1",
    f"u:{_SECRET}@exchange.example",
    f"https://u:{_SECRET}@",
    # Every shape above carries a well-formed prefix, so none of them can reach a
    # redactor that disagrees with the parse about where the authority starts.
    # These are that class: a "://" that is not a scheme separator, and an authority
    # opened by a bare "//" with no "://" in the reference at all.
    f"u:{_SECRET}@evil.example/x://a.example",
    f"ftp:{_SECRET}@a.example://x",
    f"u:{_SECRET}@a.example?q=x://y",
    f"u:{_SECRET}@a.example#f://y",
    f"//u:{_SECRET}@a.example",
    # A scheme may not begin with a digit, so the parse refuses this outright —
    # but the credential still sits behind a "://" that a laxer reader would take
    # for a separator. Pinned because a redactor that reads ONLY by the parse's
    # rule leaves it untouched.
    f"1https://u:{_SECRET}@a.example/",
]


@pytest.mark.parametrize("ref", _CREDENTIAL_REFS)
def test_the_endpoint_rule_never_echoes_a_credential(ref: str) -> None:
    refusal = _endpoint_refusal("exchange.example", ref)
    assert refusal is not None, "a credential-bearing endpoint must be refused"
    assert _SECRET not in refusal


@pytest.mark.parametrize("ref", _CREDENTIAL_REFS)
def test_the_exported_predicates_never_echo_a_credential(ref: str) -> None:
    """The rule is not the only caller: these are public faces of this SDK."""
    for call in (lambda: host_of(ref), lambda: host_anchored("exchange.example", ref)):
        try:
            call()
        except ValueError as exc:
            assert _SECRET not in str(exc)


def test_a_well_formed_credential_still_gets_the_rules_own_message() -> None:
    """Redaction must not flatten every refusal into one shape.

    A value that PARSES and carries userinfo is refused by the rule, and its message
    names the reason rather than the reference — which is what it did before, and
    what the parse-failure path was quietly bypassing.
    """
    refusal = _endpoint_refusal("exchange.example", f"https://u:{_SECRET}@exchange.example/v1")
    assert refusal == "host='exchange.example' advertises an endpoint carrying userinfo"


# The SERVING HOST, not the advertised endpoint. Every case above feeds the
# credential in as the endpoint, and no arrangement of them reaches this branch: a
# host carrying userinfo PARSES, so is_bare_host answers False instead of raising,
# and the refusal that names it is the resolver's own. That value is
# network-supplied in the real flow — it is the exchange domain an offer named.
@pytest.mark.parametrize(
    "host",
    [f"user:{_SECRET}@exchange.example", f"u:{_SECRET}@exchange.example:8443"],
)
def test_a_credential_in_the_serving_host_is_not_echoed(host: str) -> None:
    def unreachable(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        msg = "refused before the network, so the transport is never reached"
        raise AssertionError(msg)

    r = WellKnownEndpointResolver(http=httpx.Client(transport=httpx.MockTransport(unreachable)))
    with pytest.raises(ValueError) as caught:  # noqa: PT011 - the message IS the assertion
        r.resolve_endpoint(host)
    assert _SECRET not in str(caught.value)
    assert "not a bare host" in str(caught.value)


def test_an_at_sign_outside_the_authority_is_not_redacted() -> None:
    """The redaction is conservative, not indiscriminate: a path is not a credential."""
    refusal = _endpoint_refusal("exchange.example", "https://exchange.example/p%zz@x")
    assert refusal is not None
    assert "p%zz@x" in refusal
