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

import pytest

from ramp_sdk.hosts import host_anchored, host_of
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


def test_an_at_sign_outside_the_authority_is_not_redacted() -> None:
    """The redaction is conservative, not indiscriminate: a path is not a credential."""
    refusal = _endpoint_refusal("exchange.example", "https://exchange.example/p%zz@x")
    assert refusal is not None
    assert "p%zz@x" in refusal
