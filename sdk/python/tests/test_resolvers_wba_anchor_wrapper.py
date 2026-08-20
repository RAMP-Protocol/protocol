"""The WBA anchor wrapper, at the two things that are local to it.

Mirrors the TypeScript sibling in sdk/ts/tests/resolvers-wba.integration.test.ts.

The shared predicate is corpus-locked; what is NOT covered anywhere is the wrapper
around it, which adds exactly two behaviours — a bool answer in place of a raise,
and the requirement that a ``revocation_url`` be an ABSOLUTE reference. The second
matters: the shared predicate reads a schemeless value as https, which is right for
an exchange domain a caller named and wrong for a URL a directory published, where
inventing the scheme would decide the rule on the directory's behalf.

The regression the wrapper exists for is here too. An explicit non-default port on
both sides must still anchor; a predicate that folded the port away on one side only
stopped a directory anchoring its own revocation URL, and a skipped poll leaves a
revoked key resolving.
"""

from __future__ import annotations

import pytest

from ramp_sdk.resolvers.wba import _wba_host_anchored


@pytest.mark.parametrize(
    ("anchor", "candidate", "want"),
    [
        ("a.example", "https://a.example/rev.json", True),
        ("a.example", "https://sub.a.example/rev.json", True),
        # Absolute references only — a schemeless value is not anchored, rather than
        # being read as https and then anchoring.
        ("a.example", "a.example/rev.json", False),
        ("a.example", "/rev.json", False),
        # The port is compared, and an explicit one on both sides still anchors.
        ("a.example:8443", "http://a.example:8443/rev.json", True),
        ("a.example:8443", "http://a.example:9443/rev.json", False),
        ("a.example", "https://a.example:443/rev.json", True),
        # A reference the predicate cannot read is not anchored — it does not raise
        # out of the poller, which logs a skip and keeps the prior snapshot.
        ("a.example", "https://evil.example\\@a.example/rev.json", False),
        ("a.example", "https://", False),
        ("", "https://a.example/rev.json", False),
    ],
)
def test_wba_host_anchored(anchor: str, candidate: str, want: bool) -> None:
    assert _wba_host_anchored(anchor, candidate) is want
