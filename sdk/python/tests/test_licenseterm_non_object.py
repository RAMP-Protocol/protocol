"""A value that is not an entry gets a VERDICT, not an exception.

This one has no shared vector and cannot get one from the Go oracle: the Go face takes
a ``*rampv1.ResourceEntry``, so "a string where an entry should be" is not a value it
can construct, let alone marshal into a corpus. The behaviour is a property of the two
JSON ports, whose faces take whatever a caller parsed.

It is reachable the ordinary way. The pre-check exists for feeds, a JSONL line is parsed
before it is checked, and a malformed line parses to a string, a number, a list or None
just as easily as to a dict. Answering that with a raised ``AttributeError`` rather than
a verdict makes a publisher's loop over a feed die on the first bad row instead of
reporting it beside the others.

The rule id is deliberately NOT asserted equal to TypeScript's. Field-level wire
violations carry each engine's own vocabulary — Pydantic's error types here, Zod's issue
codes there — which is the recorded reason the shared corpus compares them as a boolean.
What the two ports owe each other is the SHAPE of the answer: a verdict, refused, with at
least one violation.

Mirrors sdk/ts/tests/licenseterm-non-object.test.ts.
"""

from __future__ import annotations

from typing import Any

import pytest

from ramp_sdk.licenseterm import validate_resource_entry


@pytest.mark.parametrize(
    ("label", "value"),
    [("None", None), ("a string", "not-an-entry"), ("a number", 5), ("a list", [])],
)
def test_refuses_a_non_object_with_a_verdict(label: str, value: Any) -> None:
    verdict = validate_resource_entry(value)
    assert not verdict.ok, f"{label} must be refused"
    assert verdict.violations, f"{label} must carry at least one violation"
    assert verdict.warnings == []


def test_a_real_entry_is_still_valid() -> None:
    """The guard must not have swallowed the walk it stands in front of."""
    assert validate_resource_entry({"domain": "e.co", "path": "/a"}).ok
