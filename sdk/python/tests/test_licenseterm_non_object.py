"""An ill-typed value gets a VERDICT, not an exception, and is not mistaken for a
well-typed one.

Neither case here has a shared vector, and neither can get one from the Go oracle: the
Go face takes a ``*rampv1.ResourceEntry``, so "a string where an entry should be" is not
a value it can construct, and ``Restriction.permitted`` is ``[]string``, so "a number
where a token should be" is not either — let alone marshal into a corpus. The behaviour is a property of the two
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

from ramp_sdk.licenseterm import (
    RULE_RESTRICTION_CANONICAL_DISJOINT,
    validate_license_term,
    validate_resource_entry,
)


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


# The same division one level down, on the restriction token lists.
#
# Every other check in the module skips an empty token, on the reasoning that an empty
# string is the wire tier's business. The canonical-disjointness check cannot skip it —
# two empty strings really are one token named on both sides, which is what the Go
# oracle answers — so it has to tell an EMPTY token from an ILL-TYPED one. Coercing the
# latter to "" would report a collision on the empty token and name the wrong fault,
# while the real fault, "this element is not a string", is what the wire tier already
# reports beside it.
def _term(permitted: list[Any], prohibited: list[Any]) -> dict[str, Any]:
    return {
        "restrictions": [
            {"kind": "RESTRICTION_KIND_FUNCTION", "permitted": permitted, "prohibited": prohibited}
        ]
    }


def test_ill_typed_elements_are_not_a_collision_on_the_empty_token() -> None:
    assert validate_license_term(_term(["ai-train", 5], ["search", None])).violation is None


def test_a_token_named_on_both_sides_is_still_refused() -> None:
    violation = validate_license_term(_term(["scrape", 5], ["crawl", None])).violation
    assert violation is not None
    assert violation.rule == RULE_RESTRICTION_CANONICAL_DISJOINT
    assert violation.token == "crawl"


def test_the_empty_token_still_collides() -> None:
    """Two empty strings are one token named on both sides; the Go oracle refuses them."""
    violation = validate_license_term(_term([""], [""])).violation
    assert violation is not None
    assert violation.rule == RULE_RESTRICTION_CANONICAL_DISJOINT
    assert violation.token == ""
