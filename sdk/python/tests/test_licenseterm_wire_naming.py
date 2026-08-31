"""A camelCase entry is refused, not silently accepted with its fields dropped.

This one rule has no shared vector and cannot get one from the Go oracle: protojson
ACCEPTS both spellings, so Go has no refusal to record. The refusal is a property of the
two JSON ports, whose generated models ignore what they do not recognise — an entry
spelled ``contentId`` would otherwise validate cleanly into a message with every
multiword field missing, and the pre-check would answer ok for a feed the Exchange will
read as empty. Stock ``protojson.Marshal`` emits exactly that spelling, so it is the
ordinary output of the obvious way to generate a feed.

The null half of the same policy IS corpus-pinned (licenseterm-vectors.json carries the
wire_form entries), so only this half needs saying by hand.

Mirrors sdk/ts/tests/licenseterm-wire-naming.test.ts.
"""

from __future__ import annotations

from typing import Any

from wire.base import JSON_NAME_ALIAS_ERROR

from ramp_sdk.licenseterm import validate_resource_entry

_ALIAS_RULE = f"field.{JSON_NAME_ALIAS_ERROR}"

_SNAKE: dict[str, Any] = {
    "content_id": "a-42",
    "domain": "publisher.example",
    "path": "/premium/article-42.html",
}


def test_the_alias_is_refused_and_the_rule_is_named() -> None:
    verdict = validate_resource_entry(
        {
            "contentId": "a-42",
            "domain": "publisher.example",
            "path": "/premium/article-42.html",
        }
    )

    assert not verdict.ok
    violations = [v for v in verdict.violations if v.rule == _ALIAS_RULE]
    assert violations, f"no naming refusal in {verdict.violations}"
    # Reported at the message that carried the key, which for a root field is "".
    assert violations[0].path == ""
    assert violations[0].token == ""
    assert "contentId" in violations[0].message


def test_an_alias_nested_inside_a_term_is_refused_too() -> None:
    entry = dict(_SNAKE)
    entry["terms"] = [
        {
            "semantics": "TERM_SEMANTICS_ENUMERATED",
            "pricing": {"model": "PRICING_MODEL_FREE", "rate": "0"},
            "partLabel": "chapter one",
        }
    ]

    verdict = validate_resource_entry(entry)

    assert not verdict.ok
    assert _ALIAS_RULE in [v.rule for v in verdict.violations]


def test_the_snake_case_spelling_of_the_same_entry_is_accepted() -> None:
    assert validate_resource_entry(dict(_SNAKE)).ok


def test_a_key_that_is_not_an_alias_stays_forward_compatible() -> None:
    """A field from a newer protocol version is dropped, never refused.

    Without this the rule above would read as "reject anything unrecognised", which is a
    different and much worse policy than the one the wire actually states.
    """
    entry = dict(_SNAKE)
    entry["from_a_later_version"] = 1

    assert validate_resource_entry(entry).ok
