"""The per-URI discovery shape (Python side) — mirror of sdk/go core.SortGroups.

Mirrors the sdk/ts sibling sdk/ts/tests/core-sort-groups.test.ts.

A discovery call is per-URI, and the answer has to stay that way. A URI that was REFUSED
carries no offer, so a flat list erases it: nothing survives to say which resource was
refused or why, and "not in the catalogue" (give up), "scope insufficient" (acquire an
entitlement and retry) and "content blocked" (never retry) all read alike as "found
nothing". These assert the grouping keeps that difference, and that the offers inside
each group go through the SAME Verifier — the fail-closed split is not re-implemented
per group, which is what "no second verification path" means.
"""

from __future__ import annotations

from typing import Any

from ramp_sdk.core import (
    DiscoveryResult,
    Mode,
    OfferGroupResult,
    StaticOfferKeyResolver,
    Verifier,
)

_NOW = 1_700_000_000


def _verifier(mode: Mode) -> Verifier:
    # An EMPTY key map: under STRICT nothing resolves, so every offer is rejected
    # fail-closed. That is what makes "the group's offers went through the Verifier"
    # observable without any key material.
    return Verifier(mode=mode, resolver=StaticOfferKeyResolver({}), now=lambda: _NOW)


def _group(uri: str, **rest: Any) -> dict[str, Any]:
    return {"uri": uri, **rest}


def test_every_requested_uri_keeps_its_group_and_its_reason() -> None:
    groups = _verifier(Mode.OFF).sort_groups(
        [
            _group("https://site.test/a", offers=[{"offer_id": "one"}]),
            _group("https://site.test/b", absence_reason="OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT"),
            _group(
                "https://site.test/c",
                absence_reason="OFFER_ABSENCE_REASON_RESTRICTION_FILTERED",
                restriction_filters=["RESTRICTION_KIND_GEOGRAPHY"],
            ),
        ],
    )

    assert [g.uri for g in groups] == [
        "https://site.test/a",
        "https://site.test/b",
        "https://site.test/c",
    ], "a group per requested URI, in the order the responder returned"
    assert len(groups[0].result.verified) == 1
    # The refusal is an ANSWER: the agent can tell "acquire an entitlement and retry"
    # from "give up" only because the reason survived.
    assert groups[1].absence_reason == "OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT"
    assert groups[1].result.verified == [] and groups[1].result.rejected == []
    assert groups[2].restriction_filters == ["RESTRICTION_KIND_GEOGRAPHY"]


def test_a_responder_that_stated_no_reason_says_nothing_rather_than_unspecified() -> None:
    (group,) = _verifier(Mode.OFF).sort_groups([_group("https://site.test/a")])
    assert group.absence_reason is None
    assert group.discovery_method is None
    assert group.restriction_filters == []


def test_group_offers_run_through_the_same_fail_closed_verifier() -> None:
    groups = _verifier(Mode.STRICT).sort_groups(
        [_group("https://site.test/a", offers=[{"exchange": "exchange.test", "signature": "00"}])],
    )
    assert groups[0].result.verified == [], "an unresolvable key must not verify"
    assert len(groups[0].result.rejected) == 1
    assert "no offer-signing key" in groups[0].result.rejected[0].reason


def test_a_non_group_element_is_skipped_rather_than_given_an_empty_uri() -> None:
    groups = _verifier(Mode.OFF).sort_groups([None, "not a group", 7, _group("https://site.test/a")])
    assert [g.uri for g in groups] == ["https://site.test/a"], (
        "a malformed element is nothing at all; surfacing it as an empty URI would "
        "invent an answer the responder never gave"
    )


def test_no_groups_yields_no_groups() -> None:
    assert _verifier(Mode.OFF).sort_groups([]) == []


def test_flatteners_span_groups_and_ignore_the_ones_that_carry_nothing() -> None:
    verifier = _verifier(Mode.OFF)
    result = DiscoveryResult(
        groups=verifier.sort_groups(
            [
                _group("https://site.test/a", offers=[{"offer_id": "one"}]),
                _group("https://site.test/b", absence_reason="OFFER_ABSENCE_REASON_NOT_IN_CATALOG"),
                _group("https://site.test/c", offers=[{"offer_id": "two"}]),
            ],
        ),
        exchange="exchange.test",
    )

    assert [v.offer["offer_id"] for v in result.verified()] == ["one", "two"]
    assert result.rejected() == []
    # The refused URI contributes nothing to the flattened view, which is exactly why
    # the flatteners are a convenience over `groups` and never a substitute for it.
    assert len(result.groups) == 3


def test_discovery_result_defaults_say_nothing() -> None:
    empty = DiscoveryResult()
    assert empty.groups == []
    assert empty.absence_reason is None
    assert empty.exchange == ""
    assert empty.rate_limit is None
    assert empty.verified() == [] and empty.rejected() == []
    assert OfferGroupResult().uri == ""
