"""The wire policy the generated models are validated under — ``wire.base.WireModel``.

Mirrors ``gen/ts/tests/wire_policy.test.ts``.

Two rules. A ``null`` means the field has no value — the canonical wire is proto-JSON,
where that is true of any field and not only a message-typed one — and a lowerCamelCase
answer is refused rather than silently validated into a message with every multiword field
missing.

Python needs no walk for either: ``X | None`` is already how the generated models spell
every field that may be unset, and every nested model inherits ``WireModel``, so the
refusal recurses by inheritance. The TypeScript twin has to do both itself, which is why
its file is longer — and why the null rule was wrong there and right here: it was written
against fields that LOOK like messages, and the type generator flattens a timestamp to a
string.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from wire.base import JSON_NAME_ALIAS_ERROR
from wire.models import Offer, ResourceResponse, TransactionResponse, UsageReportResponse

# Captured from connectserver.EmitUnpopulatedJSONCodec() — the codec a RAMP deployment
# registers. Every unset message field is `null`.
CODEC_BODIES: list[tuple[str, type[BaseModel], str]] = [
    (
        "ResourceResponse",
        ResourceResponse,
        '{"ver":"", "exchange":"exchange.test", "offers":[], "offer_groups":[], '
        '"ext":null, "ext_critical":[]}',
    ),
    (
        "TransactionResponse",
        TransactionResponse,
        '{"ver":"1.0", "agent_identity_hash":"", "items":[], "subscription_quota":[], '
        '"ext":null, "ext_critical":[]}',
    ),
    (
        "UsageReportResponse",
        UsageReportResponse,
        '{"ver":"", "report_id":"", "ext":null, "ext_critical":[]}',
    ),
]


@pytest.mark.parametrize(("name", "model", "body"), CODEC_BODIES, ids=[c[0] for c in CODEC_BODIES])
def test_an_unset_message_field_arrives_as_null(name: str, model: type[BaseModel], body: str) -> None:
    parsed = model.model_validate(json.loads(body))
    assert getattr(parsed, "ext", "missing") is None, name


def test_a_nested_message_field_too() -> None:
    assert Offer.model_validate({"offer_id": "o", "exchange": "e.test", "pricing": None})


def test_and_one_inside_a_repeated_message() -> None:
    parsed = TransactionResponse.model_validate(
        {"ver": "1.0", "items": [{"transaction_id": "t", "cost": None}]}
    )
    assert parsed.items is not None
    assert parsed.items[0].cost is None


def test_a_null_inside_an_open_map_is_a_value_and_survives() -> None:
    # Struct carries NullValue, so a null there is data the caller sent, not an absence.
    parsed = Offer.model_validate(
        {"offer_id": "o", "exchange": "e.test", "ext": {"nested": None}}
    )
    assert parsed.ext == {"nested": None}


def _alias_refusal(model: type[BaseModel], body: dict[str, Any]) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        model.model_validate(body)
    assert any(err["type"] == JSON_NAME_ALIAS_ERROR for err in caught.value.errors()), (
        f"refused, but not as a wire-naming failure: {caught.value.errors()}"
    )
    return caught.value


def test_a_lowercamelcase_answer_is_refused_at_the_root() -> None:
    _alias_refusal(ResourceResponse, {"ver": "1.0", "exchange": "e.test", "offerGroups": []})


def test_and_one_level_down_where_the_dispute_chain_starts() -> None:
    # The root-only version of this check could not see the case that matters. A stock
    # connect-go server omits unset fields, so TransactionResponse arrives as
    # {ver, items} — every root key a single word, identical in both spellings — while
    # transaction_id sits one level down and is dropped, reading as a purchase that
    # succeeded with no transaction id and no delivery URL.
    _alias_refusal(
        TransactionResponse,
        {
            "ver": "1.0",
            "items": [
                {"transactionId": "t", "offerId": "o", "retrievalEndpoint": "https://edge/x"}
            ],
        },
    )


def test_but_an_open_maps_keys_are_data_not_field_names() -> None:
    assert Offer.model_validate(
        {"offer_id": "o", "exchange": "e.test", "ext": {"someCamelKey": 1, "offerId": 2}}
    )


def test_and_a_field_a_newer_version_added_is_accepted_and_dropped() -> None:
    parsed = Offer.model_validate(
        {"offer_id": "o", "exchange": "e.test", "__unknown_future_field__": 1}
    )
    assert not hasattr(parsed, "__unknown_future_field__")


def test_a_model_built_from_python_objects_is_left_alone() -> None:
    # The validator also runs on construction, where the names are already field names.
    assert Offer(offer_id="o", exchange="e.test")
