"""Direct behavioral regression for the money wire-pattern (H1 / kb1s0.1).

Money on the wire is a pattern-constrained string: ^([0-9]+([.][0-9]+)?)?$
(Go keeps string.pattern; Zod keeps z.string().regex(...)). The generated
Pydantic models MUST enforce the identical rule so the three verdicts converge.

This exercises the REAL generated models (wire.models) through their public
parse surface (model_validate on proto-JSON dicts, which routes through
wire.base.WireModel) for all five money fields:
  Cost.amount, Cost.unitCost, RequestConstraints.maxUnitCost,
  Pricing.rate, Pricing.unitCost

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_money_pattern.py -q

It FAILS today: mark_money_decimal tags money `format: decimal`, so the
generator emits a bare `Decimal` that DROPS the sibling string.pattern.
Pydantic's Decimal wrongly ACCEPTS "-5"/"NaN"/"Infinity"/"1E3" and wrongly
REJECTS the valid empty string "".
"""
import pytest
from pydantic import ValidationError

import wire.models as models

# A minimal valid proto-JSON instance per money field, plus the field to inject
# into. Each tuple: (case_id, ModelClass, base_instance, money_field_name).
# Base instances carry only what the model REQUIRES so the money field is the
# sole rule under test.
MONEY_FIELDS = [
    ("Cost.amount", models.Cost, {}, "amount"),
    ("Cost.unitCost", models.Cost, {}, "unitCost"),
    (
        "RequestConstraints.maxUnitCost",
        models.RequestConstraints,
        {},
        "maxUnitCost",
    ),
    (
        "Pricing.rate",
        models.Pricing,
        {"model": models.PricingModel.PRICING_MODEL_PER_UNIT.value},
        "rate",
    ),
    (
        "Pricing.unitCost",
        models.Pricing,
        {"model": models.PricingModel.PRICING_MODEL_PER_UNIT.value},
        "unitCost",
    ),
]

# Values that VIOLATE ^([0-9]+([.][0-9]+)?)?$ and MUST be rejected. Each is a
# classic bare-Decimal footgun that a plain Decimal wrongly accepts:
#   "-5"       -> negative sign not in the pattern
#   "NaN"      -> Decimal special value; not a number on the wire
#   "Infinity" -> Decimal special value; the "no float in the money path" goal
#   "1E3"      -> scientific notation; not in the pattern (and mutates on re-emit)
REJECT_VALUES = ["-5", "NaN", "Infinity", "1E3"]

# Values that MATCH the pattern and MUST be accepted. "" is valid (the whole
# body is optional) and is the case bare-Decimal wrongly rejects.
ACCEPT_VALUES = ["", "19.99"]


def _reject_ids():
    return [f"{cid}::rejects::{v!r}" for cid, *_ in MONEY_FIELDS for v in REJECT_VALUES]


def _accept_ids():
    return [f"{cid}::accepts::{v!r}" for cid, *_ in MONEY_FIELDS for v in ACCEPT_VALUES]


@pytest.mark.parametrize(
    "cls,base,field,value",
    [
        (cls, base, field, v)
        for _, cls, base, field in MONEY_FIELDS
        for v in REJECT_VALUES
    ],
    ids=_reject_ids(),
)
def test_money_field_rejects_non_pattern_value(cls, base, field, value):
    instance = {**base, field: value}
    with pytest.raises(ValidationError):
        cls.model_validate(instance)


@pytest.mark.parametrize(
    "cls,base,field,value",
    [
        (cls, base, field, v)
        for _, cls, base, field in MONEY_FIELDS
        for v in ACCEPT_VALUES
    ],
    ids=_accept_ids(),
)
def test_money_field_accepts_pattern_value(cls, base, field, value):
    instance = {**base, field: value}
    parsed = cls.model_validate(instance)
    assert getattr(parsed, field) == value
