"""Direct behavioral regression for wire forward-compatibility (H2 / kb1s0.2).

Core invariant: an UNKNOWN top-level field (a field a newer protocol version
adds that this older client has never seen) MUST be ACCEPTED and DROPPED — not
rejected, not retained. This is the whole point of WireModel's
`model_config = ConfigDict(extra="ignore")`: an older SDK keeps parsing a newer
message instead of failing closed.

This exercises the REAL generated models (wire.models) through their public
parse surface (model_validate on proto-JSON dicts, routed through
wire.base.WireModel). No corpus, no source scanning — behavior only.

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_forward_compat.py -q

It FAILS today: every generated model carries its own
`model_config = ConfigDict(extra='forbid')`, which SHADOWS the WireModel
extra='ignore' seam in Pydantic v2, so the unknown field raises ValidationError
instead of being dropped.
"""
import pytest
from pydantic import ValidationError

import wire.models as models

# A key no protocol version defines — stands in for "a field a newer version added".
UNKNOWN_KEY = "__unknown_future_field__"

# Representative models with a minimally-valid proto-JSON body (only what the
# model REQUIRES) so the sole variable under test is the extra unknown field.
# (case_id, ModelClass, base_instance)
DROP_CASES = [
    ("Cost", models.Cost, {"amount": "19.99"}),
    ("Delegation", models.Delegation, {"principal_id": "user@acme.com"}),
    ("Pricing", models.Pricing, {"model": models.PricingModel.PRICING_MODEL_FREE.value}),
]


@pytest.mark.parametrize(
    "cls,base",
    [(cls, base) for _, cls, base in DROP_CASES],
    ids=[cid for cid, *_ in DROP_CASES],
)
def test_unknown_top_level_field_accepted_and_dropped(cls, base):
    instance = {**base, UNKNOWN_KEY: "a value from the future"}

    # MUST NOT raise: an unknown top-level field is accepted (forward-compat).
    parsed = cls.model_validate(instance)

    # MUST be dropped, not retained: it is absent from the model and its dump.
    assert not hasattr(parsed, UNKNOWN_KEY)
    assert UNKNOWN_KEY not in parsed.model_dump()


def test_closed_enum_discriminator_still_rejects_bogus_value():
    # Guard: opening up unknown *top-level* fields must not over-open a CLOSED
    # enum. Pricing.model is a closed PricingModel enum; a bogus value must
    # still raise (before AND after the fix).
    with pytest.raises(ValidationError):
        models.Pricing.model_validate({"model": "PRICING_MODEL_BOGUS"})
