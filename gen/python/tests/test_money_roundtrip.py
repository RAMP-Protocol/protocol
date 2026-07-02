"""Money is a decimal STRING on the wire, so parse -> dump must be byte-exact:
a normalizing round-trip (e.g. Decimal coercion turning "007.50" into "7.50" or
"1E3" into "1E+3") would change the bytes of a JWS-signed offer or anything under
RFC 9421 Content-Digest coverage and break the signature. This pins that the
generated Pydantic money field preserves the exact wire string (regression guard
for M2 / kb1s0.6; the fix rides on money-as-str from kb1s0.1)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wire.models import Cost, Pricing  # noqa: E402

# Every value is valid per the money pattern ^([0-9]+([.][0-9]+)?)?$ and is a form
# a naive Decimal round-trip would have normalized (leading zeros, trailing zeros,
# high sub-cent precision, empty).
PRESERVED = ["007.50", "19.90", "0.0001234", "0", "", "100", "0.10"]


@pytest.mark.parametrize("value", PRESERVED)
def test_cost_amount_roundtrips_byte_exact(value):
    model = Cost.model_validate({"amount": value, "currency": "USD"})
    assert model.model_dump()["amount"] == value
    assert f'"amount":"{value}"' in model.model_dump_json()


@pytest.mark.parametrize("value", PRESERVED)
def test_pricing_rate_roundtrips_byte_exact(value):
    model = Pricing.model_validate({"model": "PRICING_MODEL_PER_UNIT", "rate": value})
    assert model.model_dump()["rate"] == value
    assert f'"rate":"{value}"' in model.model_dump_json()
