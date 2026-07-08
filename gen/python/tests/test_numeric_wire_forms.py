"""Direct behavioral regression for the proto-JSON STRING form of a bounded numeric field.

proto-JSON accepts a number as a JSON number OR a string, so protoschema models every
numeric field as anyOf[{integer|number}, {string, pattern}] — and puts minimum/maximum on
the NUMERIC arm only. merge_schema.collapse_numeric_strings drops the string arm so the
bound applies to the value the client actually validates (Pydantic lax parsing and Zod's
z.coerce.number() still accept the wire string). Leave the string arm standing and the
generated clients ACCEPT out-of-range values that Go protovalidate REJECTS.

That is the divergence class the typed-contract pipeline exists to prevent, and it cannot
be caught by the corpus: corpusgen sets values through protoreflect and protojson always
marshals a double as a JSON number, so no string-encoded double can ever appear in a case.
This test covers it directly, through the real generated models (model_validate on
proto-JSON dicts), exactly as test_money_pattern.py covers the money pattern.

quantity_tolerance (optional double, gte 0 lte 1) is the first bounded double in the wire
contract. window_seconds (optional int32, gt 0 lte 31536000) pins the pre-existing integer
collapse against regression.

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_numeric_wire_forms.py -q
"""
import pytest
from pydantic import ValidationError

import wire.models as models

BASE = {"tenant_id": "x"}

# (field, wire value, accepted) — the wire value is what protoJSON would carry.
CASES = [
    # A double in range, in both encodings Go accepts.
    ("quantity_tolerance", 0.5, True),
    ("quantity_tolerance", "0.5", True),
    ("quantity_tolerance", 0, True),
    ("quantity_tolerance", "0", True),
    ("quantity_tolerance", 1, True),
    ("quantity_tolerance", "1", True),
    # Out of [0, 1] — Go rejects both encodings, so the clients must too.
    ("quantity_tolerance", 1000, False),
    ("quantity_tolerance", "1000", False),
    ("quantity_tolerance", 1.5, False),
    ("quantity_tolerance", "1.5", False),
    ("quantity_tolerance", -1, False),
    ("quantity_tolerance", "-5", False),
    ("quantity_tolerance", "1e3", False),
    # int32 (gt 0, lte 31536000) — the integer collapse, guarded against regression.
    ("window_seconds", 1, True),
    ("window_seconds", "1", True),
    ("window_seconds", 0, False),
    ("window_seconds", "0", False),
    ("window_seconds", 31536001, False),
    ("window_seconds", "31536001", False),
]


@pytest.mark.parametrize(
    "field,value,accepted", CASES, ids=[f"{f}={v!r}" for f, v, _ in CASES]
)
@pytest.mark.parametrize("cls_name", ["SetReportingPolicyRequest", "SetReportingPolicyResponse"])
def test_numeric_bounds_apply_to_the_wire_string_form(cls_name, field, value, accepted):
    cls = getattr(models, cls_name)
    instance = {**BASE, field: value}
    if accepted:
        assert cls.model_validate(instance) is not None
    else:
        with pytest.raises(ValidationError):
            cls.model_validate(instance)


def test_no_field_admits_an_unbounded_string_arm():
    # Guard the guard: if the union ever comes back, the parametrized cases above would
    # still pass for the numeric form while silently accepting the string form. Assert the
    # annotation itself carries no `str` alternative.
    annotation = repr(models.SetReportingPolicyRequest.model_fields["quantity_tolerance"].annotation)
    assert "str" not in annotation, f"quantity_tolerance regained a string arm: {annotation}"
