"""Regression: repeated.unique must survive subclassing a generated model.

The corpus-driven parity suite can only name exact generated message types, so it
cannot express a consumer subclass -- the path on which the unique rule silently
no-opped, because it is enforced via a name-keyed base-class validator and a subclass
has a different __name__. These tests cover the documented WireModel subclass seam
directly (plain subclass and the extra="forbid" strictness seam), plus a control that
proves ordinary inherited field bounds still fire on a subclass.
"""
import pytest
from pydantic import ConfigDict, ValidationError

from wire.models import ReportingPolicy

VALID = {"tenant_id": "x", "quantity_tolerance": 0, "window_seconds": 1}


class Plain(ReportingPolicy):
    pass


class Strict(ReportingPolicy):
    model_config = ConfigDict(extra="forbid")  # the documented strictness seam


@pytest.mark.parametrize("cls", [ReportingPolicy, Plain, Strict])
def test_unique_enforced_on_class_and_subclasses(cls):
    with pytest.raises(ValidationError):
        cls.model_validate({**VALID, "required_fields": ["a", "a"]})


@pytest.mark.parametrize("cls", [ReportingPolicy, Plain, Strict])
def test_distinct_items_accepted(cls):
    cls.model_validate({**VALID, "required_fields": ["a", "b"]})


@pytest.mark.parametrize("cls", [Plain, Strict])
def test_inherited_field_bounds_still_fire_on_subclass(cls):
    # control: an ordinary inherited rule (item pattern) must still reject on a subclass,
    # proving the MRO walk did not come at the cost of breaking field-annotation inheritance.
    with pytest.raises(ValidationError):
        cls.model_validate({**VALID, "required_fields": ["@bad"]})
