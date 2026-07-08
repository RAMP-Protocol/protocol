"""Base class for every generated model.

All generated models inherit this, so it is the single place to configure model-wide
behavior and the one point an application extends to add or relax behavior across every
model at once. Hand-written; not regenerated.
"""
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

from wire.unique import UNIQUE_ITEM_FIELDS


class WireModel(BaseModel):
    # Forward-compatible: fields from a newer protocol version are ignored, not
    # rejected. A consumer that wants strictness sets extra="forbid" in its own
    # subclass.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    @model_validator(mode="after")
    def _reject_duplicate_items(self) -> "WireModel":
        # (buf.validate.field).repeated.unique. datamodel-code-generator drops JSON
        # Schema's `uniqueItems` for pydantic v2, so this rule cannot ride into models.py
        # the way every other field rule does; it arrives via the generated wire/unique.py
        # instead. Zod gets the same rule inline, from `uniqueItems` in the JSON Schema.
        # No rule is restated here: the field list is derived from Go protovalidate.
        for name in UNIQUE_ITEM_FIELDS.get(type(self).__name__, ()):
            items = getattr(self, name, None)
            if items is not None and len(items) != len(set(items)):
                raise ValueError(f"{name}: repeated value must contain unique items")
        return self

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        # Proto-JSON omits unset optional fields; default to the same so parse → dump
        # round-trips match the wire. Pass exclude_none=False to include nulls.
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(**kwargs)
