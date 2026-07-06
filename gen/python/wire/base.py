"""Base class for every generated model.

All generated models inherit this, so it is the single place to configure model-wide
behavior and the one point an application extends to add or relax behavior across every
model at once. Hand-written; not regenerated.
"""
from typing import Any

from pydantic import BaseModel, ConfigDict


class WireModel(BaseModel):
    # Forward-compatible: fields from a newer protocol version are ignored, not
    # rejected. A consumer that wants strictness sets extra="forbid" in its own
    # subclass.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        # Proto-JSON omits unset optional fields; default to the same so parse → dump
        # round-trips match the wire. Pass exclude_none=False to include nulls.
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(**kwargs)
