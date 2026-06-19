"""WireModel — the single base class every generated model extends.

The name is deliberately neutral (no protocol name): renaming the protocol must not
ripple into consumers' imports. This is the one seam between the generated models and
your application — SDK-wide configuration and any cross-cutting override live here, so
a change applies to every model at once and the dependency on the generated layer is
this one class, not N of them.

Hand-written; NOT regenerated. The generated models inherit it via
datamodel-code-generator's --base-class wire.base.WireModel.
"""
from typing import Any

from pydantic import BaseModel, ConfigDict


class WireModel(BaseModel):
    # Forward-compatible by default: fields from a newer protocol version are ignored,
    # not rejected. A consumer that wants strictness sets extra="forbid" in its OWN
    # subclass of WireModel (the tier-2 seam) — one place, not per model.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        # Proto-JSON omits unset optional fields; default to the same so a parse →
        # dump round-trip matches the wire. Pass exclude_none=False to include nulls.
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(**kwargs)
