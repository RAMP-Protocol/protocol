"""Base class for every generated model.

All generated models inherit this, so it is the single place to configure model-wide
behavior and the one point an application extends to add or relax behavior across every
model at once. Hand-written; not regenerated.

Because every generated model — nested ones included — inherits this class, a validator
here runs at every depth of a message for free. That is why the wire-naming refusal below
needs no walk, while its TypeScript twin in ``gen/ts/wire/base.ts`` has to recurse itself.
"""
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic_core import PydanticCustomError

from wire.names import snake_from_json_name
from wire.unique import UNIQUE_ITEM_FIELDS

#: Error ``type`` on the refusal below, so a caller can recognise it in
#: ``ValidationError.errors()`` without matching on a message string.
JSON_NAME_ALIAS_ERROR = "ramp_json_name_alias"


class WireModel(BaseModel):
    # Forward-compatible: fields from a newer protocol version are ignored, not
    # rejected. A consumer that wants strictness sets extra="forbid" in its own
    # subclass.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def _refuse_json_name_alias(cls, data: Any) -> Any:
        """Refuse a message whose field names are protojson's lowerCamelCase alias.

        The RAMP wire is snake_case proto-JSON and the camelCase ``json_name`` alias is out
        of contract, so a conformant peer serves snake_case — connect-go does that only
        when a codec with UseProtoNames is registered, which a RAMP deployment does and a
        stock connect-go server does not. ``extra="ignore"`` above means such an answer
        would otherwise validate SUCCESSFULLY into a message with every multiword field
        missing, and nothing anywhere would say so.

        Depth is the point, and the money verb is why: a stock connect-go server omits
        unset fields, so a TransactionResponse arrives as ``{ver, items}`` — every root key
        a single word, identical in both spellings — while ``transaction_id`` sits one
        level down in TransactionResultItem and is dropped. That reads as a purchase that
        succeeded with no transaction id and no delivery URL, severing the dispute chain at
        its first link. Inheritance covers the depth: TransactionResultItem is a WireModel
        too, so it checks itself.

        Open maps are out of reach by construction rather than by a hold-back list. A
        ``dict[str, Any]`` field is validated as data, not as a model, so its keys — which
        are caller-chosen — never reach this method.

        A value that is not a mapping is left alone: this also runs when a model is built
        from Python objects rather than parsed from the wire, and there the field names are
        already the field names.
        """
        if not isinstance(data, dict):
            return data
        declared = cls.model_fields
        for key in data:
            if not isinstance(key, str) or key in declared:
                continue
            name = snake_from_json_name(key)
            if name != key and name in declared:
                raise PydanticCustomError(
                    JSON_NAME_ALIAS_ERROR,
                    "peer answered with the lowerCamelCase json_name alias ({key}); the RAMP "
                    "wire is snake_case proto-JSON, so its answer cannot be read without "
                    "silently dropping every multiword field",
                    {"key": key},
                )
        return data

    @model_validator(mode="after")
    def _reject_duplicate_items(self) -> "WireModel":
        # (buf.validate.field).repeated.unique. datamodel-code-generator drops JSON
        # Schema's `uniqueItems` for pydantic v2, so this rule cannot ride into models.py
        # the way every other field rule does; it arrives via the generated wire/unique.py
        # instead. Zod gets the same rule inline, from `uniqueItems` in the JSON Schema.
        # No rule is restated here: the field list is derived from Go protovalidate.
        #
        # Walk the MRO, NOT just type(self).__name__: the manifest is keyed by the
        # generated message class name, and a consumer SUBCLASS (the documented extension
        # seam above) has a different __name__. Field-annotation rules (constr/Field
        # bounds, patterns) inherit structurally across the MRO; this out-of-band rule
        # must walk the base classes itself or it silently no-ops on subclasses.
        # WireModel/BaseModel/object are not manifest keys, so they resolve to () — inert.
        fields: set[str] = set()
        for klass in type(self).__mro__:
            fields.update(UNIQUE_ITEM_FIELDS.get(klass.__name__, ()))
        for name in fields:
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
