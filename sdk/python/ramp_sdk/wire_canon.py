"""Wire-to-canonical offer conversion (the from-wire canonicalizer).

The RAMP Connect wire is snake_case proto-JSON with ``EmitUnpopulated``: zero-valued
scalars, empty repeateds, null messages and ``*_UNSPECIFIED`` enums are all present.
That is what ``sdk/go/connectserver/codec.go`` marshals (``UseProtoNames: true``), and
what ``codec_test.go`` guards — a stray ``UseProtoNames=false`` is the regression it
catches. The offer SIGNATURE covers the CANONICAL form: the same snake_case proto
names, but omit-unpopulated, enums-as-names (sdk/go helpers
``canonicalSignJSONOptions``), then RFC 8785 JCS. Both sides share the naming, so what
this inversion actually undoes is the zero-inflation and the signature fields, NOT the
naming. Every Python client verifying a wire offer must still perform it before calling
:func:`ramp_sdk.core.canonical_offer_payload` — never call that on raw wire input.

The retired proto-JSON lowerCamel ``json_name`` form is still TOLERATED on input (hence
:func:`_snake`, the ``offer_camel`` parameter name, and the pre-flip fixture the tests
keep). It is out of contract: accepted when it arrives, never emitted.

:func:`from_wire_offer` performs that inversion SCHEMA-AWARE, driven by the
generated ``wire.models`` classes (gen/python), whose field DEFAULTS encode
proto3 presence: ``default None`` marks a presence-tracked field (proto3
optional scalar, message, repeated, map) whose wire presence means SET (kept
verbatim — including an optional string deliberately set to ``""``), while a
zero default (``""``/``0``) or a required field marks a non-optional scalar
whose zero value the canonical form omits (dropped). Repeated fields drop when
empty; unset messages/Structs arrive as ``null`` and drop; a set-but-empty
message (``{}``) is kept; map values keep their keys VERBATIM (map keys are
data, never case-converted). ``*_UNSPECIFIED`` enum values are zero values and
drop.

Byte-parity with the Go oracle is pinned by ``tests/test_wire_canon.py``: over the
drift-gated ``sdk/go/helpers/testdata/wire-canonical-vectors.json`` corpus for the
current snake_case wire, and over a live-captured fixture pair for the retired form.

KNOWN LIMITS (fail-closed, never fail-open): a wire offer carrying fields newer
than the pinned gen models is kept verbatim and will verify FALSE (rejected,
not silently accepted), and a non-optional int64 zero (emitted as ``"0"``) is
not dropped (no such field exists on the Offer tree today).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, get_args, get_origin

from wire import base as wire_base
from wire import models as wire_models

if TYPE_CHECKING:
    from pydantic.fields import FieldInfo

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])([A-Z])")
_UNSPECIFIED_ENUM = re.compile(r"^[A-Z][A-Z0-9_]*_UNSPECIFIED$")


def _snake(key: str) -> str:
    """Invert protojson's retired lowerCamel json_name back to the proto name.

    Idempotent on already-snake keys, which is what the current wire and the shared
    corpus emit — so the inversion costs nothing and keeps the retired form working.
    """
    return _CAMEL_BOUNDARY.sub(r"_\1", key).lower()


# Sentinel: the field would be omitted entirely by the canonical marshal.
_OMIT = object()


def _message_arg(annotation: Any) -> type[Any] | None:
    """Return the WireModel subclass inside an annotation, if any."""
    if isinstance(annotation, type) and issubclass(annotation, wire_base.WireModel):
        return annotation
    for arg in get_args(annotation):
        found = _message_arg(arg)
        if found is not None:
            return found
    return None


def _is_map(annotation: Any) -> bool:
    """True when the annotation is a proto map/Struct (a plain dict type)."""
    if get_origin(annotation) is dict:
        return True
    return any(_is_map(arg) for arg in get_args(annotation))


def _canon_scalar(value: Any, *, presence: bool) -> Any:
    """Canonicalize a scalar field value per proto3 presence semantics."""
    if presence:
        return value  # set (it is on the wire) → part of the signed bytes
    zeroish = value == "" or value is False or (not isinstance(value, bool) and value == 0)
    if zeroish or (isinstance(value, str) and _UNSPECIFIED_ENUM.match(value)):
        return _OMIT
    return value


def _canon_field(field: FieldInfo, value: Any) -> Any:
    """Canonicalize one wire field value using the gen model's field metadata."""
    if value is None:
        return _OMIT  # unset message/Struct (EmitUnpopulated renders null)
    msg_cls = _message_arg(field.annotation)
    if isinstance(value, list):
        items = [
            _canon_message(msg_cls, v) if msg_cls and isinstance(v, dict) else v for v in value
        ]
        return items or _OMIT  # canonical omits empty repeated
    if isinstance(value, dict):
        if msg_cls is not None:
            return _canon_message(msg_cls, value)  # set-but-empty {} stays
        if _is_map(field.annotation):
            return value or _OMIT  # map keys stay VERBATIM
        return value
    return _canon_scalar(value, presence=field.default is None)


def _canon_message(model_cls: type[Any], wire: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct one message's canonical dict from its wire dict."""
    fields = model_cls.model_fields
    out: dict[str, Any] = {}
    for key, value in wire.items():
        name = _snake(key)
        field = fields.get(name)
        if field is None:
            # Newer-than-pin field: keep it so verification fails CLOSED (the
            # signature covered bytes this pin cannot reconstruct).
            out[name] = value
            continue
        canon = _canon_field(field, value)
        if canon is not _OMIT:
            out[name] = canon
    return out


def from_wire_offer(offer_camel: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the canonical (signed) offer dict from the wire offer dict."""
    return _canon_message(wire_models.Offer, offer_camel)
