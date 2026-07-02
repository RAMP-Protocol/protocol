"""Cross-field (message-CEL) validation — the one genuinely net-new L1 surface.

Mirrors the sdk/ts sibling (sdk/ts/src/crossfield.ts). The 7 cross-field rules
live ONLY in proto/ramp/v1/ramp.proto as protovalidate message-CEL options; the
Go oracle executes them via protovalidate. Field-level Pydantic (gen/python) and
Zod cannot express them. This layer closes that gap on the Python side: it
transcribes each CEL predicate VERBATIM (see the per-rule comment) and each
emitting a STABLE rule-id matching the conformance/corpus/crossfield.json ``rules``
strings — the direct analogue of the Go oracle's ``ValidationRuleIDs(err)``
``contains(got, want)`` contract, not pass/fail-only.

The generated Pydantic models (gen/python/wire/models.py) are COMPOSED onto via
``@model_validator`` (below), never forked. The rule-id extraction itself reads
the raw proto-JSON so it works regardless of casing: proto-JSON field names arrive
in either camelCase (uriDigest, scopeLicense — the wire default) or snake_case
(uri_digest, scope_license — as the shared corpus records them); the accessors
read both so a rule fires on the same field regardless of which casing the caller
supplies.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from pydantic import model_validator
from wire.models import License, LicenseTerm, Obligation, Pricing, Restriction

if TYPE_CHECKING:
    from collections.abc import Callable

# ---- generated enum members (reused, not forked) --------------------------
_OBLIGATION_KIND_SHARE_ALIKE = "OBLIGATION_KIND_SHARE_ALIKE"
_TERM_SEMANTICS_REFERENCE_ONLY = "TERM_SEMANTICS_REFERENCE_ONLY"
_PRICING_MODEL_FREE = "PRICING_MODEL_FREE"
_PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT"

_ZERO_RATE_RE = re.compile(r"^0+([.]0+)?$")


# ---- tolerant field accessors ---------------------------------------------
def _as_obj(v: Any) -> dict[str, Any] | None:
    return v if isinstance(v, dict) else None


def _field(o: dict[str, Any], *names: str) -> Any:
    for n in names:
        if o.get(n) is not None:
            return o[n]
    return None


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


# ---- per-message cross-field predicates -----------------------------------
# Each returns the rule-ids VIOLATED by the instance (empty => passes). The
# boolean expression mirrors the CEL predicate; a rule-id is emitted when the CEL
# predicate is FALSE (protovalidate rejects when the expression is false).


def _license_rules(o: dict[str, Any]) -> list[str]:
    """License.digest_required_with_uri: ``this.uri == '' || this.uri_digest != ''``."""
    uri = _str(_field(o, "uri"))
    uri_digest = _str(_field(o, "uriDigest", "uri_digest"))
    digest_obj = _as_obj(_field(o, "digest"))
    has_digest = uri_digest != "" or digest_obj is not None
    if uri != "" and not has_digest:
        return ["license.digest_required_with_uri"]
    return []


def _license_term_rules(o: dict[str, Any]) -> list[str]:
    """LicenseTerm reference_only.requires_uri + one_restriction_per_kind."""
    out: list[str] = []
    semantics = _str(_field(o, "semantics"))
    if semantics == _TERM_SEMANTICS_REFERENCE_ONLY:
        license_ = _as_obj(_field(o, "license"))
        if license_ is None or _str(_field(license_, "uri")) == "":
            out.append("license_term.reference_only.requires_uri")
    restrictions = _field(o, "restrictions")
    if isinstance(restrictions, list):
        kinds = [_str(_field(_as_obj(r) or {}, "kind")) for r in restrictions]
        if len(set(kinds)) != len(kinds):
            out.append("license_term.one_restriction_per_kind")
    return out


def _obligation_rules(o: dict[str, Any]) -> list[str]:
    """Obligation.share_alike.requires_scope_license."""
    if _str(_field(o, "kind")) != _OBLIGATION_KIND_SHARE_ALIKE:
        return []
    raw = _field(o, "scopeLicense", "scope_license")
    raw_obj = _as_obj(raw)
    identified = (isinstance(raw, str) and raw != "") or (
        raw_obj is not None
        and (_str(_field(raw_obj, "id")) != "" or _str(_field(raw_obj, "uri")) != "")
    )
    return [] if identified else ["obligation.share_alike.requires_scope_license"]


def _pricing_rules(o: dict[str, Any]) -> list[str]:
    """Pricing per_unit.requires_unit + free.zero_rate."""
    out: list[str] = []
    model = _str(_field(o, "model"))
    if model == _PRICING_MODEL_PER_UNIT and _str(_field(o, "unit")) == "":
        out.append("pricing.per_unit.requires_unit")
    if model == _PRICING_MODEL_FREE:
        rate = _str(_field(o, "rate"))
        if rate != "" and not _ZERO_RATE_RE.match(rate):
            out.append("pricing.free.zero_rate")
    return out


def _restriction_rules(o: dict[str, Any]) -> list[str]:
    """Restriction.permitted_prohibited_disjoint: ``permitted.all(p, !(p in prohibited))``."""
    permitted = _field(o, "permitted")
    prohibited = _field(o, "prohibited")
    if not isinstance(permitted, list) or not isinstance(prohibited, list):
        return []
    banned = {_str(p) for p in prohibited}
    for p in permitted:
        if _str(p) in banned:
            return ["restriction.permitted_prohibited_disjoint"]
    return []


_RULES_BY_MESSAGE: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "License": _license_rules,
    "LicenseTerm": _license_term_rules,
    "Obligation": _obligation_rules,
    "Pricing": _pricing_rules,
    "Restriction": _restriction_rules,
}


def cross_field_rule_ids(message: str, json: Any) -> list[str]:
    """Return the cross-field (message-CEL) rule-ids ``json`` violates for ``message``.

    Empty when it passes cross-field validation. Direct analogue of the Go oracle's
    ``ValidationRuleIDs(err)`` over the crossfield corpus.
    """
    fn = _RULES_BY_MESSAGE.get(message)
    if fn is None:
        msg = f"cross_field_rule_ids: unknown message {message}"
        raise ValueError(msg)
    o = _as_obj(json)
    return fn(o) if o is not None else []


# ---- composed models (generated field-level + cross-field refinements) -----
# Compose the cross-field layer ONTO the generated models by SUBCLASSING them and
# adding a single @model_validator, so a consumer gets one model that enforces BOTH
# the generated field-level rules (inherited, never forked) and the cross-field
# rules. The rule-id extraction above is independent of field-level validation, so
# a field error never masquerades as a cross-field verdict (and vice versa).


def _make_cross_field(base: type[Any], message: str) -> type[Any]:
    def _check(self: Any) -> Any:
        violated = cross_field_rule_ids(message, self.model_dump(by_alias=True, exclude_none=True))
        if violated:
            joined = ", ".join(violated)
            msg = f"cross-field rule(s) violated: {joined}"
            raise ValueError(msg)
        return self

    namespace = {
        "__module__": __name__,
        "_ramp_cross_field": model_validator(mode="after")(_check),
    }
    return type(f"{message}CrossField", (base,), namespace)


LicenseCrossField = _make_cross_field(License, "License")
LicenseTermCrossField = _make_cross_field(LicenseTerm, "LicenseTerm")
ObligationCrossField = _make_cross_field(Obligation, "Obligation")
PricingCrossField = _make_cross_field(Pricing, "Pricing")
RestrictionCrossField = _make_cross_field(Restriction, "Restriction")
