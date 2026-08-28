"""Cross-field (message-CEL) validation — the one genuinely net-new L1 surface.

Mirrors the sdk/ts sibling (sdk/ts/src/crossfield.ts). The cross-field rules
live ONLY in proto/ramp/v1/ramp.proto as protovalidate message-CEL options; the
Go oracle executes them via protovalidate. Field-level Pydantic (gen/python) and
Zod cannot express them. This layer closes that gap on the Python side: it
transcribes each CEL predicate VERBATIM (see the per-rule comment) and each
emitting a STABLE rule-id matching the conformance/corpus/crossfield.json ``rules``
strings — the direct analogue of the Go oracle's ``ValidationRuleIDs(err)``
``contains(got, want)`` contract, not pass/fail-only.

The generated Pydantic models (gen/python/wire/models.py) are COMPOSED onto via
``@model_validator`` (below), never forked. The rule-id extraction reads snake_case
proto-JSON field names exclusively — the wire, corpus, and signed form are all
snake_case (UseProtoNames=true).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from pydantic import model_validator
from wire.models import (
    GetAccountStatusResponse,
    License,
    LicenseTerm,
    Obligation,
    Pricing,
    RegistrationFailure,
    Restriction,
    WellKnownManifest,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# ---- generated enum members (reused, not forked) --------------------------
_OBLIGATION_KIND_SHARE_ALIKE = "OBLIGATION_KIND_SHARE_ALIKE"
_TERM_SEMANTICS_REFERENCE_ONLY = "TERM_SEMANTICS_REFERENCE_ONLY"
_REGISTRATION_FAILURE_INVALID_DATA = "REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA"
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
    uri_digest = _str(_field(o, "uri_digest"))
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
    raw = _field(o, "scope_license")
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


def _well_known_manifest_rules(o: dict[str, Any]) -> list[str]:
    """WellKnownManifest.terms_digest_requires_terms_uri.

    ``this.terms_digest == '' || this.terms_uri != ''``. A digest pins the
    document at ``terms_uri``, so publishing one without the address it pins
    leaves nothing to check the bytes against. Mirror of the License rule above.
    """
    terms_digest = _str(_field(o, "terms_digest"))
    terms_uri = _str(_field(o, "terms_uri"))
    if terms_digest != "" and terms_uri == "":
        return ["well_known_manifest.terms_digest_requires_terms_uri"]
    return []


def _get_account_status_response_rules(o: dict[str, Any]) -> list[str]:
    """GetAccountStatusResponse.terms_digest_requires_billing_ref.

    ``this.terms_digest == '' || this.billing_ref != ''``. The digest is what this
    ACCOUNT accepted, so it cannot travel without the account handle it hangs on.
    A reader that took the digest from a response carrying no billing_ref would be
    reading an acceptance for an account that does not exist. Mirror of the
    WellKnownManifest rule above, asked of the read side.
    """
    terms_digest = _str(_field(o, "terms_digest"))
    billing_ref = _str(_field(o, "billing_ref"))
    if terms_digest != "" and billing_ref == "":
        return ["get_account_status_response.terms_digest_requires_billing_ref"]
    return []


def _registration_failure_rules(o: dict[str, Any]) -> list[str]:
    """RegistrationFailure.field_errors_scoped_to_invalid_data.

    ``this.field_errors.size() == 0 || this.reason == 6``. The member list names
    what failed the published schema, so any other reason carrying it publishes
    detail that does not apply to the refusal.
    """
    field_errors = _field(o, "field_errors")
    if isinstance(field_errors, list) and field_errors:
        if _str(_field(o, "reason")) != _REGISTRATION_FAILURE_INVALID_DATA:
            return ["registration_failure.field_errors_scoped_to_invalid_data"]
    return []


_RULES_BY_MESSAGE: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "GetAccountStatusResponse": _get_account_status_response_rules,
    "License": _license_rules,
    "LicenseTerm": _license_term_rules,
    "Obligation": _obligation_rules,
    "Pricing": _pricing_rules,
    "Restriction": _restriction_rules,
    "RegistrationFailure": _registration_failure_rules,
    "WellKnownManifest": _well_known_manifest_rules,
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
        # mode="json" is load-bearing, not tidiness. The default dump renders an enum
        # member as its Python repr ("ObligationKind.OBLIGATION_KIND_SHARE_ALIKE"),
        # while every cross-field rule compares against the WIRE token
        # ("OBLIGATION_KIND_SHARE_ALIKE"). Without it, each rule that reads an enum
        # silently never fires: the model accepts a payload the Go oracle refuses, and
        # no test noticed because the rule-id API is fed raw JSON and answers correctly.
        violated = cross_field_rule_ids(
            message, self.model_dump(by_alias=True, exclude_none=True, mode="json")
        )
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


GetAccountStatusResponseCrossField = _make_cross_field(
    GetAccountStatusResponse, "GetAccountStatusResponse"
)
LicenseCrossField = _make_cross_field(License, "License")
LicenseTermCrossField = _make_cross_field(LicenseTerm, "LicenseTerm")
ObligationCrossField = _make_cross_field(Obligation, "Obligation")
PricingCrossField = _make_cross_field(Pricing, "Pricing")
RestrictionCrossField = _make_cross_field(Restriction, "Restriction")
RegistrationFailureCrossField = _make_cross_field(RegistrationFailure, "RegistrationFailure")
WellKnownManifestCrossField = _make_cross_field(WellKnownManifest, "WellKnownManifest")
