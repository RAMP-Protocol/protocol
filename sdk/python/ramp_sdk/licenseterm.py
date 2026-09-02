"""License-term canonicalisation and the ingest-tier checks — Python port of the
sdk/go oracle (helpers/licenseterm.go), pinned to the shared
licenseterm-vectors.json. Mirrors the sdk/ts sibling (sdk/ts/src/licenseterm.ts).

A pushed entry passes two tiers at the Exchange. The wire tier is the generated
field-level model plus the cross-field (message-CEL) rules, applied to the entry
as received. The ingest tier runs over the CANONICALISED terms: restriction
tokens are folded and alias-resolved to their registered form, then a bare
``Pricing.unit`` or ``Quota.metric`` that is not a registered token is rejected,
while an unregistered restriction token and an ``OBLIGATION_KIND_OTHER``
obligation without detail are accepted with a warning that reaches
``PushResourcesResponse.warnings``. The Exchange's own run is the deciding one; a
client-side verdict is advice about what that run will say.

Folding is ASCII-only and only RFC 8259 whitespace is trimmed — ``str.lower()``
turns U+212A KELVIN SIGN into ``k`` and a homograph into a registered token.
Messages are the exact strings the Go oracle emits, which are the strings an
Exchange puts on the wire. Inputs are proto-JSON dicts (snake_case); every face
returns a new object and never modifies its input.
"""

from __future__ import annotations

import copy
import string
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from vocab import functiontokens, geographytokens, pricingunits, quotametrics, usertypes
from wire.models import ResourceEntry

from .crossfield import cross_field_rule_ids

#: Rejects a bare (non-namespaced) Pricing.unit that is not a registered metering token.
RULE_PRICING_UNIT_REGISTERED = "pricing.unit.registered"
#: Rejects a bare Quota.metric that is not a registered quota token.
RULE_QUOTA_METRIC_REGISTERED = "quota.metric.registered"
#: Warns about a bare restriction token not registered on its axis; the term is accepted.
RULE_RESTRICTION_CANONICAL_DISJOINT = "restriction.canonical_disjoint"
"""Rejects a restriction whose permitted and prohibited lists name the same token once
both are canonicalised. The wire tier's rule compares the tokens AS WRITTEN, so two
accepted spellings of one token — an alias beside its registered form, or two spellings
differing only in ASCII case — pass it and collide only after the fold."""

RULE_RESTRICTION_TOKEN_REGISTERED = "restriction.token.registered"
#: Warns about an OBLIGATION_KIND_OTHER obligation carrying no detail.
RULE_OBLIGATION_OTHER_REQUIRES_DETAIL = "obligation.other.requires_detail"

_KIND_FUNCTION = "RESTRICTION_KIND_FUNCTION"
_KIND_GEOGRAPHY = "RESTRICTION_KIND_GEOGRAPHY"
_KIND_USER_TYPE = "RESTRICTION_KIND_USER_TYPE"
#: The enum's zero, as the oracle spells it when a restriction carries no kind.
_KIND_UNSPECIFIED = "RESTRICTION_KIND_UNSPECIFIED"
_OBLIGATION_KIND_OTHER = "OBLIGATION_KIND_OTHER"

_JSON_WHITESPACE = " \t\n\r"
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_ASCII_UPPER = str.maketrans(string.ascii_lowercase, string.ascii_uppercase)


@dataclass(frozen=True)
class RuleViolation:
    """One reason an entry or a term would be refused.

    ``rule`` is the rule id (an ingest-tier id above, a cross-field CEL id, or
    ``field.<pydantic error type>`` for a field-level refusal — the field-level ids
    are language-local); ``path`` is the snake_case proto-JSON field path relative
    to the checked message; ``token`` is the offending value when the rule is about
    one token, else ``""``.
    """

    rule: str
    path: str
    token: str
    message: str


@dataclass(frozen=True)
class RuleWarning:
    """One non-fatal finding; ``message`` is the exact wire string of the warning."""

    rule: str
    path: str
    token: str
    message: str


@dataclass(frozen=True)
class TermVerdict:
    """What :func:`validate_license_term` reports for one already-canonical term."""

    violation: RuleViolation | None
    warnings: list[RuleWarning] = field(default_factory=list)


@dataclass(frozen=True)
class EntryVerdict:
    """What :func:`validate_resource_entry` reports: both tiers, wire tier first."""

    violations: list[RuleViolation] = field(default_factory=list)
    warnings: list[RuleWarning] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when the entry carries no violation. Warnings do not fail it."""
        return not self.violations


def _as_obj(v: Any) -> dict[str, Any] | None:
    return v if isinstance(v, dict) else None


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _trim_json_whitespace(s: str) -> str:
    # The four RFC 8259 whitespace characters and nothing else, so a token padded
    # with a non-breaking space stays padded, in every language.
    return s.strip(_JSON_WHITESPACE)


def _ascii_lower(s: str) -> str:
    return s.translate(_ASCII_LOWER)


def _ascii_upper(s: str) -> str:
    return s.translate(_ASCII_UPPER)


def _has_canonical_rule(kind: str) -> bool:
    return kind in (_KIND_FUNCTION, _KIND_USER_TYPE, _KIND_GEOGRAPHY)


def _is_namespaced(token: str) -> bool:
    return ":" in token


def _is_iso_alpha2(token: str) -> bool:
    # Two uppercase ASCII letters — the structural shape of an ISO 3166-1 alpha-2
    # code, which the geography registry deliberately does not enumerate.
    return len(token) == 2 and all("A" <= c <= "Z" for c in token)


def canonical_restriction_token(kind: str, token: str) -> str:
    """Return the canonical form of a restriction token on an axis.

    ``kind`` is the RestrictionKind enum NAME. RFC 8259 whitespace is trimmed, the
    ASCII case is folded (lower for FUNCTION and USER_TYPE, upper for GEOGRAPHY)
    and, where the axis authors aliases, the alias resolves to its registered
    token. OTHER and any unknown axis are returned unchanged. Applying it twice is
    a fixed point.
    """
    if kind == _KIND_FUNCTION:
        return functiontokens.canonical(_ascii_lower(_trim_json_whitespace(token)))
    if kind == _KIND_USER_TYPE:
        return usertypes.canonical(_ascii_lower(_trim_json_whitespace(token)))
    if kind == _KIND_GEOGRAPHY:
        return geographytokens.canonical(_ascii_upper(_trim_json_whitespace(token)))
    return token


def known_restriction_token(kind: str, token: str) -> bool:
    """Report whether an already-canonical token is registered on its axis.

    GEOGRAPHY admits the registered specials and any two-uppercase-letter ISO
    3166-1 alpha-2 code; OTHER and unknown axes are never known.
    """
    if kind == _KIND_FUNCTION:
        return functiontokens.is_registered(token)
    if kind == _KIND_USER_TYPE:
        return usertypes.is_registered(token)
    if kind == _KIND_GEOGRAPHY:
        return geographytokens.is_registered(token) or _is_iso_alpha2(token)
    return False


def _canonicalize_tokens(kind: str, tokens: Any) -> Any:
    if not isinstance(tokens, list):
        return tokens
    return [canonical_restriction_token(kind, t) if isinstance(t, str) else t for t in tokens]


def normalize_license_term(term: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of the term with its restriction tokens canonicalised.

    Only the axes that carry a canonicalisation rule move; nothing else does. The
    input is untouched (the Go oracle rewrites in place; the corpus pins the output
    either way).
    """
    out = copy.deepcopy(term)
    for r in _as_list(out.get("restrictions")):
        restriction = _as_obj(r)
        if restriction is None:
            continue
        kind = _str(restriction.get("kind"))
        if not _has_canonical_rule(kind):
            continue
        if "permitted" in restriction:
            restriction["permitted"] = _canonicalize_tokens(kind, restriction["permitted"])
        if "prohibited" in restriction:
            restriction["prohibited"] = _canonicalize_tokens(kind, restriction["prohibited"])
    return out


def normalize_resource_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of the entry with every term normalised."""
    out = copy.deepcopy(entry)
    terms = _as_list(out.get("terms"))
    if terms:
        out["terms"] = [normalize_license_term(t) if isinstance(t, dict) else t for t in terms]
    return out


def _bare_unregistered(token: str, registered: Any) -> bool:
    if token == "" or _is_namespaced(token):
        return False
    return not registered(token)


def _restriction_token_warning(kind: str, tok: str, path: str) -> RuleWarning | None:
    if tok == "" or _is_namespaced(tok) or known_restriction_token(kind, tok):
        return None
    # An absent kind is the enum's zero, and the oracle names it: Go formats the enum,
    # which spells the unset value rather than leaving a gap. These strings are the exact
    # bytes an Exchange puts in warnings[], so a doubled space here is a real difference
    # in what a publisher is told, not a rendering detail.
    return RuleWarning(
        rule=RULE_RESTRICTION_TOKEN_REGISTERED,
        path=path,
        token=tok,
        message=f'unregistered {kind or _KIND_UNSPECIFIED} restriction token "{tok}" (term accepted)',
    )


def _canonical_disjoint_violation(i: int, restriction: dict[str, Any]) -> RuleViolation | None:
    """Return the violation for the first permitted token of ``restriction`` whose canonical
    form is also the canonical form of one of its prohibited tokens, or ``None``.

    It canonicalises what it compares rather than trusting the term to have been
    normalised, and it runs on every axis — where the fold is a no-op the check is plain
    equality, which is what a server that never asked for the wire tier needs. The finding
    names the canonical token, not the spellings that produced it, so the message does not
    depend on whether the caller folded first.
    """
    permitted = _as_list(restriction.get("permitted"))
    prohibited = _as_list(restriction.get("prohibited"))
    if not permitted or not prohibited:
        return None
    kind = _str(restriction.get("kind"))
    banned = {canonical_restriction_token(kind, _str(tok)) for tok in prohibited}
    for j, tok in enumerate(permitted):
        canon = canonical_restriction_token(kind, _str(tok))
        if canon not in banned:
            continue
        return RuleViolation(
            rule=RULE_RESTRICTION_CANONICAL_DISJOINT,
            path=f"restrictions[{i}].permitted[{j}]",
            token=canon,
            message=f'restriction token "{canon}" is both permitted and prohibited after canonicalisation',
        )
    return None


def validate_license_term(term: dict[str, Any]) -> TermVerdict:
    """Run the ingest-tier checks over one term, in a fixed order.

    A bare ``pricing.unit`` that is not registered, then the first offending
    ``quotas[].metric``, then the first restriction whose permitted and prohibited
    lists name one token once canonicalised. An accepted term carries one warning
    per unregistered bare restriction token — restriction order, permitted before
    prohibited — then one per ``OBLIGATION_KIND_OTHER`` obligation without detail.

    Every check but the disjointness one reads the term as already canonical. The
    wire tier is not re-run here; disjointness is the one property both tiers assert,
    over different values, so a term the boundary clears can still fail here.
    """
    pricing = _as_obj(term.get("pricing")) or {}
    unit = _str(pricing.get("unit"))
    if _bare_unregistered(unit, pricingunits.is_registered):
        return TermVerdict(
            violation=RuleViolation(
                rule=RULE_PRICING_UNIT_REGISTERED,
                path="pricing.unit",
                token=unit,
                message=f'pricing unit "{unit}" is not a registered metering token',
            )
        )
    for i, q in enumerate(_as_list(term.get("quotas"))):
        metric = _str((_as_obj(q) or {}).get("metric"))
        if _bare_unregistered(metric, quotametrics.is_registered):
            return TermVerdict(
                violation=RuleViolation(
                    rule=RULE_QUOTA_METRIC_REGISTERED,
                    path=f"quotas[{i}].metric",
                    token=metric,
                    message=f'quota metric "{metric}" is not a registered quota token',
                )
            )
    for i, r in enumerate(_as_list(term.get("restrictions"))):
        restriction = _as_obj(r)
        if restriction is None:
            continue
        violation = _canonical_disjoint_violation(i, restriction)
        if violation is not None:
            return TermVerdict(violation=violation)
    warnings: list[RuleWarning] = []
    for i, r in enumerate(_as_list(term.get("restrictions"))):
        restriction = _as_obj(r)
        if restriction is None:
            continue
        kind = _str(restriction.get("kind"))
        for j, tok in enumerate(_as_list(restriction.get("permitted"))):
            w = _restriction_token_warning(kind, _str(tok), f"restrictions[{i}].permitted[{j}]")
            if w is not None:
                warnings.append(w)
        for j, tok in enumerate(_as_list(restriction.get("prohibited"))):
            w = _restriction_token_warning(kind, _str(tok), f"restrictions[{i}].prohibited[{j}]")
            if w is not None:
                warnings.append(w)
    for i, o in enumerate(_as_list(term.get("obligations"))):
        obligation = _as_obj(o)
        if obligation is None:
            continue
        if _str(obligation.get("kind")) == _OBLIGATION_KIND_OTHER and _str(obligation.get("detail")) == "":
            warnings.append(
                RuleWarning(
                    rule=RULE_OBLIGATION_OTHER_REQUIRES_DETAIL,
                    path=f"obligations[{i}].detail",
                    token="",
                    message="obligation of kind OTHER has no detail (term accepted)",
                )
            )
    return TermVerdict(violation=None, warnings=warnings)


def _loc_path(loc: tuple[Any, ...]) -> str:
    out = ""
    for seg in loc:
        if isinstance(seg, int):
            out += f"[{seg}]"
        else:
            out = str(seg) if out == "" else f"{out}.{seg}"
    return out


def _cross_field_sites(entry: dict[str, Any]) -> list[tuple[str, str, Any]]:
    # Every message instance reachable from an entry that carries a cross-field
    # rule, with its entry-relative path. The generated model is field-level and
    # the composed cross-field models attach per message, so the walk is explicit.
    sites: list[tuple[str, str, Any]] = []
    for i, t in enumerate(_as_list(entry.get("terms"))):
        term = _as_obj(t)
        if term is None:
            continue
        base = f"terms[{i}]"
        sites.append((base, "LicenseTerm", term))
        if "license" in term:
            sites.append((f"{base}.license", "License", term["license"]))
        if "pricing" in term:
            sites.append((f"{base}.pricing", "Pricing", term["pricing"]))
        for j, r in enumerate(_as_list(term.get("restrictions"))):
            sites.append((f"{base}.restrictions[{j}]", "Restriction", r))
        for k, o in enumerate(_as_list(term.get("obligations"))):
            sites.append((f"{base}.obligations[{k}]", "Obligation", o))
            obligation = _as_obj(o)
            if obligation is not None and "scope_license" in obligation:
                sites.append((f"{base}.obligations[{k}].scope_license", "License", obligation["scope_license"]))
    return sites


def validate_resource_entry(entry: dict[str, Any]) -> EntryVerdict:
    """Report the verdict the Exchange reaches for one entry (proto-JSON dict).

    Both tiers in the Exchange's order: the wire tier — the generated field-level
    model over the entry as given, plus every cross-field rule reachable from it —
    then the ingest tier over a normalised copy of the terms. The entry passed in
    is never modified. The Exchange stops at the first tier that fails; this face
    reports both so a publisher fixes everything in one round. Paths are relative
    to the entry.
    """
    violations: list[RuleViolation] = []
    try:
        ResourceEntry.model_validate(entry)
    except ValidationError as e:
        for err in e.errors():
            violations.append(
                RuleViolation(
                    rule=f"field.{err['type']}",
                    path=_loc_path(tuple(err["loc"])),
                    token="",
                    message=str(err["msg"]),
                )
            )
    # Everything below reads members off the entry, so a value that is not a dict has
    # nothing to walk. The model above has already said so — a non-dict yields its own
    # type violation — and continuing would raise AttributeError instead of returning
    # that verdict. A publisher feeding this a parsed JSONL line reaches it with
    # whatever the line held, so a malformed row must get a verdict like any other
    # refusal rather than an exception the TypeScript port does not raise either.
    if not isinstance(entry, dict):
        return EntryVerdict(violations=violations, warnings=[])
    for path, message, value in _cross_field_sites(entry):
        for rule_id in cross_field_rule_ids(message, value):
            violations.append(
                RuleViolation(rule=rule_id, path=path, token="", message=f"cross-field rule violated: {rule_id}")
            )
    warnings: list[RuleWarning] = []
    normalized = normalize_resource_entry(entry)
    for i, t in enumerate(_as_list(normalized.get("terms"))):
        term = _as_obj(t)
        if term is None:
            continue
        prefix = f"terms[{i}]."
        verdict = validate_license_term(term)
        if verdict.violation is not None:
            v = verdict.violation
            violations.append(RuleViolation(rule=v.rule, path=prefix + v.path, token=v.token, message=v.message))
            continue
        for w in verdict.warnings:
            warnings.append(RuleWarning(rule=w.rule, path=prefix + w.path, token=w.token, message=w.message))
    return EntryVerdict(violations=violations, warnings=warnings)
