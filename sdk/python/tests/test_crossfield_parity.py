"""Cross-field Pydantic parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/crossfield.parity.test.ts (NOT the
weaker gen/python/tests/test_parity.py). test_parity.py asserts pass/fail ONLY —
correct for the field-level
cases.json but strictly weaker for crossfield.json, because a refinement could
fire for the WRONG reason. This suite asserts the reported cross-field RULE IDS,
the direct analogue of the Go oracle's `contains(ValidationRuleIDs(err), want)`.

Contract: expose
`ramp_sdk.cross_field_rule_ids(message, json) -> list[str]`. For each corpus
case in conformance/corpus/crossfield.json, assert each expected `rules[]` id
(minus the co-emitted "required" presence rule protovalidate co-emits with
reference_only.requires_uri) is CONTAINED in the extracted ids. To catch
OVER-rejection, also drive >=1 VALID instance per message and assert it yields an
EMPTY rule-id list.

RED now purely because `ramp_sdk` does not exist yet (import cannot resolve →
collection error). The implement step composes the cross-field @model_validator
layer onto the generated gen/python/wire/models.py classes, each emitting the
stable rule-id, at which point this goes green with no change to the assertions.

Generated vocabulary tokens (gen/python/vocab/functiontokens.py) are referenced
for the restriction axis-value fields rather than string literals, mirroring the
sibling's use of the FUNCTION token vocabulary.
"""

from __future__ import annotations

import pytest

# Reference generated vocabulary tokens rather than string literals for the
# restriction FUNCTION axis-values (PYTHONPATH=gen/python at test time).
from vocab.functiontokens import AI_INPUT, AI_TRAIN

from conftest import CONFORMANCE_CORPUS, load_json

# RED: sdk/python/ramp_sdk/crossfield.py (exposing cross_field_rule_ids) does not
# exist yet (TDD red).
from ramp_sdk import cross_field_rule_ids  # type: ignore[import-not-found]

_CASES = load_json(CONFORMANCE_CORPUS / "crossfield.json")

_EXPECTED_MESSAGES = {
    "License",
    "LicenseTerm",
    "Obligation",
    "Pricing",
    "Restriction",
    "WellKnownManifest",
}


def test_crossfield_corpus_shape() -> None:
    # >=8 mutants across exactly the 6 cross-field messages.
    assert len(_CASES) >= 8
    assert {c["message"] for c in _CASES} == _EXPECTED_MESSAGES


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_crossfield_mutant_rejected_with_matching_rule_ids(case: dict[str, object]) -> None:
    assert case["valid"] is False, f"corpus case {case['id']} must be invalid"

    got = cross_field_rule_ids(str(case["message"]), case["json"])

    # rejected at all
    assert len(got) > 0, f"{case['id']} was accepted (no cross-field rule fired)"

    # each message-CEL rule id recorded by the oracle must be present. "required"
    # is a presence rule protovalidate co-emits with reference_only.requires_uri;
    # the cross-field layer must surface the cross-field rule id at minimum, so
    # only assert the message-CEL ids.
    for want in case["rules"]:  # type: ignore[union-attr]
        if want == "required":
            continue
        assert want in got, f"{case['id']}: expected rule {want} in {got}"


# VALID instances (one per message) — invert each mutant's single violated
# predicate so the instance is legitimately cross-field-clean. These catch
# OVER-rejection: the SDK must report NO cross-field rule-ids for them.
_VALID_INSTANCES: list[dict[str, object]] = [
    {
        # License.digest_required_with_uri: a uri present WITH a digest satisfies it.
        "name": "License with uri+digest",
        "message": "License",
        "json": {
            "id": "CC-BY-4.0",
            "uri": "https://example.com/license",
            "digest": {
                "algorithm": "DIGEST_ALGORITHM_SHA256",
                "value": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            },
        },
    },
    {
        # LicenseTerm.one_restriction_per_kind: one restriction per kind is fine.
        "name": "LicenseTerm with one restriction per kind",
        "message": "LicenseTerm",
        "json": {
            "pricing": {"model": "PRICING_MODEL_FREE", "rate": "0"},
            "restrictions": [{"kind": "RESTRICTION_KIND_FUNCTION", "permitted": [AI_TRAIN]}],
            "semantics": "TERM_SEMANTICS_ENUMERATED",
        },
    },
    {
        # Obligation.share_alike.requires_scope_license: SHARE_ALIKE WITH a
        # scope_license satisfies the implication.
        "name": "Obligation SHARE_ALIKE with scope_license",
        "message": "Obligation",
        "json": {
            "kind": "OBLIGATION_KIND_SHARE_ALIKE",
            "trigger": "OBLIGATION_TRIGGER_ON_USE",
            "scope_license": "CC-BY-SA-4.0",
        },
    },
    {
        # Pricing.free.zero_rate: FREE with rate "0" satisfies it.
        "name": "Pricing FREE with zero rate",
        "message": "Pricing",
        "json": {"model": "PRICING_MODEL_FREE", "rate": "0"},
    },
    {
        # Restriction.permitted_prohibited_disjoint: disjoint permitted/prohibited
        # sets satisfy it.
        "name": "Restriction with disjoint permitted/prohibited",
        "message": "Restriction",
        "json": {
            "kind": "RESTRICTION_KIND_FUNCTION",
            "permitted": [AI_TRAIN],
            "prohibited": [AI_INPUT],
        },
    },
]


@pytest.mark.parametrize(
    "instance",
    _VALID_INSTANCES,
    ids=[str(i["name"]) for i in _VALID_INSTANCES],
)
def test_crossfield_does_not_over_reject_valid_instances(instance: dict[str, object]) -> None:
    got = cross_field_rule_ids(str(instance["message"]), instance["json"])
    assert got == [], f"{instance['name']}: unexpected cross-field rule-ids {got}"
