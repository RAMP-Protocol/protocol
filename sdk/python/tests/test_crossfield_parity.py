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
    "GetAccountStatusResponse",
    "License",
    "LicenseTerm",
    "Obligation",
    "Pricing",
    "RegistrationFailure",
    "Restriction",
    "WellKnownManifest",
}


def test_crossfield_corpus_shape() -> None:
    # >=8 mutants across exactly the cross-field messages named above.
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
    {
        # field_errors_scoped_to_invalid_data: the member list WITH the one
        # reason it belongs to.
        "name": "RegistrationFailure INVALID_REGISTRATION_DATA with field_errors",
        "message": "RegistrationFailure",
        "json": {
            "reason": "REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA",
            "field_errors": [{"path": "/vat_id", "error": "required"}],
        },
    },
    {
        # The other side: any other reason, carrying no member list.
        "name": "RegistrationFailure TERMS_DIGEST_STALE without field_errors",
        "message": "RegistrationFailure",
        "json": {"reason": "REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE"},
    },
    {
        # terms_digest_requires_billing_ref: a digest WITH the account it hangs on.
        "name": "GetAccountStatusResponse with billing_ref+terms_digest",
        "message": "GetAccountStatusResponse",
        "json": {
            "ver": "1.0",
            "billing_ref": "acct-1",
            "active": True,
            "terms_digest": "sha256:" + "ab" * 32,
        },
    },
    {
        # An account whose Exchange publishes no terms digest, so none was recorded.
        # This is the instance that catches a predicate inverted to fire on a MISSING
        # terms_digest rather than on an accountless one.
        "name": "GetAccountStatusResponse with an account and no digest",
        "message": "GetAccountStatusResponse",
        "json": {"ver": "1.0", "billing_ref": "acct-1", "active": True},
    },
    {
        # The answer to an agent that has not registered: no account, so no digest
        # either. Catches a predicate that fires on a missing billing_ref alone.
        "name": "GetAccountStatusResponse with no account at all",
        "message": "GetAccountStatusResponse",
        "json": {"ver": "1.0", "billing_ref": "", "active": False},
    },
    {
        # terms_digest_requires_terms_uri: a digest WITH the address it pins.
        "name": "WellKnownManifest with terms_uri+terms_digest",
        "message": "WellKnownManifest",
        "json": {
            "ver": "1.0",
            "role": "ROLE_EXCHANGE",
            "domain": "exchange.example",
            "terms_uri": "https://exchange.example/terms",
            "terms_digest": "sha256:" + "ab" * 32,
        },
    },
    {
        # The common case the rule must NOT reject: no terms document at all.
        # Both members are optional, so a manifest publishing neither is clean —
        # this is the instance that catches a predicate inverted to fire on a
        # missing terms_uri rather than on an unpinned digest.
        "name": "WellKnownManifest with neither terms member",
        "message": "WellKnownManifest",
        "json": {"ver": "1.0", "role": "ROLE_EXCHANGE", "domain": "exchange.example"},
    },
]


def test_every_registered_message_has_a_valid_instance() -> None:
    """Pins the two lists together. A cross-field rule registered without a valid
    instance is a rule whose predicate can be inverted while the suite stays green:
    the corpus mutants only prove OVER-acceptance is caught, never over-rejection."""
    covered = {str(i["message"]) for i in _VALID_INSTANCES}
    assert covered == _EXPECTED_MESSAGES, (
        f"messages without a valid instance: {sorted(_EXPECTED_MESSAGES - covered)}"
    )


def test_every_registered_rule_has_a_composed_model() -> None:
    """Pins the REGISTRY to the COMPOSED EXPORTS.

    These are two hand-maintained lists that must agree, and nothing made them agree
    before: a rule was added to the registry and the matching composed model was not,
    so ``cross_field_rule_ids`` answered correctly while the composed model — the
    surface a consumer is told to use — accepted the payload the rule forbids. The Go
    oracle refused it. Two conformant readers, two answers.

    Compare by NAME rather than by asking each model what it validates, because the
    failure being guarded is a MISSING model: a check that iterates over the models
    that exist can never see the one that was never created.
    """
    from ramp_sdk import crossfield as _cf

    composed = {n[: -len("CrossField")] for n in dir(_cf) if n.endswith("CrossField")}
    registered = set(_cf._RULES_BY_MESSAGE)  # noqa: SLF001
    assert composed == registered, (
        f"registered but not composed: {sorted(registered - composed)}; "
        f"composed but not registered: {sorted(composed - registered)}"
    )


def test_the_composed_model_actually_refuses_a_corpus_mutant() -> None:
    """The set-equality test above proves a model EXISTS, not that it is wired up.

    A composed model built from the wrong message name, or one whose validator never
    runs, still passes it. So drive real corpus mutants through the composed models and
    require the refusal, which is the behaviour a consumer depends on.

    Only the mutants the BASE model accepts can prove anything here. The corpus carries
    minimal JSON, so many mutants are also missing a field-level requirement, and the
    composed model then refuses before the cross-field validator ever runs — a refusal
    that would pass this test while proving nothing about the layer under test. Those
    are skipped deliberately, and the count is asserted so the skip cannot quietly
    become "all of them".
    """
    import pydantic

    from ramp_sdk import crossfield as _cf

    import wire.models as _wire

    checked = 0
    for case in _CASES:
        if case["valid"]:
            continue
        model = getattr(_cf, f"{case['message']}CrossField", None)
        assert model is not None, f"no composed model for {case['message']}"

        base = getattr(_wire, str(case["message"]))
        try:
            base.model_validate(case["json"])
        except pydantic.ValidationError:
            continue  # field-level refuses it first; see the docstring

        with pytest.raises(pydantic.ValidationError) as excinfo:
            model.model_validate(case["json"])
        rendered = str(excinfo.value)
        for rule_id in case["rules"]:
            assert rule_id in rendered, (
                f"{case['id']}: composed model refused, but not for {rule_id}"
            )
        checked += 1

    assert checked, (
        "every crossfield mutant was already refused at field level, so this test "
        "exercised no composed validator at all"
    )


@pytest.mark.parametrize(
    "instance",
    _VALID_INSTANCES,
    ids=[str(i["name"]) for i in _VALID_INSTANCES],
)
def test_crossfield_does_not_over_reject_valid_instances(instance: dict[str, object]) -> None:
    got = cross_field_rule_ids(str(instance["message"]), instance["json"])
    assert got == [], f"{instance['name']}: unexpected cross-field rule-ids {got}"
