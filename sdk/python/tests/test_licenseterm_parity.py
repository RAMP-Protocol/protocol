"""License-term parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/licenseterm.parity.test.ts.

``ramp_sdk.licenseterm`` MUST reproduce the sdk/go oracle. The shared vectors at
sdk/go/helpers/testdata/licenseterm-vectors.json carry five lists:
  - fold:      {name, kind, token, canonical}
  - normalize: {name, term, normalized}          (proto-JSON, snake_case)
  - known:     {name, kind, token, known}
  - validate:  {name, term, violation|null, warnings[]}
  - entry:     {name, entry, ok, structural, term_rules[], warnings[]}
Every finding is {rule, path, token, message}; the message is the exact wire
string, so the comparison is byte-for-byte, not shape-for-shape.
"""

from __future__ import annotations

import copy
from dataclasses import asdict

import pytest
from conftest import CONFORMANCE_CORPUS, GO_TESTDATA, load_json

from ramp_sdk.licenseterm import (
    RULE_PRICING_UNIT_REGISTERED,
    RULE_QUOTA_METRIC_REGISTERED,
    canonical_restriction_token,
    known_restriction_token,
    normalize_license_term,
    validate_license_term,
    validate_resource_entry,
)

_VECTORS = load_json(GO_TESTDATA / "licenseterm-vectors.json")
_FOLD = _VECTORS["fold"]
_NORMALIZE = _VECTORS["normalize"]
_KNOWN = _VECTORS["known"]
_VALIDATE = _VECTORS["validate"]
_ENTRY = _VECTORS["entry"]
_TERM_RULES = {RULE_PRICING_UNIT_REGISTERED, RULE_QUOTA_METRIC_REGISTERED}

# The registered cross-field rule ids, read from the generated cross-field corpus —
# corpusgen emits one mutant per message-level CEL rule, so its ``rules`` are the
# descriptor's own set. Reading them beats listing them here: the vectors record ids
# the descriptor owns, and this side must classify by the same set or a violation
# lands in the wrong column. A superset is harmless — an id no entry can reach never
# appears in a verdict.
_CROSS_FIELD_RULES = {
    rule for case in load_json(CONFORMANCE_CORPUS / "crossfield.json") for rule in case.get("rules", [])
}


def test_vector_lists_nonempty() -> None:
    for lst in (_FOLD, _NORMALIZE, _KNOWN, _VALIDATE, _ENTRY):
        assert len(lst) > 0


@pytest.mark.parametrize("vector", _FOLD, ids=[v["name"] for v in _FOLD])
def test_fold_matches_go_oracle(vector: dict) -> None:
    assert canonical_restriction_token(vector["kind"], vector["token"]) == vector["canonical"]


@pytest.mark.parametrize("vector", _NORMALIZE, ids=[v["name"] for v in _NORMALIZE])
def test_normalize_matches_go_oracle(vector: dict) -> None:
    before = copy.deepcopy(vector["term"])
    got = normalize_license_term(vector["term"])
    assert got == vector["normalized"]
    assert vector["term"] == before  # the input is never modified
    assert normalize_license_term(got) == vector["normalized"]  # idempotent


@pytest.mark.parametrize("vector", _KNOWN, ids=[v["name"] for v in _KNOWN])
def test_known_matches_go_oracle(vector: dict) -> None:
    assert known_restriction_token(vector["kind"], vector["token"]) is vector["known"]


@pytest.mark.parametrize("vector", _VALIDATE, ids=[v["name"] for v in _VALIDATE])
def test_validate_matches_go_oracle(vector: dict) -> None:
    verdict = validate_license_term(vector["term"])
    got_violation = None if verdict.violation is None else asdict(verdict.violation)
    assert got_violation == vector["violation"]
    assert [asdict(w) for w in verdict.warnings] == vector["warnings"]


@pytest.mark.parametrize("vector", _ENTRY, ids=[v["name"] for v in _ENTRY])
def test_entry_matches_go_oracle(vector: dict) -> None:
    before = copy.deepcopy(vector["entry"])
    verdict = validate_resource_entry(vector["entry"])
    assert vector["entry"] == before
    assert verdict.ok is vector["ok"]
    # Three columns, three strengths — the same split the emitter records: whole
    # findings for the SDK-owned ingest tier, ids for the cross-field rules the proto
    # owns, and a bare boolean for the field-level ids that are Pydantic's here and
    # protovalidate's in the oracle.
    term_rules = [asdict(v) for v in verdict.violations if v.rule in _TERM_RULES]
    cross_field = [v.rule for v in verdict.violations if v.rule in _CROSS_FIELD_RULES]
    structural = any(
        v.rule not in _TERM_RULES and v.rule not in _CROSS_FIELD_RULES for v in verdict.violations
    )
    assert structural is vector["structural"]
    assert cross_field == vector["cross_field_rules"]
    assert term_rules == vector["term_rules"]
    assert [asdict(w) for w in verdict.warnings] == vector["warnings"]
