"""ErrorDetail CONSTRUCT-side parity (Python) — write-half replay of the Go corpus.

Sibling of the read-side test_errordetail_parity.py and the TS construct leg
sdk/ts/tests/errordetail-construct.parity.test.ts. Where the read-side suite proves
Python can PARSE the shared Go-oracle ErrorDetail wire, this suite proves Python can
CONSTRUCT it: the 7 typed domain error-detail builders — the Python peers of the Go
sdk/go/helpers.*Detail constructors (errordetail.go:24-75) — must, from
(domain, message, reason), emit byte-for-byte the same canonical proto-JSON the Go
emitter recorded in error-detail-vectors.json.

RED until the builders exist: importing the 7 builder symbols from
``ramp_sdk.errordetail`` is the failing collection error — the builders are absent
(only the READ half parse_error_detail/reason/error_detail_from exists today).

The replay honors the binding recipe on agentic-content-access:
  1. detail = <builder for vector.reason family>(domain, message, reason_enum)
     — arity is exactly (domain, message, reason); the builder sets ONLY the oneof
     reason block, mirroring Go which omits sub-fields (offer_id, rejected_paths, …).
  2. IF the vector carries metadata, apply it POST-construction (detail.metadata =
     vector metadata) — mirroring the Go emitter, which sets multiKey.Metadata AFTER
     base(). The builder OMITS metadata by design; this is why the
     multi_key_metadata_with_reason vector does not fail.
  3. Assert FULL-object byte-parity DIRECT to the Go oracle wire:
     detail.model_dump(mode="json", exclude_none=True) == vector["wire_json"]
     — strictly stronger than a parse round-trip.

The corpus today vectors only 2 of the 7 reason families (transaction_denial,
retrieval_auth_failure); the implement step adds the other 5 vectors + builders.
This suite iterates over ALL reason-carrying vectors present, so it is red now (the
builder import fails) and goes green covering every family the corpus exercises.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED before the builders exist: these 7 names do not yet exist in
# ramp_sdk.errordetail (only the read-side parse_error_detail/reason live there), so
# this import is a collection-time failure — the TDD-red anchor of this task.
from ramp_sdk.errordetail import (  # type: ignore[attr-defined]
    catalog_rejection_detail,
    dispute_failure_detail,
    domain_verification_failure_detail,
    registration_failure_detail,
    retrieval_auth_failure_detail,
    transaction_denial_detail,
    usage_report_rejection_detail,
)

# reason-oneof family (the vector's reason_field) -> the typed builder that owns it.
# Covers all 7 families even though the corpus vectors only some of them today, so a
# vector for any family added later dispatches without touching this test.
_BUILDERS = {
    "transaction_denial": transaction_denial_detail,
    "catalog_rejection": catalog_rejection_detail,
    "retrieval_auth_failure": retrieval_auth_failure_detail,
    "dispute_failure": dispute_failure_detail,
    "registration_failure": registration_failure_detail,
    "domain_verification_failure": domain_verification_failure_detail,
    "usage_report_rejection": usage_report_rejection_detail,
}

_VECTORS = load_json(GO_TESTDATA / "error-detail-vectors.json")["vectors"]
_REASON_VECTORS = [v for v in _VECTORS if v["reason_field"] != ""]


def test_construct_side_has_reason_vectors_to_replay() -> None:
    """Guards against a silently-empty parametrization: at least one reason-carrying
    vector must exist, else the construct-side proof would vacuously pass."""
    assert len(_REASON_VECTORS) > 0


def test_all_seven_builders_are_present() -> None:
    """Every reason family has a typed builder — pins the 5 families whose corpus
    vectors the implement step still has to add (they go green once vectored)."""
    assert set(_BUILDERS) == {
        "transaction_denial",
        "catalog_rejection",
        "retrieval_auth_failure",
        "dispute_failure",
        "registration_failure",
        "domain_verification_failure",
        "usage_report_rejection",
    }
    assert all(callable(b) for b in _BUILDERS.values())


@pytest.mark.parametrize(
    "vector", _REASON_VECTORS, ids=[v["name"] for v in _REASON_VECTORS]
)
def test_builder_emits_go_oracle_wire(vector: dict) -> None:
    """Build the typed detail from (domain, message, reason) via the family's builder
    and assert it serializes byte-for-byte to the Go oracle wire_json."""
    build = _BUILDERS[vector["reason_field"]]

    # Base arity is (domain, message, reason); the reason NAME string coerces to the
    # generated enum member (proto-JSON enums are NAME strings). registration_failure
    # is the one family whose builder takes a fourth argument — the per-member detail
    # its INVALID_REGISTRATION_DATA reason is useless without — so a vector carrying
    # field_errors feeds them BACK to the builder rather than setting them
    # post-construction. Every other family's sub-fields stay caller-set.
    extra = {"field_errors": vector["field_errors"]} if vector.get("field_errors") else {}
    detail = build(vector["domain"], vector["message"], vector["reason_enum"], **extra)

    # metadata is set POST-construction, mirroring the Go emitter (multiKey.Metadata
    # after base()); the builder omits it by design.
    if vector["metadata"]:
        detail.metadata = vector["metadata"]

    assert detail.model_dump(mode="json", exclude_none=True) == vector["wire_json"]
