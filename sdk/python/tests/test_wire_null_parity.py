"""A null is how the wire spells "no value", and every SDK has to read one.

Replays the Go-emitted null wire-policy corpus (wire-null-vectors.json). Python already
accepted every one of these — its generated models spell the fields ``X | None`` — so this
suite is not where the bug was. It is here because the corpus is the thing that says the
rule once for all three languages, and a rule only one language is held to is how the two
drifted apart in the first place: TypeScript refused bodies Go and Python read, and nothing
failed, because no vector carried a null on anything but a message field.

Mirrors sdk/ts/tests/wire-null.parity.test.ts.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from conftest import GO_TESTDATA, load_json
from wire.models import RateLimitInfo, ResourceAttestation, ResourceResponse

_VECTORS: list[dict[str, Any]] = load_json(GO_TESTDATA / "wire-null-vectors.json")["vectors"]

# The generated model each case is parsed against. Keyed by the corpus's own name for the
# message, so a case naming a model this suite has not wired up fails loudly rather than
# being skipped into silence.
_MODELS: dict[str, type[BaseModel]] = {
    "ResourceAttestation": ResourceAttestation,
    "RateLimitInfo": RateLimitInfo,
    "ResourceResponse": ResourceResponse,
}


def test_the_vector_set_is_not_empty() -> None:
    assert len(_VECTORS) > 0, "an empty corpus would make every case below vacuous"


@pytest.mark.parametrize("vector", _VECTORS, ids=[str(v["name"]) for v in _VECTORS])
def test_python_reads_what_the_wire_may_carry(vector: dict[str, Any]) -> None:
    model = _MODELS.get(str(vector["message"]))
    assert model is not None, f"no model wired for {vector['message']!r}"
    try:
        model.model_validate(vector["wire_json"])
        accepted = True
    except ValidationError:
        accepted = False
    assert accepted is bool(vector["accepted"]), vector["note"]


def test_a_null_on_a_defaulted_field_is_not_a_value_of_its_own() -> None:
    """The half a boolean verdict cannot carry.

    ACCEPTED alone would be satisfied by a parser that took the null and left the field
    holding anything at all. Go reads it as the field's default, the empty string. Python
    keeps ``None`` and drops it on the way out — ``WireModel.model_dump`` defaults to
    ``exclude_none=True`` — so the two agree on what reaches the wire again, which is the
    property that matters, and differ on the in-memory spelling.
    """
    parsed = ResourceAttestation.model_validate({"keyid": None, "verifier": "v.test"})
    assert parsed.keyid is None
    assert "keyid" not in parsed.model_dump()
