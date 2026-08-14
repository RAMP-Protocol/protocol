"""Direct behavioral regression for the base64 wire forms of a bytes-rule field.

protoschema renders a bytes field too loose in both rule kinds, so
merge_schema.tighten_bytes_len rewrites them from the bytesgen manifest:

  - bytes.len=32 (the Ed25519 keys, signed_url_hash): protoschema's 43..44
    CHARACTER window also admits a 33-byte value (44 unpadded chars) and a
    31-byte padded value (44 chars with '=='). The rewrite pins the payload to
    exactly 43 chars of ONE alphabet plus optional exact padding.
  - bytes.min_len=1 (the canonical-bytes fields): protoschema's pattern counts
    padding as content, so "==" (zero payload bytes, which Go protojson refuses
    to decode) passed. The rewrite requires the encoded payload chars of at
    least 1 byte BEFORE the padding tail.

The rows live in conformance/testdata/bytes_wire_forms.json, shared with the Zod
harness (gen/ts/tests/bytes_wire_forms.test.ts) and pinned against Go itself by
conformance/bytes_wire_forms_test.go — Go protojson + protovalidate is the oracle
the generated patterns mirror. See that file's $comment for why the generated
corpus cannot cover this axis (protojson re-encodes every bytes value into one
canonical form, so no unpadded, url-safe or malformed string ever appears in a
corpus case).

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_bytes_wire_forms.py -q
"""
import json
import pathlib

import pytest
from pydantic import ValidationError

import wire.models as models

VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parents[3]
     / "conformance" / "testdata" / "bytes_wire_forms.json").read_text()
)

CASES = [
    (f["message"], f["field"], form["value"], form["accepted"])
    for f in VECTORS["fields"]
    for form in VECTORS["form_sets"][f["form_set"]]["forms"]
]


def test_vectors_are_nonempty():
    # Guard against a renamed key or a moved file making the suite vacuous.
    assert CASES, "no bytes wire-form vectors loaded"


@pytest.mark.parametrize(
    "cls_name,field,value,accepted",
    CASES,
    ids=[f"{m}.{f}={v!r}" for m, f, v, _ in CASES],
)
def test_bytes_rules_decide_every_base64_wire_form(cls_name, field, value, accepted):
    cls = getattr(models, cls_name)
    instance = {**VECTORS["bases"][cls_name], field: value}
    if accepted:
        assert cls.model_validate(instance) is not None
    else:
        with pytest.raises(ValidationError):
            cls.model_validate(instance)
