"""Cross-language validation parity (Python / Pydantic side).

Every case in conformance/corpus/cases.json is a proto-JSON instance with the
verdict Go protovalidate assigned it. This asserts the generated Pydantic models
reach the SAME verdict — i.e. the proto -> JSON Schema -> Pydantic pipeline carries
every field-level rule faithfully. The corpus is generated (no rule is restated
here); the Go conformance suite pins it to protovalidate, the drift gate keeps it
fresh, and the TS suite asserts the identical corpus against Zod.

Run:  PYTHONPATH=gen/python pytest gen/python/tests
"""
import json
import pathlib

import pytest

import wire.models as models

CORPUS = pathlib.Path(__file__).resolve().parents[3] / "conformance" / "corpus" / "cases.json"
CASES = json.loads(CORPUS.read_text())


def _accepts(message: str, instance) -> bool:
    cls = getattr(models, message)
    try:
        cls.model_validate(instance)
        return True
    except Exception:
        return False


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_pydantic_matches_go_verdict(case):
    assert hasattr(models, case["message"]), f"no generated model wire.models.{case['message']}"
    accepted = _accepts(case["message"], case["json"])
    assert accepted == case["valid"], (
        f"{case['id']}: Pydantic accepted={accepted} but Go verdict valid={case['valid']} "
        f"(rules={case.get('rules')})"
    )


def test_corpus_is_nonempty():
    # Guard against a silently empty/!-found corpus making the suite vacuous.
    assert len(CASES) > 0
