"""Cross-language parity: the registration-schema rules answer as the Go oracle does.

The corpus at ``sdk/go/helpers/testdata/registration-schema-vectors.json`` is emitted
from the real Go faces. This suite replays it unchanged. A vector change is a
protocol-level change and goes through the vector-owning review, never in as a port
fix — if a case here fails, the port is wrong until proven otherwise.

Three dimensions, and what each is for:

``compile``  which schemas a party may publish at all. Every rule has an accept and
             a refusal, and both caps have both sides of their boundary.
``validate`` what a refusal SAYS: the RFC 6901 pointer, the failed keyword, the
             deterministic order and the 64-item cap.
``pattern``  the regex alphabet on its own, so a refusal that could have come from
             several rules is still attributable to one.

The ``error`` PROSE is deliberately not pinned in any of them:
``RegistrationFieldError.error`` is documented as validator-defined and
non-authoritative, so asserting the wording would fail this port for a difference
the contract explicitly permits. The keyword is pinned instead — it is the same word
in every JSON Schema library. That the prose never carries the submitted value is a
separate, stronger claim, and it is asserted here directly rather than by a vector,
because it is a property of every possible payload rather than of these.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import GO_TESTDATA, load_json

from ramp_sdk.regschema import (
    MAX_PORTABLE_REPEAT,
    MAX_REGISTRATION_FIELD_ERROR_PATH_LEN,
    MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN,
    MAX_REGISTRATION_FIELD_ERRORS,
    MAX_REGISTRATION_SCHEMA_BYTES,
    MAX_REGISTRATION_SCHEMA_DEPTH,
    MAX_REGISTRATION_SCHEMA_EVALUATIONS,
    REGISTRATION_SCHEMA_DIALECT,
    _DIVERGENT_ESCAPES,
    compile_registration_schema,
    is_safe_schema_pattern,
)

_DOC = load_json(GO_TESTDATA / "registration-schema-vectors.json")
_COMPILE = _DOC["compile"]
_VALIDATE = _DOC["validate"]
_PATTERN = _DOC["pattern"]
_MATCH = _DOC["match"]


def test_the_rule_constants_match_the_oracle() -> None:
    """The caps are the corpus's own header, so a port that picked its own numbers
    fails before a single case runs."""
    assert REGISTRATION_SCHEMA_DIALECT == _DOC["dialect"]
    assert MAX_REGISTRATION_SCHEMA_BYTES == _DOC["max_schema_bytes"]
    assert MAX_REGISTRATION_SCHEMA_DEPTH == _DOC["max_schema_depth"]
    assert MAX_REGISTRATION_FIELD_ERRORS == _DOC["max_field_errors"]
    assert MAX_REGISTRATION_FIELD_ERROR_PATH_LEN == _DOC["max_field_error_path_len"]
    assert MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN == _DOC["max_field_error_text_len"]
    assert MAX_REGISTRATION_SCHEMA_EVALUATIONS == _DOC["max_schema_evaluations"]
    assert MAX_PORTABLE_REPEAT == _DOC["max_pattern_repeat"]
    # The alphabet itself, not a description of it. Dropping an escape from all three
    # SDKs used to leave every gate green; this is what makes that go red.
    assert "".join(sorted(_DIVERGENT_ESCAPES)) == _DOC["forbidden_pattern_escapes"]


@pytest.mark.parametrize("vector", _COMPILE, ids=[v["name"] for v in _COMPILE])
def test_compile_matches_the_oracle(vector: dict[str, Any]) -> None:
    schema, verdict = compile_registration_schema(vector["schema"].encode("utf8"))
    assert verdict == vector["expected_verdict"]
    # The schema is usable exactly when it was accepted — a port that returned a
    # compiled schema alongside a refusal would let a caller ignoring the verdict
    # enforce a schema the rules rejected.
    assert (schema is not None) is (verdict == "accepted")


@pytest.mark.parametrize("vector", _VALIDATE, ids=[v["name"] for v in _VALIDATE])
def test_validate_matches_the_oracle(vector: dict[str, Any]) -> None:
    schema, verdict = compile_registration_schema(vector["schema"].encode("utf8"))
    assert verdict == "accepted", f"the case's own schema does not compile: {verdict}"
    assert schema is not None

    violations = schema.violations(vector["data"])
    assert [pointer for pointer, _kw, _text in violations] == vector["expected_paths"]
    assert [keyword for _p, keyword, _text in violations] == vector["expected_keywords"]

    # The public face carries the same pointers, in the same order, in the wire's
    # two-field shape.
    field_errors = schema.validate(vector["data"])
    assert [fe["path"] for fe in field_errors] == vector["expected_paths"]
    for fe in field_errors:
        assert len(fe["path"]) <= MAX_REGISTRATION_FIELD_ERROR_PATH_LEN
        assert 1 <= len(fe["error"]) <= MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN
    assert len(field_errors) <= MAX_REGISTRATION_FIELD_ERRORS


@pytest.mark.parametrize("vector", _PATTERN, ids=[v["name"] for v in _PATTERN])
def test_pattern_alphabet_matches_the_oracle(vector: dict[str, Any]) -> None:
    assert is_safe_schema_pattern(vector["pattern"]) is vector["safe"]


@pytest.mark.parametrize("vector", _MATCH, ids=[v["name"] for v in _MATCH])
def test_pattern_matching_matches_the_oracle(vector: dict[str, Any]) -> None:
    """The dimension whose absence let a whole class of divergence ship.

    The other three record which schemas are ADMITTED; this one records what an
    admitted schema then MATCHES, which is where the three engines silently disagreed
    — ``^abc$`` against ``"abc\\n"`` and ``^\\d+$`` against Arabic-Indic digits both
    conformed here and violated in the other two, with every suite green.
    """
    schema = json.dumps(
        {
            "type": "object",
            "properties": {"vat_id": {"type": "string", "pattern": vector["pattern"]}},
        }
    )
    compiled, verdict = compile_registration_schema(schema.encode("utf8"))
    assert verdict == "accepted", f"the case's own pattern is not admitted: {verdict}"
    assert compiled is not None
    conforms = not compiled.validate({"vat_id": vector["value"]})
    assert conforms is vector["matches"]


def test_field_errors_never_echo_the_submitted_value() -> None:
    """The leakage rule, asserted directly rather than through a vector.

    ``RegistrationFieldError.error`` states the violated constraint and never the
    value, because a refusal travels back over the wire while registration_data is an
    operator's business data. The guard has teeth in Python specifically: jsonschema's
    own ``error.message`` quotes the offending value, and it is the obvious thing to
    reach for.
    """
    sentinel = "ZZTOPSECRETVALUE9999"
    schema, verdict = compile_registration_schema(
        b"""{
            "type":"object",
            "required":["legal_name"],
            "properties":{
                "vat_id":{"type":"string","pattern":"^[A-Z]{2}[0-9]+$","minLength":40},
                "count":{"type":"number","minimum":10},
                "kind":{"enum":["a","b"]},
                "fixed":{"const":"only-this"},
                "tags":{"type":"array","uniqueItems":true}
            },
            "additionalProperties":false
        }"""
    )
    assert verdict == "accepted"
    assert schema is not None

    field_errors = schema.validate(
        {
            "vat_id": sentinel,
            "count": 1,
            "kind": sentinel,
            "fixed": sentinel,
            "tags": [sentinel, sentinel],
            sentinel: sentinel,
            "nonempty": sentinel,
        }
    )
    assert field_errors, "the payload was expected to fail; this guard would assert nothing"
    for fe in field_errors:
        assert sentinel not in fe["error"], f"error text for {fe['path']!r} carries the value"
        assert sentinel not in fe["path"], "pointer carries the submitted value"


def test_a_str_schema_is_refused_rather_than_silently_uncapped() -> None:
    """Both caps are defined over UTF-8 BYTES, and Python will run them against a
    ``str`` without complaining: ``len`` counts characters against a byte cap, and the
    depth scan compares integer byte values against one-character strings, so every
    comparison is False and it returns 0 — the gate does not weaken, it disappears.

    A caller holding a decoded manifest reaches for ``json.dumps``, which returns
    ``str``, so this is the natural mistake rather than an exotic one.
    """
    deep = '{"not":' * 100 + "{}" + "}" * 100
    assert compile_registration_schema(deep.encode("utf8"))[1] == "too_deep"
    with pytest.raises(TypeError, match="BYTES"):
        compile_registration_schema(deep)  # type: ignore[arg-type]

    # And the size cap, where a multi-byte document is far longer in bytes than in
    # characters — 6,037 characters, 18,037 bytes, against a 16,384-byte cap.
    oversize = json.dumps({"type": "object", "description": "€" * 6000}, ensure_ascii=False)
    assert compile_registration_schema(oversize.encode("utf8"))[1] == "too_large"
    with pytest.raises(TypeError, match="BYTES"):
        compile_registration_schema(oversize)  # type: ignore[arg-type]


def test_the_refusing_registry_blocks_a_reference_the_scan_did_not_catch() -> None:
    """The SSRF backstop, exercised past the scan.

    This library's DEFAULT registry resolves an http:// reference by making the
    request — verified against a local listener before this was installed. The scan is
    the rule; a reference that escapes it must still not dial.
    """
    from ramp_sdk.regschema import _REFUSING_REGISTRY

    import jsonschema
    import referencing.exceptions

    validator = jsonschema.Draft202012Validator(
        {"$ref": "http://127.0.0.1:1/pwned"}, registry=_REFUSING_REGISTRY
    )
    with pytest.raises(referencing.exceptions.Unresolvable):
        list(validator.iter_errors("x"))


def test_no_compiled_schema_passes_the_payload_through() -> None:
    """An Exchange that publishes no data_schema accepts registration_data
    uninspected. Nothing to compile means nothing to enforce, which is the contract's
    pass-through case rather than an error."""
    schema, verdict = compile_registration_schema(b"{not json")
    assert verdict == "malformed"
    assert schema is None
