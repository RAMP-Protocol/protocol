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

import base64
import json
from typing import Any, get_args

import pytest
from conftest import GO_TESTDATA, load_json

from ramp_sdk.regschema import (
    MAX_PORTABLE_REPEAT,
    MAX_REGISTRATION_FIELD_ERROR_PATH_LEN,
    MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN,
    MAX_REGISTRATION_FIELD_ERRORS,
    MAX_REGISTRATION_SCHEMA_BYTES,
    MAX_REGISTRATION_SCHEMA_DEPTH,
    MAX_REGISTRATION_DATA_BYTES,
    MAX_REGISTRATION_DATA_MEMBERS,
    MAX_REGISTRATION_SCHEMA_EVALUATIONS,
    REGISTRATION_SCHEMA_DIALECT,
    RegistrationDataVerdict,
    SchemaVerdict,
    _PORTABLE_ESCAPES,
    _PORTABLE_SYNTAX_ESCAPES,
    check_registration_data,
    compile_registration_schema,
    is_safe_schema_pattern,
)

_DOC = load_json(GO_TESTDATA / "registration-schema-vectors.json")
_COMPILE = _DOC["compile"]
_VALIDATE = _DOC["validate"]
_PATTERN = _DOC["pattern"]
_MATCH = _DOC["match"]
_REGDATA = _DOC["registration_data"]


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
    assert MAX_REGISTRATION_DATA_BYTES == _DOC["max_registration_data_bytes"]
    assert MAX_REGISTRATION_DATA_MEMBERS == _DOC["max_registration_data_members"]
    # The alphabet itself, not a description of it. Dropping an escape from all three
    # SDKs used to leave every gate green; this is what makes that go red.
    admitted = _PORTABLE_ESCAPES | _PORTABLE_SYNTAX_ESCAPES
    assert "".join(sorted(admitted)) == _DOC["portable_pattern_escapes"]


def _vector_bytes(vector: dict[str, Any]) -> bytes:
    """The input a vector states. Most carry it as text; the encoding cases carry it as
    base64, because invalid UTF-8 cannot be written into a JSON string at all and the
    rules are defined over the bytes AS SERVED."""
    if "schema_b64" in vector:
        return base64.b64decode(vector["schema_b64"])
    return str(vector["schema"]).encode("utf8")


@pytest.mark.parametrize("vector", _COMPILE, ids=[v["name"] for v in _COMPILE])
def test_compile_matches_the_oracle(vector: dict[str, Any]) -> None:
    schema, verdict = compile_registration_schema(_vector_bytes(vector))
    assert verdict == vector["expected_verdict"]
    # The schema is usable exactly when it was accepted — a port that returned a
    # compiled schema alongside a refusal would let a caller ignoring the verdict
    # enforce a schema the rules rejected.
    assert (schema is not None) is (verdict == "accepted")


@pytest.mark.parametrize("vector", _VALIDATE, ids=[v["name"] for v in _VALIDATE])
def test_validate_matches_the_oracle(vector: dict[str, Any]) -> None:
    schema, verdict = compile_registration_schema(_vector_bytes(vector))
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


@pytest.mark.parametrize("vector", _REGDATA, ids=[v["name"] for v in _REGDATA])
def test_registration_data_bounds_match_the_oracle(vector: dict[str, Any]) -> None:
    """The bounds on a SUBMITTED payload, which are the other half of the resource
    story: the schema's caps bound the schema, and validation cost is the schema's cost
    multiplied by the elements in the payload.

    The boundary cases are what pin the UNIT. registration_data is not served as bytes —
    it arrives decoded — so the rule names an encoding, and a port measuring its own
    language's rendering instead would agree on the easy cases and part on these.
    """
    assert check_registration_data(vector["data"]) == vector["expected_verdict"]


def test_a_non_finite_number_is_a_verdict_not_an_exception() -> None:
    """The one outcome the shared corpus cannot carry: JSON has no way to write NaN or
    Infinity, which is exactly why a payload holding one has no canonical form — and a
    decoded map can still hold one, because the value came from a language rather than
    from a JSON document."""
    for value in (float("inf"), float("-inf"), float("nan")):
        assert check_registration_data({"n": value}) == "uncanonicalizable"


def test_an_integer_measures_as_the_double_the_wire_will_carry() -> None:
    """The one divergence this port could have had all to itself.

    ``registration_data`` is a Struct, whose only numeric type is a double, so the other
    two SDKs never see an integer at all — their decoded numbers are already doubles.
    This language keeps them, and the canonicalizer refuses any outside the 2**53 safe
    domain, so an unconverted payload would answer ``uncanonicalizable`` here and
    ``accepted`` there. The corpus cannot state this case, because JSON has one numeric
    type and the distinction does not survive the file.
    """
    assert check_registration_data({"n": 10**16}) == "accepted"
    assert check_registration_data({"n": 2**53 + 1}) == "accepted"
    # Nested, and through a list, since the coercion has to be total to be worth having.
    assert check_registration_data({"a": {"b": [10**16]}}) == "accepted"
    # A bool subclasses int here and must not be rendered as a number.
    assert check_registration_data({"flag": True}) == "accepted"


def test_the_payload_face_answers_rather_than_raising() -> None:
    """Three inputs this port could hit an exception on, where the other two SDKs answer.

    The face is documented as returning a verdict for every way a payload can fail, and
    a caller that let an exception escape would crash the request — or, wrapping it
    broadly, read the crash as "no schema" and turn enforcement off.

    The 600-deep case is the one where this port is deliberately STRICTER than Go, which
    accepts a payload that deep: the canonicalizer walks it recursively and this
    interpreter runs out of stack first. Closing that difference needs a nesting bound in
    the contract, which is a publishing rule rather than a port fix, so it is recorded
    here rather than hidden. What matters for this test is that it answers.
    """
    deep: dict[str, Any] = {}
    cur = deep
    for _ in range(600):
        cur["a"] = {}
        cur = cur["a"]
    for name, payload in (
        ("a non-finite number", {"n": float("inf")}),
        ("an integer too large for a double", {"n": 10**400}),
        ("a payload nested past the recursion limit", deep),
    ):
        assert check_registration_data(payload) == "uncanonicalizable", name


def test_a_long_flat_reference_chain_does_not_exhaust_the_stack() -> None:
    """The compile face walks references iteratively.

    A flat chain is three containers deep however long it is, so the lexical depth cap
    never sees it, while the walk that follows references sees one link per definition. A
    recursive walk raised RecursionError on a document well under the size cap. The
    shared corpus carries this case too; this asserts the property directly, at a length
    the corpus does not have to encode.
    """
    links = 560
    defs = {str(i): {"$ref": f"#/$defs/{i + 1}"} for i in range(links)}
    defs[str(links)] = {"type": "string"}
    raw = json.dumps({"$defs": defs, "$ref": "#/$defs/0"}, separators=(",", ":")).encode()
    assert len(raw) <= MAX_REGISTRATION_SCHEMA_BYTES
    assert compile_registration_schema(raw)[1] == "accepted"


def test_the_verdict_vocabularies_match_the_oracle() -> None:
    """The corpus emits both lists so a port that grew a verdict the oracle does not
    have, or lost one it does, is caught by comparing the list rather than by whichever
    cases happen to exercise each token. Nothing read them until now, so this port's
    hand-written Literal could drift from the oracle with every gate green."""
    assert list(get_args(SchemaVerdict)) == _DOC["verdicts"]
    assert list(get_args(RegistrationDataVerdict)) == _DOC["registration_data_verdicts"]
