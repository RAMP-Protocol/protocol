"""Safe validation of a published registration schema — Python port of the sdk/go
oracle (``helpers/regschema.go``).

An Exchange MAY publish ``AccountRegistration.data_schema`` in its ``ramp.json``: a
JSON Schema describing the ``RegisterRequest.registration_data`` it expects. Two
parties read that schema and MUST agree — the Exchange enforcing it on the way in,
and a client pre-checking a payload before it signs and sends one. A payload that
passes one and fails the other is the failure this module exists to remove, so the
rules live in the SDK once rather than in each consumer's choice of library.

The client's copy is the harder half: it arrives out of a THIRD PARTY's manifest,
which makes a schema an attacker-influenced input reached before any signature is
checked. Hence: no reference is resolved outside the document, the dialect is
pinned to draft 2020-12, and size, depth and the ``pattern`` alphabet are bounded.
The pattern rule is not only about backtracking — see ``is_safe_schema_pattern``.

Pure: bytes in, verdict out, no IO and no state. Byte-parity-guarded against the Go
oracle by the shared vectors at
``sdk/go/helpers/testdata/registration-schema-vectors.json``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

import jsonschema
import referencing.exceptions
from jsonschema import validators
from referencing import Registry

__all__ = [
    "MAX_REGISTRATION_FIELD_ERRORS",
    "MAX_REGISTRATION_FIELD_ERROR_PATH_LEN",
    "MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN",
    "MAX_REGISTRATION_SCHEMA_BYTES",
    "MAX_REGISTRATION_SCHEMA_DEPTH",
    "MAX_REGISTRATION_SCHEMA_EVALUATIONS",
    "REGISTRATION_SCHEMA_DIALECT",
    "RegistrationSchema",
    "SchemaVerdict",
    "compile_registration_schema",
    "is_safe_schema_pattern",
]

# The published schema's size cap, measured as the UTF-8 bytes of the data_schema
# member AS SERVED in ramp.json — which is why the compile face takes raw bytes
# rather than a decoded document. A re-encoding is a different length than what the
# origin sent, and the cap is defined over what the origin sent.
MAX_REGISTRATION_SCHEMA_BYTES = 16384

# How deeply the schema document may nest, counting JSON containers, so a bare ``{}``
# is depth 1. Deep allOf/$ref chains are the cheapest way to make a compile
# expensive; a real registration schema is three to five levels deep.
MAX_REGISTRATION_SCHEMA_DEPTH = 32

# The number of member failures a refusal may carry — the wire's own bound
# (RegistrationFailure.field_errors declares repeated.max_items = 64), restated so
# the validator never builds a list the contract would reject.
MAX_REGISTRATION_FIELD_ERRORS = 64

# The wire bounds on RegistrationFieldError.path and .error, for the same reason.
MAX_REGISTRATION_FIELD_ERROR_PATH_LEN = 255
MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN = 255

# Bounds the WORK of checking a payload, which the size and depth caps do not:
# ``anyOf`` branches multiply along a reference chain, so a schema can be small and
# shallow and still cost an unbounded amount to evaluate. Cost is linear in this
# count, so the bound is really a time bound expressed as a number a static walk can
# compute and a shared corpus can pin, which a stopwatch cannot.
MAX_REGISTRATION_SCHEMA_EVALUATIONS = 10000

# NOTE on wall-clock bounds. The Go oracle carries a compile timeout, which it can
# enforce because its runtime preempts. This port carries none, deliberately: a
# CPU-bound spin holds the interpreter, a worker thread cannot be cancelled, and a
# signal-based alarm works only on the main thread of the main interpreter — which is
# not where a server validates. A control that cannot preempt the work it names is not
# a control. What bounds this port is entirely static and identical in all three
# languages: the size, depth and evaluation caps, and the pattern alphabet, which
# refuses the nested quantifiers that make backtracking catastrophic in the first
# place. Go's timeout is a language-local backstop, not part of the accepted/refused
# contract, and no admitted schema should ever reach it.

# The only $schema value a published data_schema may name. A document naming none is
# read as this dialect; one naming another is refused rather than validated under
# semantics its author did not intend.
REGISTRATION_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


# SchemaVerdict is the outcome of compiling a published data_schema. The tokens are
# the Go ``SchemaVerdict.String()`` vocabulary verbatim, which is what the shared
# vectors record — a Literal rather than an Enum, matching the sibling
# ``AudienceVerdict``, so a replay compares the same word rather than an ordinal
# whose meaning depends on declaration order.
#
# "no_verdict" is Go's zero value and is never returned by either language; it is in
# the vocabulary because the corpus carries the whole vocabulary.
SchemaVerdict = Literal[
    "no_verdict",
    "accepted",
    "malformed",
    "wrong_dialect",
    "remote_ref",
    "too_large",
    "too_deep",
    "unsafe_pattern",
    "too_complex",
    "ref_cycle",
    "compile_timeout",
    "uncompilable",
    "not_published",
]


# Escape letters whose meaning is not shared by all three SDK engines. Each would
# otherwise let one SDK accept a schema another refuses, or — worse, because it is
# silent — let two SDKs accept the same schema and disagree about which payloads
# match it. See is_safe_schema_pattern for the full argument.
_DIVERGENT_ESCAPES = frozenset("123456789kpPsSAzZQECGK")

# Keywords whose value is arbitrary JSON DATA rather than a subschema. Their
# contents are never read as keywords, so a ``const`` carrying a "$ref" member is a
# value a payload may equal rather than a reference to resolve. Their nesting is
# still bounded, by the lexical depth scan over the raw bytes.
_NON_SCHEMA_KEYWORDS = frozenset({"const", "default", "enum", "examples"})

# Keywords that map NAMES to subschemas. Their child keys are property or definition
# names rather than keywords: ``{"properties": {"$ref": {...}}}`` declares a property
# called "$ref", not a reference.
_SCHEMA_MAP_KEYWORDS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
)

_REFERENCE_KEYWORDS = ("$ref", "$dynamicRef", "$recursiveRef")

_POINTER_ESCAPES = ((("~"), "~0"), ("/", "~1"))


# The largest {n,m} bound admitted. RE2 refuses a repeat count over 1000 outright
# while the other two engines expand it, so a larger bound is a pattern one SDK
# compiles and another does not.
MAX_PORTABLE_REPEAT = 1000


def _is_portable_quantifier(s: str) -> bool:
    """Whether the ``{...}`` starting at ``s`` is a counted repeat every engine reads
    the same way. A ``{`` that opens no valid quantifier is refused rather than
    treated as a literal, because whether it IS a literal is precisely what the
    engines disagree about."""
    end = s.find("}")
    if end < 0:
        return False
    body = s[1:end]
    if not body:
        return False
    for part in body.split(",", 1):
        if not part:
            continue  # "{n,}" is well formed
        if not part.isdigit():
            return False
        if int(part) > MAX_PORTABLE_REPEAT:
            return False
    return True


def _group_body(p: str, open_at: int) -> tuple[str, int] | None:
    """The text between the parenthesis at ``open_at`` and its match, plus the index
    just past the closing parenthesis."""
    depth = 0
    in_class = False
    i = open_at
    n = len(p)
    while i < n:
        ch = p[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "(" and not in_class:
            depth += 1
        elif ch == ")" and not in_class:
            depth -= 1
            if depth == 0:
                return p[open_at + 1 : i], i + 1
        i += 1
    return None


def _strip_escapes(s: str) -> str:
    """Remove escaped characters so an escaped metacharacter (``\\+``) is not read as
    a quantifier."""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _has_nested_quantifier(p: str) -> bool:
    """Whether the pattern quantifies a group whose body can itself repeat or branch —
    the shape that makes a backtracking engine explore exponentially many ways to
    match one input.

    This is the half of the catastrophic-backtracking answer that excluding lookaround
    and backreferences does not cover: nested quantifiers need neither, and every
    classic form — ``(a+)+``, ``(a|a)*``, ``([a-z]+)*``, ``(?:a*)*`` — sits comfortably
    inside the rest of the alphabet. It has to be STATIC: a regex spin holds CPython's
    interpreter, so no timer in this port could stop one.

    Deliberately coarse — a quantified group whose body contains any of ``* + ? { |``.
    Deciding whether a particular body is genuinely ambiguous is not decidable in
    general, and the conservative answer costs an author a rewrite while the permissive
    one costs a service its availability.
    """
    in_class = False
    i = 0
    n = len(p)
    while i < n:
        ch = p[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "(" and not in_class:
            found = _group_body(p, i)
            if found is not None:
                body, after = found
                # A non-capturing group's "?:" is syntax, not content.
                body = body.removeprefix("?:")
                if (
                    after < n
                    and p[after] in "*+?{"
                    and any(c in _strip_escapes(body) for c in "*+?{|")
                ):
                    return True
        i += 1
    return False


def is_safe_schema_pattern(pattern: str) -> bool:
    """Whether a ``pattern`` uses only constructs all three SDK languages express
    identically, and none that make a backtracking engine explode.

    Draft 2020-12 patterns are ECMA-262, and the three SDKs run three different
    engines over them: Go's RE2, JavaScript's RegExp and Python's ``re``. Two distinct
    failures follow, and this function answers only the first.

    Some constructs one engine cannot express at all — RE2 has no lookaround,
    JavaScript has no inline flags — so no care at the call site reconciles them and
    they are refused here. Others every engine compiles and then reads DIFFERENTLY:
    ``\\d`` is Unicode-aware in this port and ASCII in the other two, and ``$`` also
    matches before a trailing newline here. Those are NOT refused — they appear in
    almost every real pattern — they are corrected, by compiling with the ASCII flag
    and rewriting ``$``. See ``_ramp_pattern`` below.

    The last rule is about availability rather than agreement: a quantified group whose
    body can repeat or branch is refused, because that is what makes backtracking
    catastrophic and no timer in this port could stop one.
    """
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                # A trailing backslash is not a pattern any engine compiles.
                return False
            if pattern[i + 1] in _DIVERGENT_ESCAPES:
                return False
            i += 2  # the escaped character is consumed, never re-read as syntax
            continue
        if ch == "[":
            if in_class:
                # A literal "[" inside a class — EXCEPT when it opens a POSIX name.
                # "[:alpha:]" is a character class to RE2 and the literal characters
                # ":alph" to JavaScript: both compile, then match different strings.
                if pattern.startswith("[:", i):
                    return False
                i += 1
                continue
            in_class = True
            rest = pattern[i + 1 :]
            rest = rest.removeprefix("^")
            # "]" straight after the opening bracket is a literal in POSIX and an
            # empty class in ECMA; the engines disagree about whether it compiles.
            if rest.startswith("]") or not rest:
                return False
            if pattern.startswith("[[:", i):
                return False
        elif ch == "]":
            if not in_class:
                # An unmatched "]" is a literal to RE2 and a syntax error to ajv.
                return False
            in_class = False
        elif ch == "(" and not in_class:
            if i + 1 < n and pattern[i + 1] == "?":
                # Everything spelled "(?..." is refused except the non-capturing
                # group, the only one all three engines write the same way. That
                # covers lookaround, the atomic group "(?>", inline flags "(?i)", and
                # the named group whose spelling differs by engine.
                if i + 2 >= n or pattern[i + 2] != ":":
                    return False
                i += 3
                continue
        elif ch == "{" and not in_class:
            if not _is_portable_quantifier(pattern[i:]):
                return False
        i += 1
    # An unclosed class is a literal "[" to RE2 and a syntax error to ajv.
    if in_class:
        return False
    return not _has_nested_quantifier(pattern)


def _ramp_regex(pattern: str) -> re.Pattern[str]:
    """Compile a schema ``pattern`` so this port matches the same strings as the Go
    and JavaScript ones.

    Two corrections, both silent divergences rather than errors — the dangerous kind,
    because every engine compiles the pattern and only the verdicts differ:

    ``re.ASCII`` — ``\\d``, ``\\w``, ``\\s`` and ``\\b`` are Unicode-aware by default for
    ``str`` patterns here and ASCII-only in RE2 and ECMA-262. Without the flag
    ``^\\d+$`` accepts Arabic-Indic digits in this port alone.

    ``$`` becomes ``\\Z`` — Python's ``$`` also matches just BEFORE a trailing newline,
    where RE2 and ECMA-262 match only at the very end. Without the rewrite
    ``^[A-Z]{2}[0-9]+$`` accepts ``"DE12345\\n"`` in this port alone. The rewrite is
    bracket- and escape-aware, so a literal ``$`` in ``[$]`` or ``\\$`` is left alone.
    """
    out: list[str] = []
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "$" and not in_class:
            out.append("\\Z")
            i += 1
            continue
        out.append(ch)
        i += 1
    return re.compile("".join(out), re.ASCII)


def _ramp_pattern(validator: Any, patrn: str, instance: Any, _schema: Any) -> Any:
    """The ``pattern`` keyword, re-implemented over ``_ramp_regex``.

    Overriding the keyword rather than pre-processing the schema keeps the correction
    in one place and leaves the document the Exchange published byte-identical to the
    one this port validates against.
    """
    if validator.is_type(instance, "string") and _ramp_regex(patrn).search(instance) is None:
        yield jsonschema.ValidationError(f"pattern: {patrn}")


def _is_dialect(value: str) -> bool:
    """The 2020-12 identifier in the two spellings that name the same dialect."""
    return value in (REGISTRATION_SCHEMA_DIALECT, REGISTRATION_SCHEMA_DIALECT + "#")


def _check_keywords(obj: dict[str, Any]) -> SchemaVerdict:
    """Per-object rules, in the fixed order a document breaking two must answer."""
    schema_id = obj.get("$schema")
    if isinstance(schema_id, str) and not _is_dialect(schema_id):
        return "wrong_dialect"
    for keyword in _REFERENCE_KEYWORDS:
        ref = obj.get(keyword)
        # A same-document reference starts at the document root ("#/$defs/x") or at
        # an anchor in it ("#name"). Anything else names a resource this document
        # does not carry, and resolving it is the fetch the contract forbids.
        if isinstance(ref, str) and not ref.startswith("#"):
            return "remote_ref"
    pattern = obj.get("pattern")
    if isinstance(pattern, str) and not is_safe_schema_pattern(pattern):
        return "unsafe_pattern"
    # patternProperties states its regexes as KEYS, so they are checked here rather
    # than by the generic pattern branch above.
    pattern_properties = obj.get("patternProperties")
    if isinstance(pattern_properties, dict):
        for key in sorted(pattern_properties):
            if not is_safe_schema_pattern(key):
                return "unsafe_pattern"
    return "accepted"


# JSON structural bytes, named so the lexical scan below reads as JSON rather than
# as arithmetic.
_QUOTE = 0x22
_BACKSLASH = 0x5C
_OPENERS = frozenset({0x7B, 0x5B})  # { [
_CLOSERS = frozenset({0x7D, 0x5D})  # } ]


def _raw_nesting_depth(raw: bytes) -> int:
    """The deepest JSON container nesting in ``raw``, counted lexically — no parse,
    no recursion, one pass over the bytes.

    It is string-aware, so a brace inside a string literal is text rather than a
    container, and escape-aware so a literal quote does not end the string early. It
    does NOT check that the brackets balance: an unbalanced document is the parser's
    to reject, and this only has to produce an upper bound on how deep a parser would
    have to descend.

    Byte-wise rather than character-wise on purpose. Every delimiter it looks for is
    ASCII, and no continuation byte of a multi-byte UTF-8 sequence can collide with
    one, so decoding first would cost a pass and change nothing.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == _BACKSLASH:
                escaped = True
            elif byte == _QUOTE:
                in_string = False
            continue
        if byte == _QUOTE:
            in_string = True
        elif byte in _OPENERS:
            depth += 1
            deepest = max(deepest, depth)
        elif byte in _CLOSERS:
            depth -= 1
    return deepest


def _scan_schema_map(child: Any) -> SchemaVerdict:
    """Walk a keyword whose child object maps NAMES to subschemas. The child's keys
    are property or definition names, never keywords, so only its values are read as
    schemas."""
    if not isinstance(child, dict):
        # Not the shape the keyword takes; walk it generically rather than guess. An
        # invalid schema is the compiler's to reject.
        return _scan(child)
    for name in sorted(child):
        verdict = _scan(child[name])
        if verdict != "accepted":
            return verdict
    return "accepted"


def _scan(node: Any) -> SchemaVerdict:
    """Walk the decoded document once, enforcing the dialect, reference and pattern
    rules. Depth is NOT its business — ``_raw_nesting_depth`` owns that bound and has
    already run, which is what lets this walk recurse freely. The first failure
    decides."""
    if isinstance(node, dict):
        verdict = _check_keywords(node)
        if verdict != "accepted":
            return verdict
        # Sorted so a document with two faults answers the same way on every run and
        # in every language.
        for key in sorted(node):
            # A non-schema keyword's value is DATA. Its contents are not read as
            # keywords at all, so a ``const`` carrying a "$ref" member is a value a
            # payload may equal rather than a reference to resolve.
            if key in _NON_SCHEMA_KEYWORDS:
                continue
            child = node[key]
            verdict = _scan_schema_map(child) if key in _SCHEMA_MAP_KEYWORDS else _scan(child)
            if verdict != "accepted":
                return verdict
    elif isinstance(node, list):
        for item in node:
            verdict = _scan(item)
            if verdict != "accepted":
                return verdict
    return "accepted"


# --- work bound -----------------------------------------------------------------

# Keywords holding a LIST of subschemas, each of which may be evaluated against the
# same instance. They are what makes cost multiply along a reference chain.
_BRANCH_KEYWORDS = frozenset({"anyOf", "oneOf", "allOf", "prefixItems"})

# Keywords holding exactly one subschema.
_SINGLE_SUBSCHEMA_KEYWORDS = frozenset(
    {
        "not",
        "if",
        "then",
        "else",
        "items",
        "contains",
        "propertyNames",
        "additionalProperties",
        "unevaluatedProperties",
        "unevaluatedItems",
        "contentSchema",
    }
)

# Saturation point. Counting stops here rather than continuing to a number that
# carries no information past the cap.
_COST_CEILING = MAX_REGISTRATION_SCHEMA_EVALUATIONS + 1


class _CostWalker:
    """Counts the worst-case number of subschema evaluations, and — because counting
    means following every reference to its target — also decides whether a reference
    cycle is present and whether a same-document reference resolves at all."""

    def __init__(self, root: Any) -> None:
        self.root = root
        self.anchors: dict[str, Any] = {}
        _collect_anchors(root, self.anchors)
        self.memo: dict[str, int] = {}
        self.on_stack: set[str] = set()
        self.verdict: SchemaVerdict = "accepted"

    def fail(self, verdict: SchemaVerdict) -> int:
        if self.verdict == "accepted":
            self.verdict = verdict
        return _COST_CEILING

    def cost(self, node: Any) -> int:
        """The worst-case evaluations ``node`` can require against one instance: a
        boolean schema is one, an object schema is itself plus everything it can
        delegate to.

        ``$defs`` and ``definitions`` are deliberately NOT counted — they are
        reachable only through a reference, and counting them here as well would
        charge a shared definition once per declaration plus once per use.
        """
        if self.verdict != "accepted":
            return _COST_CEILING
        if not isinstance(node, dict):
            return 1
        total = 1
        for key in sorted(node):
            value = node[key]
            if key in _NON_SCHEMA_KEYWORDS or key in ("$defs", "definitions"):
                continue
            if key in _REFERENCE_KEYWORDS:
                if isinstance(value, str):
                    total = _add_cost(total, self.ref_cost(value))
            elif key in _BRANCH_KEYWORDS:
                if isinstance(value, list):
                    for item in value:
                        total = _add_cost(total, self.cost(item))
                else:
                    total = _add_cost(total, self.cost(value))
            elif key in _SINGLE_SUBSCHEMA_KEYWORDS:
                total = _add_cost(total, self.cost(value))
            elif key in _SCHEMA_MAP_KEYWORDS:
                if isinstance(value, dict):
                    for name in sorted(value):
                        total = _add_cost(total, self.cost(value[name]))
                else:
                    total = _add_cost(total, self.cost(value))
            if total >= _COST_CEILING:
                return _COST_CEILING
        return total

    def ref_cost(self, ref: str) -> int:
        """Count a reference's target once and remember it. A location already being
        counted is a cycle: its cost is not finite, and it is what makes two of the
        three ports abort rather than answer."""
        if ref in self.memo:
            return self.memo[ref]
        if ref in self.on_stack:
            return self.fail("ref_cycle")
        target, ok = self.resolve(ref)
        if not ok:
            return self.fail("uncompilable")
        self.on_stack.add(ref)
        c = self.cost(target)
        self.on_stack.discard(ref)
        self.memo[ref] = c
        return c

    def resolve(self, ref: str) -> tuple[Any, bool]:
        """Follow a same-document reference. The scan has already refused anything not
        beginning with "#", so only three forms reach here: the whole document, an RFC
        6901 pointer into it, and a ``$anchor`` name."""
        frag = ref.removeprefix("#")
        if not frag:
            return self.root, True
        if not frag.startswith("/"):
            if frag in self.anchors:
                return self.anchors[frag], True
            return None, False
        node = self.root
        for raw_token in frag[1:].split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict):
                if token not in node:
                    return None, False
                node = node[token]
            elif isinstance(node, list):
                if not token.isdigit() or int(token) >= len(node):
                    return None, False
                node = node[int(token)]
            else:
                return None, False
        return node, True


def _add_cost(a: int, b: int) -> int:
    if a >= _COST_CEILING or b >= _COST_CEILING or a + b >= _COST_CEILING:
        return _COST_CEILING
    return a + b


def _collect_anchors(node: Any, out: dict[str, Any]) -> None:
    """Index every ``$anchor`` so a "#name" reference resolves without a second walk
    per reference."""
    if isinstance(node, dict):
        anchor = node.get("$anchor")
        if isinstance(anchor, str) and anchor not in out:
            out[anchor] = node
        for key in sorted(node):
            _collect_anchors(node[key], out)
    elif isinstance(node, list):
        for item in node:
            _collect_anchors(item, out)


def _check_evaluation_cost(doc: Any) -> SchemaVerdict:
    """Bound how much work validating a payload can cost. The size and depth caps
    bound the DOCUMENT and say nothing about this."""
    walker = _CostWalker(doc)
    cost = walker.cost(doc)
    if walker.verdict != "accepted":
        return walker.verdict
    if cost > MAX_REGISTRATION_SCHEMA_EVALUATIONS:
        return "too_complex"
    return "accepted"


def _json_pointer(tokens: Any) -> str:
    """Render an instance location as an RFC 6901 pointer. The empty location is the
    empty pointer, which addresses registration_data itself — how a whole-object
    failure that belongs to no single member is reported."""
    out = []
    for token in tokens:
        text = str(token)
        for char, escape in _POINTER_ESCAPES:
            text = text.replace(char, escape)
        out.append("/" + text)
    return "".join(out)


def _clamp_pointer(pointer: str) -> str:
    """Keep a pointer inside the wire's length bound WITHOUT truncating it. A
    pointer cut mid-token addresses a different member — or none — so an over-long
    one degrades to the longest ANCESTOR that fits."""
    if len(pointer) <= MAX_REGISTRATION_FIELD_ERROR_PATH_LEN:
        return pointer
    for i in range(len(pointer) - 1, 0, -1):
        if pointer[i] == "/" and i <= MAX_REGISTRATION_FIELD_ERROR_PATH_LEN:
            return pointer[:i]
    return ""


def _clamp_text(text: str) -> str:
    """Keep the constraint text inside the wire's bound. The field also has a
    minimum of one character, so an empty description becomes a generic one rather
    than a message the contract would reject."""
    if not text:
        return "does not conform to the published schema"
    return text[:MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN]


def _describe(error: jsonschema.ValidationError) -> tuple[str, str]:
    """Turn a failure into ``(keyword, constraint text)``.

    It reads ONLY the constraint side. The library's own ``error.message`` is never
    used, because it quotes the offending value — «'DE12345' does not match
    '^[A-Z]{2}[0-9]+$'» — and the wire contract forbids a refusal from carrying the
    submitted value back out.
    """
    keyword = str(error.validator) if error.validator is not None else "schema"
    if keyword == "required":
        # jsonschema reports one missing property per error; the name comes off the
        # SCHEMA's required list, not off the payload.
        missing = _missing_properties(error)
        return keyword, ("required: " + ", ".join(missing)) if missing else "required"
    if keyword == "type":
        want = error.validator_value
        wanted = want if isinstance(want, list) else [want]
        return keyword, "must be of type " + " or ".join(str(w) for w in wanted)
    if keyword in _BOUND_KEYWORDS:
        # The bound comes off the schema, so naming it leaks nothing and is the one
        # piece of detail that makes a refusal actionable.
        return keyword, f"{keyword}: {error.validator_value}"
    fixed = _FIXED_TEXT.get(keyword)
    if fixed is not None:
        return keyword, fixed
    # Anything the table does not name still reports the keyword that failed, which
    # is enough to act on and carries nothing off the payload by construction.
    return keyword, f"does not satisfy {keyword}"


# Keywords whose constraint is a single schema-side bound worth stating verbatim.
_BOUND_KEYWORDS = frozenset(
    {
        "exclusiveMaximum",
        "exclusiveMinimum",
        "maxContains",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minContains",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "pattern",
    }
)

# Keywords whose constraint has no short value-free rendering, so the text names the
# rule instead. `enum` and `const` deliberately omit the allowed values: they come
# off the schema and would be safe, but they can be long and are not needed to act.
# `additionalProperties` omits the offending member NAMES, which come off the payload
# — a member name an operator chose is as much their data as its value.
_FIXED_TEXT = {
    "additionalProperties": "additional properties are not allowed",
    "allOf": "must match every branch of allOf",
    "anyOf": "must match at least one branch of anyOf",
    "const": "must equal the value the schema fixes",
    "contains": "must contain a matching item",
    "dependentRequired": "dependentRequired",
    "enum": "must be one of the values the schema enumerates",
    "not": "must not match the schema under not",
    "oneOf": "must match exactly one branch of oneOf",
    "propertyNames": "property name does not match propertyNames",
    "uniqueItems": "items must be unique",
}


def _missing_properties(error: jsonschema.ValidationError) -> list[str]:
    """The member names a ``required`` failure names, read from STRUCTURED data.

    This library states them only inside ``error.message``, which is the one place
    this module refuses to read — not merely for the leakage rule (a required
    failure's message names a member the SCHEMA demands, so it would be safe) but
    because the message is not parseable: it renders the name with ``repr``, which
    switches to double quotes when the name itself contains an apostrophe, so a
    member called ``o'brien`` silently dropped out of the refusal and the operator was
    told only that something was required.

    The set difference is exact and needs no parsing. It also renders the whole set at
    once, matching the Go oracle, which reports every missing member in one entry.
    """
    required = error.validator_value
    instance = error.instance
    if not isinstance(required, list) or not isinstance(instance, dict):
        return []
    return sorted(str(name) for name in required if name not in instance)


class RegistrationSchema:
    """A compiled, accepted data_schema. Immutable and safe to share, so a server
    compiles the operator's schema once at start-up and a client caches one per
    Exchange."""

    __slots__ = ("_validator",)

    def __init__(self, validator: jsonschema.protocols.Validator) -> None:
        self._validator = validator

    def validate(self, data: dict[str, Any] | None) -> list[dict[str, str]]:
        """Check a registration_data payload and name what failed.

        An empty list means the payload conforms. Each entry is a
        ``{"path", "error"}`` mapping ready for ``registration_failure_detail``:
        ``path`` an RFC 6901 pointer relative to registration_data (``""`` addresses
        the whole object), ``error`` the violated CONSTRAINT and never the submitted
        value.

        The order is deterministic — entries are deduplicated by pointer and keyword,
        then sorted by both, before the list is capped. Three validators walk a
        failing document in three different orders, so an unsorted list is one no
        shared corpus could pin.
        """
        return [
            {"path": path, "error": _clamp_text(text)}
            for path, _keyword, text in self.violations(data)
        ]

    def violations(self, data: dict[str, Any] | None) -> list[tuple[str, str, str]]:
        """The whole answer as ``(pointer, keyword, text)`` triples.

        ``validate`` narrows this to the wire's two-field shape; the parity suite
        reads it whole, because the corpus pins the KEYWORD — the same word in every
        JSON Schema library — while ``error`` wording is validator-defined by
        contract and deliberately not pinned.
        """
        instance: Any = {} if data is None else data
        flat: list[tuple[str, str, str]] = []
        seen: dict[tuple[str, str], int] = {}

        def walk(error: jsonschema.ValidationError) -> None:
            if error.context:
                for cause in error.context:
                    walk(cause)
                return
            keyword, text = _describe(error)
            pointer = _clamp_pointer(_json_pointer(error.absolute_path))
            key = (pointer, keyword)
            at = seen.get(key)
            if at is not None:
                # Where a key repeats, the lexicographically smallest text wins, so
                # the prose does not depend on which duplicate was walked first.
                if text < flat[at][2]:
                    flat[at] = (pointer, keyword, text)
                return
            seen[key] = len(flat)
            flat.append((pointer, keyword, text))

        for error in self._validator.iter_errors(instance):
            walk(error)
        flat.sort(key=lambda entry: (entry[0], entry[1]))
        return flat[:MAX_REGISTRATION_FIELD_ERRORS]


# The 2020-12 validator with RAMP's corrected `pattern` keyword. Built once: extending
# a validator compiles a new class, and doing that per schema would be wasteful.
_RampValidator = validators.extend(jsonschema.Draft202012Validator, {"pattern": _ramp_pattern})


def _refuse_retrieve(uri: str) -> Any:
    """The SSRF backstop. Every reference that reaches here has already escaped the
    scan, so the only correct answer is to refuse — never to dial."""
    raise referencing.exceptions.Unretrievable(uri)


# An empty registry that refuses to fetch. Without it this library's default registry
# will resolve an http:// reference by making the request, which is precisely the
# fetch the contract forbids; the scan is the rule, and this is the layer beneath it.
_REFUSING_REGISTRY: Registry[Any] = Registry(retrieve=_refuse_retrieve)


def _decode(raw: bytes) -> tuple[Any, SchemaVerdict]:
    """The pre-parse gauntlet: the two bounds that must hold BEFORE a parser sees the
    document, then the parse, then the top-level shape.

    Size first, on the bytes as served: an oversized document must not be decoded to
    find out that it was oversized.

    Depth second, and still on the raw bytes — before the document is handed to a
    JSON parser rather than after. Every parser across the three SDKs descends
    recursively, and this one aborts on a deeply nested document in a way that is not
    a verdict at all: ``json.loads`` raises ``RecursionError``, which is not the
    exception a malformed document raises. A depth check placed after the parse would
    therefore be reached only for documents harmless enough to parse — precisely the
    ones it is not needed for. Lexical counting needs no recursion.
    """
    if not raw.strip():
        # Nothing to compile is its own answer, not a malformed document: an Exchange
        # that publishes no data_schema is the contract's ordinary case.
        return None, "not_published"
    if len(raw) > MAX_REGISTRATION_SCHEMA_BYTES:
        return None, "too_large"
    if _raw_nesting_depth(raw) > MAX_REGISTRATION_SCHEMA_DEPTH:
        return None, "too_deep"
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None, "malformed"
    # A JSON OBJECT and nothing else. 2020-12 admits a bare boolean as a schema, but
    # data_schema is a google.protobuf.Struct, which carries an object — so a boolean
    # cannot reach this face over the wire at all, and admitting one would pin
    # behaviour for a document the contract has no way to transport.
    if not isinstance(doc, dict):
        return None, "malformed"
    return doc, "accepted"


def compile_registration_schema(raw: bytes) -> tuple[RegistrationSchema | None, SchemaVerdict]:
    """Check a published data_schema against every rule and compile it.

    ``raw`` is the schema AS SERVED — the exact UTF-8 bytes of the data_schema member
    in ramp.json — because MAX_REGISTRATION_SCHEMA_BYTES is defined over those bytes.

    The schema is non-None only on ``ACCEPTED``. There is no exception: every way
    this can fail is a property of the schema, and both callers need to know WHICH.
    They read the same refusal differently, and that difference is the contract. A
    CLIENT pre-checking a payload treats any non-accepted verdict as "do not
    pre-check" and sends anyway — the Exchange's enforcement is the deciding one, and
    a client that refused here would block a payload the Exchange would have taken.
    An EXCHANGE compiling its OWN configured schema treats the same verdict as an
    operator misconfiguration, and must not advertise a schema it cannot enforce.
    """
    doc, verdict = _decode(raw)
    if verdict != "accepted":
        return None, verdict
    verdict = _scan(doc)
    if verdict != "accepted":
        return None, verdict
    # The work bound, still before the library is involved. This is also where a
    # reference cycle and a same-document reference that resolves to nothing are
    # found, because counting the cost means following every reference to its target.
    verdict = _check_evaluation_cost(doc)
    if verdict != "accepted":
        return None, verdict

    validator_cls = _RampValidator
    try:
        # check_schema is the metaschema pass; without it an invalid document is only
        # discovered when a payload happens to reach the broken keyword.
        validator_cls.check_schema(doc)
    except jsonschema.exceptions.SchemaError:
        return None, "uncompilable"
    # No format_checker is passed, deliberately: format, contentEncoding and
    # contentMediaType stay ANNOTATIONS, never assertions. The three languages'
    # libraries default differently, so leaving this to a default would make the same
    # document conform in one SDK and not in another.
    return RegistrationSchema(validator_cls(doc, registry=_REFUSING_REGISTRY)), "accepted"
