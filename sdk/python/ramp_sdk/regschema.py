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

import codecs
import json
from typing import Any, Literal

import jsonschema
import referencing.exceptions
import rfc8785
from referencing import Registry

__all__ = [
    "MAX_REGISTRATION_DATA_BYTES",
    "MAX_REGISTRATION_DATA_MEMBERS",
    "MAX_REGISTRATION_FIELD_ERRORS",
    "MAX_REGISTRATION_FIELD_ERROR_PATH_LEN",
    "MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN",
    "MAX_REGISTRATION_SCHEMA_BYTES",
    "MAX_REGISTRATION_SCHEMA_DEPTH",
    "MAX_REGISTRATION_SCHEMA_EVALUATIONS",
    "REGISTRATION_SCHEMA_DIALECT",
    "RegistrationDataVerdict",
    "RegistrationSchema",
    "SchemaVerdict",
    "check_registration_data",
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


# Escape letters every engine spells the same way AND reads the same way. This is an
# ALLOWLIST, and that is the point: the set of escapes the three engines disagree
# about is open-ended, so enumerating it means adding an entry every time somebody
# finds another one. See is_safe_schema_pattern for the full argument.
_PORTABLE_ESCAPES = frozenset("dDwWnrtfv")

# The regex metacharacters an author escapes to mean the character itself. Every
# engine accepts these — they are the characters that NEED escaping, so no dialect can
# refuse them. Escaping anything else is an "identity escape", which ECMA-262 refuses
# under the ``u`` flag that the TypeScript port's validator compiles with.
_PORTABLE_SYNTAX_ESCAPES = frozenset("$()*+./?[\\]^{|}")

# The escapes standing for a SET of characters rather than one. A set cannot be the
# endpoint of a range, and the engines disagree about whether saying so ("[\\w-x]") is
# an error or a reinterpretation.
_SHORTHAND_CLASS_ESCAPES = frozenset("dDwW")

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


_JSON_WHITESPACE = frozenset(b" \t\r\n")


def _is_json_blank(raw: bytes) -> bool:
    """Whether ``raw`` carries nothing but JSON whitespace, which is what "this
    Exchange publishes no data_schema" looks like in bytes.

    The definition is RFC 8259's and nothing wider: space, tab, carriage return and
    line feed. It is deliberately NOT each language's idea of whitespace, because that
    is three different sets — Go's ``unicode.IsSpace`` takes U+00A0 and U+3000, this
    port's ``bytes.strip()`` takes neither, and JavaScript's ``String.trim`` takes both
    plus a leading byte order mark. This gate decides the ENFORCEMENT SWITCH: reading a
    document as blank means reading it as "no schema published", which turns validation
    off. So it has to be the same question in all three, asked over the bytes AS SERVED
    rather than over a decoded string — decoding is itself where one of those
    disagreements lives, and a mark or an ill-formed byte must survive to reach the rule
    that refuses it.
    """
    return all(b in _JSON_WHITESPACE for b in raw)


def _refuse_json_constant(token: str) -> Any:
    """Reject the JavaScript-only numeric literals. RFC 8259 §6 excludes Infinity and
    NaN from the JSON grammar; this parser admits them unless told otherwise."""
    msg = f"{token} is not a JSON value"
    raise ValueError(msg)


def _hex_escape_len(pattern: str, i: int) -> int:
    """The length of a ``\\xHH`` escape at ``i``, or 0 if there is not one there.

    Exactly two hex digits: ``\\x41`` is read the same by all three engines, while the
    brace form ``\\x{41}`` is an RE2 spelling the other two refuse and a short
    ``\\x4`` is refused by all three.
    """
    if pattern[i : i + 2] != "\\x" or len(pattern) < i + 4:
        return 0
    if not all(c in "0123456789abcdefABCDEF" for c in pattern[i + 2 : i + 4]):
        return 0
    return 4


def _is_range_hyphen(pattern: str, i: int) -> bool:
    """Whether the character at ``i`` is a "-" acting as a range operator inside a
    bracket expression, rather than the literal hyphen a class may end with."""
    return i < len(pattern) and pattern[i] == "-" and i + 1 < len(pattern) and pattern[i + 1] != "]"


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

    The escape rule is an ALLOWLIST rather than a list of the divergent escapes,
    because the divergent set is open-ended: two successive reviews found new
    counterexamples by trying, which is the signature of a rule stated from the wrong
    side. The portable set is small, closed and checkable, and the corpus carries it
    as data so the contract and all three SDKs are compared against one another.

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
            if _hex_escape_len(pattern, i):
                i += 4  # the whole \xHH is consumed, never re-read as syntax
                continue
            nxt = pattern[i + 1]
            if nxt not in _PORTABLE_ESCAPES and nxt not in _PORTABLE_SYNTAX_ESCAPES:
                return False
            # A range whose endpoint is a shorthand CLASS rather than a character —
            # "[\w-x]". RE2 reads it as a range and compiles; this port and ECMA-262
            # under the ``u`` flag both refuse it. Only the adjacency is refused.
            if in_class and nxt in _SHORTHAND_CLASS_ESCAPES and _is_range_hyphen(pattern, i + 2):
                return False
            i += 2  # the escaped character is consumed, never re-read as syntax
            continue
        # The mirror of the case above: "[a-\w]".
        if (
            ch == "-"
            and in_class
            and _is_range_hyphen(pattern, i)
            and pattern[i + 1] == "\\"
            and i + 2 < n
            and pattern[i + 2] in _SHORTHAND_CLASS_ESCAPES
        ):
            return False
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


def _rewrite_dollar(pattern: str) -> str:
    """Rewrite every ``$`` that acts as an anchor into ``\\Z``.

    Python's ``$`` also matches just BEFORE a trailing newline, where RE2 and ECMA-262
    match only at the very end, so without this ``^[A-Z]{2}[0-9]+$`` accepted
    ``"DE12345\\n"`` in this port alone — silently, because every engine compiled the
    pattern and only the verdicts differed. The scan is bracket- and escape-aware, so
    a literal dollar sign in ``[$]`` or ``\\$`` is left alone.
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
    return "".join(out)


_ASCII_SCOPE_OPEN = "(?a:"


def _corrected_pattern_source(pattern: str) -> str:
    """Rewrite one author-written regex into a source that means the SAME thing here
    as it does in RE2 and in ECMA-262.

    Two corrections, both expressed in the SOURCE rather than in compile flags, and
    that is the whole point. This library compiles regexes in four places — the
    ``pattern`` keyword, the ``patternProperties`` keys, the matched-key scan behind
    ``additionalProperties``, and the evaluated-key scan behind
    ``unevaluatedProperties`` — and overriding keywords reached only the first two.
    A registration whose property name was a non-ASCII digit was refused by
    ``additionalProperties`` in the other two SDKs and accepted here, which is exactly
    the split this face exists to prevent. Correcting the source fixes every call site
    at once, including ones a future release of the library might add.

    ``(?a:...)`` is a SCOPED flag rather than the global ``(?a)``. It has to be:
    ``find_additional_properties`` joins every patternProperties key with "|", and a
    global flag anywhere but position 0 is a compile error.

    ``$`` becomes ``\\Z`` because Python's ``$`` also matches just before a final
    newline, so "DE12345\\n" satisfied a "^[A-Z]{2}[0-9]+$" that the other two
    refused. The rewrite is bracket-aware: a ``$`` inside a character class is a
    literal dollar sign.
    """
    return _ASCII_SCOPE_OPEN + _rewrite_dollar(pattern) + ")"


def _authored_pattern_source(pattern: str) -> str:
    """Recover the author's own text from a corrected source, for a refusal an
    operator reads.

    Both rewrites are exactly reversible, and the alphabet is what guarantees it:
    ``\\Z`` is not an admitted escape, so every ``\\Z`` present was inserted here.
    """
    if not pattern.startswith(_ASCII_SCOPE_OPEN) or not pattern.endswith(")"):
        return pattern
    inner = pattern[len(_ASCII_SCOPE_OPEN) : -1]
    out: list[str] = []
    i = 0
    while i < len(inner):
        if inner[i] == "\\" and i + 1 < len(inner):
            out.append("$" if inner[i + 1] == "Z" else inner[i : i + 2])
            i += 2
            continue
        out.append(inner[i])
        i += 1
    return "".join(out)


def _correct_regexes(node: Any) -> Any:
    """Return a copy of the document with every regex-valued position corrected.

    The walk mirrors ``_scan`` exactly, and for the same reasons: a ``const`` holds
    DATA whose contents are never read as keywords, and ``properties``/``$defs`` map
    NAMES to subschemas, so a property literally called "pattern" is a property name
    and not a regex.
    """
    if isinstance(node, list):
        return [_correct_regexes(item) for item in node]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    for key, child in node.items():
        if key in _NON_SCHEMA_KEYWORDS:
            out[key] = child
        elif key == "pattern" and isinstance(child, str):
            out[key] = _corrected_pattern_source(child)
        elif key == "patternProperties" and isinstance(child, dict):
            # The regexes are the KEYS here, which is why overriding the `pattern`
            # keyword never reached them.
            out[key] = {_corrected_pattern_source(k): _correct_regexes(v) for k, v in child.items()}
        elif key in _SCHEMA_MAP_KEYWORDS and isinstance(child, dict):
            out[key] = {name: _correct_regexes(sub) for name, sub in child.items()}
        else:
            out[key] = _correct_regexes(child)
    return out


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
    if keyword == "pattern":
        # The AUTHOR's pattern, not this port's corrected copy: an operator reading a
        # refusal should see the regex their Exchange published.
        return keyword, f"pattern: {_authored_pattern_source(str(error.validator_value))}"
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


# The stock 2020-12 validator. It needs no keyword overrides because the correction
# lives in the schema SOURCE — see _correct_regexes. An earlier version extended the
# `pattern` keyword instead, which reached `pattern` and `propertyNames` and missed
# `patternProperties` keys and the two matched-key scans behind `additionalProperties`
# and `unevaluatedProperties`. Correcting the source reaches every place this library
# compiles a regex, including any a future release adds.
_RampValidator = jsonschema.Draft202012Validator


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
    # BYTES, checked at runtime rather than trusted from the annotation. Both bounds
    # below are defined over UTF-8 bytes, and Python will happily run them against a
    # ``str``: ``len`` then counts characters against a byte cap, and the depth scan
    # compares integer byte values against one-character strings, so every comparison
    # is False and it returns 0 — the gate does not weaken, it disappears. A caller
    # holding a decoded manifest reaches for ``json.dumps``, which returns ``str``, so
    # this is the natural mistake rather than an exotic one. Refusing it loudly is the
    # only safe answer; silently validating a schema neither cap was applied to is not.
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        msg = (
            "compile_registration_schema takes the schema's UTF-8 BYTES as served, "
            f"not {type(raw).__name__} — the size and depth caps are defined over bytes "
            "and cannot be applied to a decoded string. Encode it first."
        )
        raise TypeError(msg)
    raw = bytes(raw)
    if _is_json_blank(raw):
        # Nothing to compile is its own answer, not a malformed document: an Exchange
        # that publishes no data_schema is the contract's ordinary case.
        return None, "not_published"
    if len(raw) > MAX_REGISTRATION_SCHEMA_BYTES:
        return None, "too_large"
    # The ENCODING, still on the raw bytes, because every rule below is stated over a
    # document and this decides WHICH document that is. RFC 8259 forbids adding a byte
    # order mark and lets a parser ignore one, so both policies conform and the choice
    # had to be made once for all three SDKs: ``json.loads`` strips it from bytes and
    # JavaScript's TextDecoder strips it by default, while Go's parser does not, so the
    # same document compiled in two SDKs and was malformed in the third. It is refused
    # — a stripped mark would make the size cap above count three bytes the schema does
    # not contain, and a mark is only valid at the start of a JSON text, never inside
    # the ramp.json member this schema lives in.
    if raw.startswith(codecs.BOM_UTF8):
        return None, "malformed"
    if _raw_nesting_depth(raw) > MAX_REGISTRATION_SCHEMA_DEPTH:
        return None, "too_deep"
    try:
        # parse_constant refuses NaN, Infinity and -Infinity. RFC 8259 excludes them
        # from the grammar, but this parser accepts all three as an extension, so
        # without it a document Go and TypeScript both call malformed compiled here.
        doc = json.loads(raw, parse_constant=_refuse_json_constant)
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
        # discovered when a payload happens to reach the broken keyword. It runs on the
        # document AS PUBLISHED — the corrected copy below is this port's private
        # business and must not be what the author's schema is judged against.
        validator_cls.check_schema(doc)
    except jsonschema.exceptions.SchemaError:
        return None, "uncompilable"
    # Every regex in the document, rewritten to mean here what it means in the other
    # two SDKs. This happens AFTER the metaschema pass and after every rule above, so
    # what is scanned, bounded and validated as a schema is always the published
    # document; only the copy handed to the matcher carries the correction.
    corrected = _correct_regexes(doc)
    # No format_checker is passed, deliberately: format, contentEncoding and
    # contentMediaType stay ANNOTATIONS, never assertions. The three languages'
    # libraries default differently, so leaving this to a default would make the same
    # document conform in one SDK and not in another.
    return RegistrationSchema(validator_cls(corrected, registry=_REFUSING_REGISTRY)), "accepted"


# The submitted payload's size cap, measured as its RFC 8785 canonical JSON encoding.
#
# The UNIT has to be named, and that is the whole point. Every other cap in this module
# is over bytes a party actually served; registration_data is not served as bytes at all
# — it arrives as a decoded google.protobuf.Struct — so "16KB" means nothing until an
# encoding is chosen, and two implementations choosing privately is the disagreement
# this module exists to remove. JCS is the choice because all three SDKs already compute
# it for the signing primitive, and because it pins number formatting: a payload
# carrying 1e300 is seven bytes to one renderer and three hundred to another.
#
# It bounds WORK, not storage. The schema's caps bound the schema; nothing bounded the
# payload the schema is applied to, and validation cost is roughly the schema's cost
# multiplied by the elements in the payload — a subschema under ``items`` is counted
# once by MAX_REGISTRATION_SCHEMA_EVALUATIONS and evaluated once per element.
MAX_REGISTRATION_DATA_BYTES = 16384

# The number of members allowed at the TOP LEVEL of a payload. Top level rather than
# recursive, deliberately: nested bulk is already bounded by the byte cap, and a
# recursive count would refuse a small document that merely nests, which a business
# entity legitimately does (an address is an object).
MAX_REGISTRATION_DATA_MEMBERS = 64

# The outcome of checking a submitted registration_data payload. Tokens are the Go
# oracle's vocabulary verbatim, which is what the shared vectors record.
#
# "no_verdict" is Go's zero value and is never returned here; it is in the vocabulary
# because the corpus carries the whole vocabulary.
RegistrationDataVerdict = Literal[
    "no_verdict",
    "accepted",
    "too_large",
    "too_many_members",
    "uncanonicalizable",
]


def _registration_data_bytes(data: dict[str, Any] | None) -> int:
    """The length of the payload's RFC 8785 canonical JSON encoding. A ``None`` payload
    encodes as the empty object rather than as ``null``, so an absent payload and an
    empty one measure the same."""
    return len(rfc8785.dumps(data if data is not None else {}))


def check_registration_data(data: dict[str, Any] | None) -> RegistrationDataVerdict:
    """Bound a submitted registration_data payload.

    ``data`` is the decoded object. A ``None`` or empty payload is accepted: sending no
    business data is a matter for the published schema's ``required`` list, not for a
    size bound.

    This runs BEFORE :meth:`RegistrationSchema.validate`, for the same reason the
    schema's own size cap runs before the schema is parsed: the bound exists to stop
    work, so it has to precede the work. An Exchange refuses an over-bound payload
    outright — a malformed request rather than a schema failure, so NOT
    REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA, which names non-conformance
    to a published schema and applies only when one is published.
    """
    # Members first: it is a length check, and it bounds the document the canonical
    # encoding below then has to walk.
    if data is not None and len(data) > MAX_REGISTRATION_DATA_MEMBERS:
        return "too_many_members"
    try:
        size = _registration_data_bytes(data)
    except (ValueError, TypeError):
        # The reachable case is a non-finite number, which JSON cannot represent. It is
        # a verdict rather than an exception because this face, like the rest of the
        # registration surface, does not throw.
        return "uncanonicalizable"
    if size > MAX_REGISTRATION_DATA_BYTES:
        return "too_large"
    return "accepted"
