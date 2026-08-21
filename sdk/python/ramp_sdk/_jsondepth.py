"""How deep a JSON document nests, counted without parsing it.

Shared, because two readers need the same answer for the same reason and a second
transcription of a security rule is how the three languages drifted apart elsewhere.

Every JSON parser across the three SDKs descends recursively, and Python's aborts on a
deeply nested document in a way that is not a verdict at all: ``json.loads`` raises
``RecursionError``, which is neither what a malformed document raises nor a failure any of
these packages says it raises. A depth check placed AFTER the parse is reached only by
documents harmless enough to parse — precisely the ones that did not need it.

So the scan is lexical and runs first. Counting needs no recursion.

Two callers today: the registration-schema compiler, reading a schema out of a third
party's manifest, and the client's response reader, reading whatever a peer answered.
"""

from __future__ import annotations

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
