"""Multi-member RFC 8941 Signature-Input dictionary parser + verbatim inner-per-label
extractor — the Python port of Go helpers.parseAllSignatures / rawInnerByLabel /
splitTopLevelMembers (verify.go).

The single-sig verify path (server_verify.py) hand-rolls a minimal ONE-label
parser; the multisig forwarding chain (o3szv) needs the FULL multi-member
dictionary parse plus the exact byte-verbatim inner value each hop's base
terminates with.

Dependency-light on purpose (no new runtime dep, mirroring the existing minimal
single-label parsers). Correctness on ADVERSARIAL headers (quoted-comma, backslash
escapes, top-level splitting, malformed reject) is pinned by
tests/test_multisig_parse_edge.py — the canonical Go golden vectors are
well-behaved and do NOT gate the parser (o3szv R2).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_CREATED_RE = re.compile(r";created=(\d+)")
_EXPIRES_RE = re.compile(r";expires=(\d+)")
_KEYID_RE = re.compile(r';keyid="([^"]*)"')
_ALG_RE = re.compile(r';alg="([^"]*)"')


@dataclass(frozen=True)
class Covered:
    """One covered-component identifier: a lowercased name plus, for a forwarding
    chain link ``"signature";key="sigN"``, the referenced predecessor label."""

    name: str
    chain_key: str | None = None


@dataclass(frozen=True)
class MultisigMember:
    """One parsed Signature-Input dictionary member (one hop's label).

    ``raw_inner`` is the VERBATIM value after ``label=`` — the exact
    @signature-params bytes the hop's signature base must terminate with
    (Go sigParams.RawInner).
    """

    label: str
    raw_inner: str
    covered: tuple[Covered, ...]
    keyid: str | None
    alg: str | None
    created: int | None
    expires: int | None

    @property
    def covered_names(self) -> frozenset[str]:
        """The lowercased covered-component names (for required-set enforcement)."""
        return frozenset(c.name for c in self.covered)


def split_top_level_members(s: str) -> list[str]:
    """Split one SFV dictionary header value on TOP-LEVEL commas.

    Honors quoted strings and their backslash escapes (Go splitTopLevelMembers) —
    a comma inside a quoted keyid must NOT tear the member in two.
    """
    parts: list[str] = []
    start = 0
    in_quote = False
    escaped = False
    for i, c in enumerate(s):
        if escaped:
            escaped = False
        elif c == "\\" and in_quote:
            escaped = True
        elif c == '"':
            in_quote = not in_quote
        elif c == "," and not in_quote:
            parts.append(s[start:i])
            start = i + 1
    parts.append(s[start:])
    return parts


def raw_inner_by_label(values: list[str]) -> dict[str, str]:
    """The VERBATIM value after ``label=`` for each label across the given
    Signature-Input header values (Go rawInnerByLabel). Later occurrences overwrite
    earlier ones, matching SFV dictionary last-wins semantics."""
    out: dict[str, str] = {}
    for v in values:
        for member in split_top_level_members(v):
            eq = member.find("=")
            if eq <= 0:
                continue
            out[member[:eq].strip()] = member[eq + 1 :].strip()
    return out


def _find_quote_end(s: str, open_idx: int) -> int:
    """Index of the closing quote for the string opening at ``open_idx``, honoring
    backslash escapes, or -1 if unterminated."""
    escaped = False
    for i in range(open_idx + 1, len(s)):
        c = s[i]
        if escaped:
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == '"':
            return i
    return -1


def _find_inner_list_end(s: str) -> int:
    """Index of the inner-list closing paren, honoring quoted strings, or -1."""
    in_quote = False
    escaped = False
    for i in range(1, len(s)):
        c = s[i]
        if escaped:
            escaped = False
        elif c == "\\" and in_quote:
            escaped = True
        elif c == '"':
            in_quote = not in_quote
        elif c == ")" and not in_quote:
            return i
    return -1


def _parse_component_param(inner: str, pos: int) -> tuple[str, str, int] | None:
    """Parse one ``;name="val"`` component param at ``pos`` (the ';'); return
    (name, value, next_index) or None on malformed."""
    eq = inner.find("=", pos)
    if eq < 0 or eq + 1 >= len(inner) or inner[eq + 1] != '"':
        return None
    name = inner[pos + 1 : eq]
    v_end = _find_quote_end(inner, eq + 1)
    if v_end < 0:
        return None
    return name, inner[eq + 2 : v_end], v_end + 1


def _parse_covered(inner: str) -> tuple[Covered, ...] | None:
    """Parse an inner-list body (``"c1" "c2";key="v" …``) into ordered covered
    components, or None on a malformed token."""
    items: list[Covered] = []
    i = 0
    n = len(inner)
    while i < n:
        if inner[i] == " ":
            i += 1
            continue
        if inner[i] != '"':
            return None
        name_end = _find_quote_end(inner, i)
        if name_end < 0:
            return None
        name = inner[i + 1 : name_end].lower()
        i = name_end + 1
        chain_key: str | None = None
        while i < n and inner[i] == ";":
            parsed = _parse_component_param(inner, i)
            if parsed is None:
                return None
            pname, pval, i = parsed
            if pname == "key":
                chain_key = pval
        items.append(Covered(name=name, chain_key=chain_key))
    return tuple(items)


def _parse_member(raw: str) -> MultisigMember | None:
    """Parse one ``label=(inner);params`` member, or None on malformed."""
    eq = raw.find("=")
    if eq <= 0:
        return None
    label = raw[:eq].strip()
    raw_inner = raw[eq + 1 :].strip()
    if not raw_inner.startswith("("):
        return None
    close = _find_inner_list_end(raw_inner)
    if close < 0:
        return None
    covered = _parse_covered(raw_inner[1:close])
    if covered is None:
        return None
    tail = raw_inner[close + 1 :]
    created = _CREATED_RE.search(tail)
    expires = _EXPIRES_RE.search(tail)
    keyid = _KEYID_RE.search(tail)
    alg = _ALG_RE.search(tail)
    return MultisigMember(
        label=label,
        raw_inner=raw_inner,
        covered=covered,
        keyid=keyid.group(1) if keyid else None,
        alg=alg.group(1) if alg else None,
        created=int(created.group(1)) if created else None,
        expires=int(expires.group(1)) if expires else None,
    )


def parse_multisig_signature_input(values: list[str]) -> list[MultisigMember] | None:
    """Full multi-label parse of the Signature-Input header values, preserving
    header order. Returns None (clean reject) on any malformed member — never a
    mis-slice into a bogus covered set."""
    members: list[MultisigMember] = []
    for v in values:
        for raw in split_top_level_members(v):
            member = _parse_member(raw)
            if member is None:
                return None
            members.append(member)
    return members or None


def signature_bytes_by_label(sig_header: str) -> dict[str, bytes]:
    """Parse the RFC 9421 ``Signature`` header (``label=:<std-base64>:, …``) into a
    label→raw-bytes map — the per-label lookup the forwarding-chain link resolution
    and the multisig verify loop share (Go signatureBytesForLabel / parseSigLabel)."""
    out: dict[str, bytes] = {}
    for member in split_top_level_members(sig_header):
        eq = member.find("=")
        if eq <= 0:
            continue
        label = member[:eq].strip()
        val = member[eq + 1 :].strip()
        first = val.find(":")
        last = val.rfind(":")
        if first < 0 or last <= first:
            continue
        try:
            out[label] = base64.b64decode(val[first + 1 : last])
        except (ValueError, TypeError):
            continue
    return out


def max_sig_label_n(signature_input: str) -> int:
    """The highest sigN label number present in a Signature-Input value (0 when
    none) — Go maxSignatureLabelN. Backs append's next-label / predecessor lookup."""
    max_n = 0
    for label in raw_inner_by_label([signature_input]):
        if not label.startswith("sig"):
            continue
        suffix = label[3:]
        if suffix.isdigit():
            n = int(suffix)
            max_n = max(max_n, n)
    return max_n
