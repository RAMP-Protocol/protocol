"""The one reading of a host reference, shared by the routing predicates in
:mod:`ramp_sdk.hosts` and by the endpoint rule in the resolvers tier.

It is a module of its own, and private, for the reason the Go oracle's internal
``endpointrule`` package gives: the rule is checked in two places for two different
reasons, and written twice it drifts. Stated once here, a refusal decided over one
reading and enforced over another cannot happen — which is exactly the defect that
shipped when the two halves used different parsers.

Nothing here is public API. :mod:`ramp_sdk.hosts` exports the predicates built on
it; these names are internal to the SDK.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class ParsedRef(NamedTuple):
    """One reading of a reference.

    ``host`` is the authority with userinfo removed and the port kept as written;
    ``hostname`` is the host alone, IPv6 brackets stripped and case preserved;
    ``port`` is the port as written, never a default filled in; ``had_scheme``
    records whether the caller actually WROTE one, because a scheme decides which
    port counts as the default and a value that named none must not be treated as
    having named https; ``has_userinfo`` is what the endpoint rule refuses on, and
    it comes from THIS reading — decided over a second, differently-shaped parse it
    disagrees with the anchor check on exactly the shape it exists to stop.
    """

    host: str
    hostname: str
    port: str
    had_scheme: bool
    scheme: str
    has_userinfo: bool


# An authority admits a CLOSED set of ASCII characters; everything outside it is
# refused. Stating the set rather than a list of separators is what makes the
# refusal structural: a separator nobody thought of is already outside it. Code
# points at or above 0x80 are admitted — the oracle's parser keeps them, so a name
# in a non-ASCII script is a usable host even though the wire's domain rule
# refuses it.
_HOST_ASCII = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:[]<>\""
)

# Userinfo admits a DIFFERENT closed set from the host: no ``"``, ``<``, ``>`` or
# ``]``. Reusing the host set here would close the backslash hole and still
# under-refuse four characters the oracle rejects — and the gap is not cosmetic.
# WHATWG treats ``\`` as a fourth authority delimiter in special schemes, so a
# backslash smuggled into userinfo ends the authority early and a fetch reaches an
# entirely different host from the one the anchor check just approved.
_USERINFO_ASCII = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:"
)

# A scheme, and only at the front. The oracle reads ``://`` as a separator solely
# when a valid scheme precedes it at position 0; anywhere else the text is a path.
# Locating the separator by search instead let a path segment supply the host —
# ``evil.example/x://a.example`` answered ``a.example``.
_SCHEME_AT_FRONT = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_BAD_ESCAPE = re.compile("%(?![0-9A-Fa-f]{2})")

# The port a scheme reaches when none is written.
_DEFAULT_PORTS = {"http": "80", "https": "443"}

_ASCII_MAX = 0x80
_DEL = 0x7F
_CONTROL_MAX = 0x20


def _invalid_host(ref: str, why: str) -> ValueError:
    """The Go oracle exposes an ``errors.Is`` sentinel for this; the port raises,
    as :func:`check_audience` does, because a sentinel is not how a caller in this
    language distinguishes causes."""
    return ValueError(f"hosts: reference is not a usable host: {why}: {ref!r}")


def _split_components(rest: str) -> tuple[str, str]:
    """Split what follows ``://`` into its authority and its path.

    The authority ends at the first delimiter that starts a path, query or fragment
    — the three things a reference can carry beyond it — and the path ends where a
    query or fragment begins. They are separated because escapes are read PER
    COMPONENT, exactly as the oracle reads them: a malformed escape is refused in a
    path and admitted in a query, which is not unescaped at parse time. Checking the
    whole reference instead refused ``?q=a%20b``, an ordinary conformant endpoint.
    """
    authority, beyond = rest, ""
    for i, c in enumerate(rest):
        if c in "/?#":
            authority, beyond = rest[:i], rest[i:]
            break
    path = beyond
    for i, c in enumerate(beyond):
        if c in "?#":
            path = beyond[:i]
            break
    return authority, path


def _vet_userinfo(ref: str, userinfo: str) -> None:
    """Refuse a credential the oracle would refuse, over its OWN character set."""
    for c in userinfo:
        # "%" and "@" are excluded from the set check on purpose: escapes are read
        # below, and an "@" before the last one is part of the credential, not a
        # second separator.
        if ord(c) < _ASCII_MAX and c not in "%@" and c not in _USERINFO_ASCII:
            raise _invalid_host(ref, f"invalid character {c!r} in userinfo")
    if _BAD_ESCAPE.search(userinfo):
        raise _invalid_host(ref, "malformed percent-escape in userinfo")


def _parse_ref(ref: str) -> ParsedRef:
    """Read a bare domain, a host:port pair, or a full URL into its authority.

    Returns ``(host, hostname, port, had_scheme, scheme)``: the authority with
    userinfo removed and the port kept as written; the host alone with IPv6
    brackets stripped and case preserved; the port as written, never a default
    filled in; whether the caller actually WROTE a scheme; and the scheme, or
    ``https`` for a reference that named none.

    A ref with no scheme is read as though it carried https, since a bare domain
    is otherwise indistinguishable from a path. One parse behind both host
    predicates, so neither can disagree with the other about what a reference
    even is.

    Deliberately NOT ``urllib.parse``. Two reasons, and both are cross-language:
    the pure tier takes no dependency that dials, and — more to the point —
    ``urlsplit`` strips tabs and newlines the oracle refuses outright, lowercases
    its ``hostname`` accessor, and keeps userinfo inside ``netloc``. Each of those
    is a value where a port built on it answers differently from Go, and the
    shared vectors carry all three.
    """
    if any(ord(c) < _CONTROL_MAX or ord(c) == _DEL for c in ref):
        raise _invalid_host(ref, "control character")
    if ref.strip() == "":
        raise _invalid_host(ref, "empty reference")
    # ``://`` is a separator only behind a valid scheme at the front. A reference
    # that carries the sequence anywhere else is not schemeless — it is malformed,
    # which is what the oracle answers, so treating it as schemeless and prepending
    # https would trade one wrong answer for another.
    had_scheme = "://" in ref
    if had_scheme and not _SCHEME_AT_FRONT.match(ref):
        raise _invalid_host(ref, 'no valid scheme before "://"')
    work = ref if had_scheme else f"https://{ref}"
    sep = work.index("://")
    scheme = work[:sep].lower() if had_scheme else "https"

    # The authority ends at the first delimiter that starts a path, query or
    # fragment — the three things a reference can carry beyond it.
    authority, path = _split_components(work[sep + 3 :])
    if _BAD_ESCAPE.search(path):
        raise _invalid_host(ref, "malformed percent-escape in path")

    # Userinfo is split at the LAST "@", so an "@" inside a credential does not
    # become part of the host.
    has_userinfo = "@" in authority
    userinfo, _, host = authority.rpartition("@")
    if not has_userinfo:
        userinfo, host = "", authority
    if host == "":
        raise _invalid_host(ref, "no host")
    _vet_userinfo(ref, userinfo)
    for c in host:
        # A percent-escape is refused in the HOST, and only there. The oracle admits
        # just the escapes decoding to a byte at or above 0x80, plus %25 — none of
        # which a domain name carries — so refusing the lot costs nothing a caller
        # can use and removes an unescaping step the three languages would each get
        # subtly wrong. Every value the two answers differ on refuses downstream
        # anyway: a host holding a raw high byte anchors to no bare domain.
        if c == "%":
            raise _invalid_host(ref, "percent-escape in the host component")
        if ord(c) < _ASCII_MAX and c not in _HOST_ASCII:
            raise _invalid_host(ref, f"invalid character {c!r} in host")

    hostname, port = _split_host(ref, host)
    return ParsedRef(host, hostname, port, had_scheme, scheme, has_userinfo)


def _split_host(ref: str, host: str) -> tuple[str, str]:
    """Split an authority into its host and its port, as written.

    Brackets are IPv6 syntax and are read as such only at the FRONT: a bracket
    anywhere else is a host that never closed one. Elsewhere the port is read from
    the FIRST colon onward, so a value that merely ENDS in digits does not pass as
    a port — ``a.example::443`` and ``a.example:44:3`` are refused rather than
    quietly read as port 443 and port 3.
    """
    if host.startswith("["):
        close = host.find("]")
        if close < 0:
            raise _invalid_host(ref, "missing ']' in host")
        hostname = host[1:close]
        after = host[close + 1 :]
        if after != "" and not after.startswith(":"):
            raise _invalid_host(ref, "trailing characters after ']' in host")
        port = after[1:] if after != "" else ""
    else:
        if "[" in host:
            raise _invalid_host(ref, "missing ']' in host")
        hostname, _, port = host.partition(":")
    if not all(c in "0123456789" for c in port):
        raise _invalid_host(ref, f"invalid port {port!r} after host")
    return hostname, port


def _canonical_port(scheme: str, port: str) -> str:
    """Render "the same port" as one string, so a port written out in full and the
    same port left implicit compare equal. An unknown scheme has no default to
    fold, so its port is kept verbatim."""
    if port == "":
        return ""
    default = _DEFAULT_PORTS.get(scheme.lower())
    return "" if default is not None and port == default else port


def _same_or_subdomain(anchor: str, candidate: str) -> bool:
    """Report whether ``candidate`` equals ``anchor`` or is a subdomain of it.

    Comparison is case-insensitive and tolerant of ONE trailing root dot — not of
    every trailing dot, which is what ``rstrip(".")`` would do and would make a
    doubled root dot compare equal to a name that never carried one. A subdomain
    match requires a full dot-delimited label boundary, so ``evil-a.com`` is NOT
    treated as a subdomain of ``a.com`` — the check a bare suffix match gets
    wrong, and the one an attacker registers a domain to exploit.
    """
    a = anchor.lower()
    c = candidate.lower()
    a = a.removesuffix(".")
    c = c.removesuffix(".")
    if a == "":
        return False
    return c == a or c.endswith(f".{a}")


def anchored_parsed(anchor: ParsedRef, candidate: ParsedRef) -> bool:
    """The anchor comparison over two references that have ALREADY been read.

    It exists so a caller holding a parse can reach the verdict without triggering
    a second one — the endpoint rule needs the userinfo answer and the anchor
    answer from one reading of the same string.

    A side that named no scheme borrows the other's, which decides only WHICH port
    counts as the default. Hostname and port are compared as two values rather than
    one joined string: joined, the label boundary would have to find ".a.com" at the
    end of "sub.a.com:8443" and would refuse a subdomain for having a port — the
    right answer reached through the wrong comparison is still the wrong comparison.
    """
    anchor_scheme = anchor.scheme if anchor.had_scheme else candidate.scheme
    candidate_scheme = candidate.scheme if candidate.had_scheme else anchor.scheme
    return _same_or_subdomain(anchor.hostname, candidate.hostname) and _canonical_port(
        anchor_scheme, anchor.port
    ) == _canonical_port(candidate_scheme, candidate.port)
