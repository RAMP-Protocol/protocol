"""Audience check and bare-domain shape — Python port of the sdk/go oracle
(helpers/hosts.go, helpers/audience.go).

Addressed requests carry the recipient's bare domain in a body field. The RFC 9421
signature does not already establish the recipient: it proves the sender signed
*the URL it dialled*, not that the URL was the right one. That dial target is
resolved from a fetched, cached ``/.well-known/ramp.json``, so a poisoned or stale
resolution redirects the request while every signature still verifies. The field
states whom the sender MEANT, independently of that resolution.

The field is stamped by whoever authors each request — the agent on the requests
it signs, a Broker on the legs it authors as sender. It is a statement BY that
sender, not tamper-evidence against it. For transactions the binding audience
statement is per item: ``Offer.exchange`` inside the Exchange-signed offer.

Pure string work, no IO. Byte-parity-guarded against the Go oracle by the shared
vectors at ``sdk/go/helpers/testdata/audience-vectors.json``.
"""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

# BARE_DOMAIN_PATTERN is the wire shape of a domain-valued field: a bare domain
# with an optional ":port", never a URL. It carries the same bytes as the Go
# ``helpers.BareDomainPattern`` and as the protovalidate pattern on the contract's
# recipient-addressing fields — the ``exchange`` field on each addressed request,
# ``Offer.exchange`` and their neighbours, not every field in ramp.proto that
# happens to hold a domain. One rule, so the check a client makes before sending
# and the check the wire makes on arrival cannot answer differently. The parity
# suite asserts these bytes against the shared vectors.
#
# The port is a real 1-65535 range rather than "one to five digits", which is why
# it is spelled out at this length: :0, :65536 and :99999 name no port at all, and
# :0443 is not a spelling of 443 but a different string.
#
# APPLY IT WITH ``fullmatch``, never ``match``. Python's ``$`` also matches just
# before a trailing newline, so ``re.match(BARE_DOMAIN_PATTERN, v)`` accepts
# "exchange.example\n" — a value Go's RE2 refuses, which is a cross-language
# divergence rather than a style preference. ``is_bare_domain`` below is the
# supported way to ask; reach for the raw pattern only when you cannot, and
# anchor it yourself.
BARE_DOMAIN_PATTERN = (
    r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}"
    r"|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$"
)

# MAX_BARE_DOMAIN_LEN is the length bound belonging to the same rule — the
# protovalidate ``string.max_len`` those fields carry, so this SDK cannot accept a
# pattern-valid but over-length value the server then rejects.
MAX_BARE_DOMAIN_LEN = 260

# Applied with fullmatch, for the reason spelled out on the pattern above. The
# shared vectors carry a trailing-newline case that fails any port using ``match``.
_BARE_DOMAIN_RE = re.compile(BARE_DOMAIN_PATTERN)


def is_bare_domain(v: str) -> bool:
    """Report whether ``v`` is a bare domain of the shape the wire admits.

    The length is checked FIRST so the work stays bounded on hostile input. This
    is insurance rather than a fix for a known blowup: the pattern is unambiguous —
    every repetition is anchored by a literal dot no label class can consume — so
    it cannot backtrack catastrophically, and matching it costs time linear in the
    input. Bounding that is still worth one comparison on an engine that
    backtracks. The order costs nothing in agreement — a value whose length differs
    between code points, UTF-16 units and bytes contains something outside ASCII,
    and the pattern refuses it regardless.
    """
    return len(v) <= MAX_BARE_DOMAIN_LEN and _BARE_DOMAIN_RE.fullmatch(v) is not None


# AudienceVerdict is the outcome of checking a request's claimed recipient
# against this Exchange's own identity. The tokens are the Go
# ``AudienceVerdict.String()`` vocabulary verbatim, which is what the shared
# vectors record.
#
# "no_verdict" means the check did not run because the configured identity is
# unusable. It is never RETURNED here — this port raises in that case, since a
# deployment fault is not something a caller should be able to read as a value —
# but it is in the vocabulary because the shared vectors carry it.
AudienceVerdict = Literal["no_verdict", "accepted", "empty", "malformed", "mismatch"]


def check_audience(self_domain: str, *claimed: str) -> AudienceVerdict:
    """Report whether every claimed recipient names this Exchange.

    ``self_domain`` is this Exchange's own bare domain — the domain it publishes
    as its IDENTITY, which is the value it stamps into the offers it issues. It is
    not the host the process happens to listen on, and the two are allowed to
    differ: an Exchange at ``exchange.example`` may serve its API from
    ``api.exchange.example``, so an operator who configures this from the listening
    host would refuse every request that named them correctly.

    ``claimed`` holds the
    recipient values the request carries — ONE for a message with a single
    ``exchange`` field, MANY for a message whose audience lives per item (a
    TransactionRequest states it once per item, in each item's signed offer).
    Every value must name this Exchange; the first that does not decides the
    verdict, and a request carrying no values at all is refused rather than waved
    through.

    The comparison is EXACT: a subdomain of this Exchange is a different party
    and does not name it. That is narrower than the endpoint rule, which does let
    a manifest advertise its endpoint on a subdomain of the host that served it —
    there the question is which addresses one Exchange may be reached at, here it
    is who the Exchange IS.

    Two spellings of the same identity still match: case is folded, and a port of
    443 written out is the same as leaving it off, since a schemeless domain is
    read as https throughout this SDK. Port 80 is not folded — it is not the
    default of the scheme a bare domain implies.

    Raises ``ValueError`` when ``self_domain`` is not a bare domain. That is a
    fault in this deployment, never in the request, and the two are kept apart so
    a caller can map them onto different status codes without inspecting any
    message.
    """
    if not is_bare_domain(self_domain):
        msg = f"hosts: configured Exchange identity is not a bare domain: {self_domain!r}"
        raise ValueError(msg)
    if not claimed:
        return "empty"
    want = _normalize_domain(self_domain)
    for c in claimed:
        if c == "":
            return "empty"
        if not is_bare_domain(c):
            return "malformed"
        if _normalize_domain(c) != want:
            return "mismatch"
    return "accepted"


def _split_host_port(v: str) -> tuple[str, str]:
    """Split ``host[:port]`` on the FIRST colon; no colon means no port.

    Shared by the audience comparison and the identity-document rule, because the
    443 fold below is half of BOTH origin comparisons and a change to it must not
    have to be made twice.

    The first colon, not the last, because the caller cannot check what this
    hands back. Splitting ``a.example:8443:9`` on the LAST colon gives the host
    half ``a.example:8443``, and ``is_bare_domain`` accepts that — its pattern
    admits an optional port, so it cannot tell a host from a host that already
    carries one. Every origin check downstream then runs against the wrong
    hostname. Splitting on the FIRST colon puts everything after it in the port
    half, where ``_port_is_writable`` refuses it. Values that reached here
    through ``is_bare_domain`` hold at most one colon, so the two rules agree on
    them and the audience corpus is unaffected.
    """
    host, sep, port = v.partition(":")
    if not sep:
        return v, ""
    return host, port


def _fold_default_port(port: str) -> str:
    """443 spelled out and 443 left implicit are the same port; nothing else folds.

    A schemeless domain is read as https everywhere in this SDK. Port 80 is NOT
    folded: that would be reading a scheme into a value that names none.
    """
    return "" if port == "443" else port


def _normalize_domain(v: str) -> str:
    """Render the two spellings of one identity as one string.

    Runs only on values ``is_bare_domain`` has already accepted, so the input is
    ASCII and holds at most one colon followed by digits — which is what lets it
    split on that colon rather than parse a URL, and is why it reproduces the Go
    oracle exactly.
    """
    host, port = _split_host_port(v)
    port = _fold_default_port(port)
    return f"{host.lower()}:{port}" if port else host.lower()


# Identity-document resolution (Python side of sdk/go/helpers/identitydocs.go).
#
# Deliberately NOT built on the ``_host_anchored`` helper in
# ``ramp_sdk.resolvers.wba``: that one implements the endpoint rule, host or
# subdomain, and this field refuses a subdomain. Whoever takes over the host an
# endpoint names misdirects calls they still cannot sign for; whoever takes over
# the host an identity document names publishes their own keys and BECOMES the
# participant.
#
# The authority is read off the RAW string rather than through
# ``urlsplit(...).hostname``, which lowercases: ``str.lower()`` maps U+212A
# KELVIN SIGN to a plain ASCII "k", so a host that is not the same name would
# arrive already disguised as one. ``is_bare_domain`` runs on the untouched value
# for exactly the reason it runs before ``_normalize_domain`` in check_audience.

# The scheme grammar of RFC 3986 §3.1, written once. Both patterns below need
# it, and the refusal that separates "https:/dir" from a relative path only means
# what it says while they agree: widen one copy and not the other, and one check
# reads a reference as having a scheme while the other reads it as having none.
_URI_SCHEME = r"[A-Za-z][A-Za-z0-9+.\-]*"

# A scheme, if the reference carries one at all.
_URI_SCHEME_RE = re.compile(rf"^{_URI_SCHEME}:")

# The authority of a reference that HAS one: an absolute URI with "//" or a
# network-path reference beginning with "//". A reference matching neither is
# relative and inherits the base's authority untouched.
_URI_AUTHORITY_RE = re.compile(rf"^(?:{_URI_SCHEME}:)?//([^/?#]*)")


# A colon reached before the first "/", "?" or "#". Read only when the reference
# carries no scheme, where such a colon cannot be a scheme delimiter.
_COLON_BEFORE_PATH_RE = re.compile(r"[^/?#]*:")


def _uri_scheme(ref: str) -> str:
    m = _URI_SCHEME_RE.match(ref)
    return m.group(0)[:-1].lower() if m else ""


# Every non-alphanumeric byte the coarse RFC 3986 character set admits: the
# unreserved punctuation, the gen-delims, the sub-delims, and the percent sign
# that introduces an escape.
_URI_PUNCTUATION = frozenset("-._~" ":/?#[]@" "!$&'()*+,;=" "%")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _untame_reason(s: str) -> str:
    """Say why ``s`` may not be resolved, as a fragment completing "the reference ...".

    Returns "" when the string is fine. NEVER echoes the input, which can carry
    a credential. Port of ``untameReason`` in sdk/go/helpers/identitydocs.go.

    This exists because the three SDKs do not share a URL parser, and the three
    parsers disagree about everything outside this character set. Go percent-
    encodes a literal "|" and a space, this port and the TypeScript one keep
    them; a control character makes the authority regex above read an ABSOLUTE
    reference as a relative one and skip every origin check; Go refuses an
    invalid escape and the other two accept it. Reproducing three parsers byte
    for byte is not achievable, so the untame input is refused instead.

    DO NOT tighten this to the per-component pchar grammar. pchar would refuse
    "[" and "]", which all three SDKs currently agree on, and there is a vector
    pinning that.
    """
    for i, c in enumerate(s):
        if not (c.isascii() and (c.isalnum() or c in _URI_PUNCTUATION)):
            # Every control character, every space, the backslash, and every
            # non-ASCII character leaves through here. ``str.isalnum`` is true
            # for far more than ASCII, which is why the isascii guard comes
            # first rather than after it.
            return "is not written in the RFC 3986 character set"
        if c != "%":
            continue
        esc = s[i + 1 : i + 3]
        if len(esc) < 2 or esc[0] not in _HEX_DIGITS or esc[1] not in _HEX_DIGITS:
            return "carries an invalid percent-escape"
        # A percent-encoded dot needs its own refusal. The rule above admits a
        # percent followed by two hex digits, and _remove_dot_segments only ever
        # sees a LITERAL dot, so "%2e" would survive every other check — and the
        # three SDKs split on it: Go and this port keep it, the WHATWG parser
        # behind the TypeScript port decodes it and then collapses the segment,
        # which names a DIFFERENT DOCUMENT.
        if esc.lower() == "2e":
            return "carries a percent-encoded dot segment"
    return ""


def _port_is_writable(port: str) -> bool:
    """Is this a decimal number a TCP port can take? An omitted port passes.

    Port of ``portIsWritable`` in sdk/go/helpers/identitydocs.go. The five-digit
    cap is not decoration: a padded ":0443" is accepted (it is a different
    string from ":443" and does not fold, which a vector pins), so the value
    cannot be compared as text — and without a length bound a long run of
    leading zeros overflows Go's Atoi while this port's unbounded int accepts
    it, which would be a new divergence.
    """
    if port == "":
        return True
    return len(port) <= 5 and port.isdigit() and port.isascii() and 1 <= int(port) <= 65535


def _vet_authority(authority: str, label: str) -> tuple[str, str]:
    """Check one authority and return its host and its folded port.

    Written once and called for both the base and the reference. The two used to
    hold the same four steps inline, and the split rule they share is exactly the
    kind of thing that gets fixed in one copy and not the other.

    Refuses userinfo without echoing the value, since that is where a credential
    would be. ``label`` names which of the two strings is at fault and is the
    only difference between the two calls.
    """
    if "@" in authority:
        raise ValueError(f"identity document: {label} carries userinfo")
    host, port = _split_host_port(authority)
    if not is_bare_domain(host):
        raise ValueError(f"identity document: {label} does not name a plain host")
    if not _port_is_writable(port):
        raise ValueError(f"identity document: {label} names a port outside 1-65535")
    return host, _fold_default_port(port)


def _merge_path(base_path: str, ref_path: str) -> str:
    """RFC 3986 5.2.3. The base always names an authority here, so an empty base
    path merges as if it were "/"."""
    if base_path == "":
        return "/" + ref_path
    return base_path[: base_path.rfind("/") + 1] + ref_path


def _raw_query_of(s: str) -> tuple[str, bool]:
    """The query a reference or URL DEFINES, exactly as written, and whether it has one.

    RFC 3986 §3.4: the query runs from the first "?" outside the fragment to the
    fragment or the end of the string. Read as a SUBSTRING rather than through a
    URL library, because the three SDKs run three serializers that disagree
    inside the character set ``_untame_reason`` admits on purpose.
    """
    head = s.split("#", 1)[0]
    _, sep, query = head.partition("?")
    return query, bool(sep)


def _raw_fragment_of(s: str) -> tuple[str, bool]:
    """The fragment a reference DEFINES, exactly as written, and whether it has one.

    RFC 3986 §3.5. PRESENCE is returned alongside the text because a defined but
    empty fragment keeps its "#" — see the output tail of
    ``resolve_identity_document``. Matches Go's ``rawFragmentOf``.
    """
    _, sep, fragment = s.partition("#")
    return fragment, bool(sep)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 5.2.4, run on the joined path.

    Needed because this port resolves the path itself. It also closes the
    divergence that started this: the old ``urljoin`` call returned an ABSOLUTE
    reference untouched, so this port alone failed to normalize
    "https://a.example/a/../b" — Go and TypeScript both answer /b. Its one call
    site is after the branches, so it runs on the inherited base path as well,
    and it is idempotent.

    Not a refusal: "../card.json" is a form the field is specified to support
    and there is a vector pinning it.

    Walks the string with an INDEX rather than reassigning the remainder. The RFC
    states the algorithm as "remove the prefix and repeat", and transcribing that
    literally is quadratic in all three languages, for two different reasons.
    CPython copies on EVERY slice, so every branch is expensive here. Go and
    TypeScript slice for free, but two of the RFC's four removal steps have to
    leave a slash behind, and writing those as a concatenation copies the whole
    remainder — which only a DOT SEGMENT reaches. So the cost hides behind the
    input: a reference of "/a" repeated to 512 KiB was flat in both of those
    ports while "/." at the same length took 6.6s in Go and 9.2s in TypeScript.
    All three now walk an index. The reference is a member of a manifest fetched
    from a third party and carries no maximum length, so the input is reachable.
    The branches below are the RFC's, unchanged; only the way the prefix is
    dropped is different.
    """
    out: list[str] = []
    i, n = 0, len(path)
    while i < n:
        rest = n - i
        if path.startswith("../", i):
            i += 3
        elif path.startswith("./", i):
            i += 2
        elif path.startswith("/./", i):
            # Drop the dot and ONE slash; the other slash starts the next segment.
            i += 2
        elif rest == 2 and path.startswith("/.", i):
            out.append("/")
            i = n
        elif path.startswith("/../", i):
            i += 3
            if out:
                out.pop()
        elif rest == 3 and path.startswith("/..", i):
            if out:
                out.pop()
            out.append("/")
            i = n
        elif (rest == 1 and path[i] == ".") or (rest == 2 and path.startswith("..", i)):
            i = n
        else:
            # Move one segment, its leading "/" included, to the output. Popping
            # one element above therefore drops a segment AND its slash, which
            # is what 5.2.4 asks for.
            j = path.find("/", i + 1) if path[i] == "/" else path.find("/", i)
            if j < 0:
                out.append(path[i:])
                i = n
            else:
                out.append(path[i:j])
                i = j
    return "".join(out)


def resolve_identity_document(manifest_url: str, ref: str) -> str:
    """Resolve an ``identity_documents`` member against the URL ramp.json came from.

    ``ref`` is an RFC 3986 URI reference, relative or absolute. ``manifest_url``
    is the URL the manifest was actually FETCHED FROM, never its self-asserted
    ``domain`` member — a hostile manifest that named its own anchor would
    validate itself.

    Refuses unless BOTH strings are tame (written in the coarse RFC 3986
    character set, every percent-escape valid, no percent-encoded dot segment —
    see ``_untame_reason``); the base is https, names a plain host and carries no
    userinfo; the reference is non-empty; and the resolved URL is https, carries
    no userinfo, names a port inside 1-65535 and sits on the SAME ORIGIN as the
    base (equal host, equal effective port). Vetting the base is not a courtesy:
    a base of
    ``http://a.example/ramp.json`` resolving to ``https://a.example/doc`` passes
    every later check, and accepting it means trusting a manifest that arrived
    unauthenticated.

    Returns the resolved URL in canonical form — host lowercased, a default port
    folded away — so every SDK returns the same string for the same input.

    Raises:
        ValueError: the reference may not be fetched.
    """
    if why := _untame_reason(manifest_url):
        # The base is checked as strictly as the reference. A tab in the base
        # PATH — not a leading one, which the scheme check already catches — was
        # accepted here and refused by Go, and every answer below is computed
        # from this string.
        raise ValueError(f"identity document: manifest URL {why}")
    if "#" in manifest_url:
        # A fragment is never sent to a server, so the URL a manifest was FETCHED
        # FROM cannot carry one. Refused rather than ignored: RFC 3986 5.2.2
        # inherits the base's fragment for a reference that defines none, and the
        # three SDKs disagree about whether a reference of "#" defines an empty
        # fragment or none at all. No fragment on the base, no question to
        # disagree about.
        raise ValueError("identity document: manifest URL carries a fragment")
    if _uri_scheme(manifest_url) != "https":
        raise ValueError("identity document: manifest URL is not https")
    base_auth_m = _URI_AUTHORITY_RE.match(manifest_url)
    if base_auth_m is None:
        raise ValueError("identity document: manifest URL names no authority")
    base_host, base_port = _vet_authority(base_auth_m.group(1), "manifest URL")

    if not ref.strip():
        raise ValueError("identity document: empty reference")
    if why := _untame_reason(ref):
        raise ValueError(f"identity document: reference {why}")
    if ref.count("#") > 1:
        # RFC 3986 3.5 gives a reference a single fragment that runs to the end
        # of the string, so a second hash is not a URI reference at all — it is
        # a fragment with a hash inside it, which has to be written %23. The
        # three parsers disagree about it: Go re-encodes the second hash, this
        # port and the TypeScript one keep it. Refused rather than picked a
        # winner for, because no correct reference reaches this line.
        raise ValueError("identity document: reference carries more than one fragment")
    ref_scheme = _uri_scheme(ref)
    # RFC 3986 3.3 and 4.2: a reference with no scheme is path-noscheme, and its
    # FIRST segment may not contain a colon — ":/x" and "1:x" would otherwise be
    # ambiguous with a scheme. Go's url.Parse refuses ":/x"; this port and the
    # TypeScript one resolved both into an ordinary path segment. Spelled out so
    # the answer does not depend on which parser happens to notice.
    if not ref_scheme and _COLON_BEFORE_PATH_RE.match(ref):
        raise ValueError("identity document: reference's first segment carries a colon")
    ref_auth_m = _URI_AUTHORITY_RE.match(ref)
    if ref_scheme and ref_scheme != "https":
        raise ValueError("identity document: reference does not resolve to an https URL")
    if ref_scheme and ref_auth_m is None:
        # "https:/dir" — a scheme with no "//" names no authority, so it resolves
        # to a URL with no host rather than borrowing the base's.
        raise ValueError("identity document: reference names no authority")
    if ref_auth_m is not None:
        ref_host, ref_port = _vet_authority(ref_auth_m.group(1), "reference")
        if ref_host.lower() != base_host.lower():
            raise ValueError("identity document: reference is not on the manifest's origin")
        if ref_port != base_port:
            raise ValueError("identity document: reference is on a different port than the manifest")

    # Only the path, query and fragment are taken from the join: the authority is
    # rebuilt from the values already checked above, which is what makes the
    # output canonical rather than an echo of however the manifest spelled it.
    #
    # THE REBUILD IS LOAD-BEARING, not a formatting step. The origin checks above
    # read the authority off the RAW string with a regex; if that regex is ever
    # made to disagree with the join about where the authority ends, the join can
    # land on another host while every check above passes. Rebuilding from
    # base_host means the answer is on the checked origin even then. That is not
    # theoretical — before the tame predicate above, a leading tab made this
    # regex read an absolute reference to evil.example as a relative path, and
    # this line was the only thing that kept the result on a.example.
    #
    # The merge below is RFC 3986 5.2.2 and 5.2.3 written out rather than
    # delegated to urljoin. urljoin routes through urlparse, which splits
    # ";params" off the last path segment and then drops an EMPTY params — so it
    # silently turns "/x;" into "/x", where Go and the WHATWG parser both keep
    # the semicolon. urlsplit has no params concept, so parsing with it and
    # merging by hand is what makes this port agree.
    ref_parts = urlsplit(ref)
    base_parts = urlsplit(manifest_url)
    if ref_auth_m is not None:
        path = ref_parts.path
    elif ref_parts.path == "":
        # The base path is INHERITED, not copied: it goes through 5.2.4 below
        # like every other branch. A base of https://a.example/a/../ramp.json
        # with a query-only or fragment-only reference otherwise kept the dot
        # segments, and Go and TypeScript both remove them - same origin,
        # different document name.
        path = base_parts.path
    elif ref_parts.path.startswith("/"):
        path = ref_parts.path
    else:
        path = _merge_path(base_parts.path, ref_parts.path)
    # 5.2.4 runs ONCE, on whichever path the branches above produced. Calling it
    # inside each branch is how the inherited one came to be missed.
    path = _remove_dot_segments(path)

    # RFC 3986 5.2.2 inherits the base's query in ONE case: the reference has an
    # empty path, no authority and no scheme, and defines no query of its own —
    # which in practice means a fragment-only reference. A reference carrying any
    # path drops the base's query even though it defines none.
    query, has_query = _raw_query_of(ref)
    if not has_query and ref_auth_m is None and not ref_scheme and ref_parts.path == "":
        # The base cannot carry a fragment, refused above, so everything after
        # its first "?" is its query.
        query, has_query = _raw_query_of(manifest_url)

    out = "https://" + base_host.lower()
    if base_port:
        out += ":" + base_port
    # RFC 3986 6.2.3: under a hierarchical scheme an empty path is equivalent to
    # "/", and "/" is the normalized form.
    out += path or "/"
    # A query or a fragment that is DEFINED BUT EMPTY keeps its delimiter: "/x?"
    # answers "/x?" and "/x#" answers "/x#". RFC 3986 6.2.3 says normalization
    # "should not remove delimiters when their associated component is empty",
    # and two URIs differing only by a trailing "#" "are considered different
    # regardless of the scheme". They are different request targets on the wire.
    # So PRESENCE decides the delimiter and the contents decide nothing.
    if has_query:
        out += "?" + query
    # The fragment is never inherited: RFC 3986 5.2.2 takes it from the reference
    # on every branch, and the base has none in any case.
    fragment, has_fragment = _raw_fragment_of(ref)
    if has_fragment:
        out += "#" + fragment
    return out
