"""Host predicates, the audience check and the bare-domain shape — Python port of
the sdk/go oracle (helpers/hosts.go, helpers/audience.go).

Two kinds of predicate live here and keeping them apart is the point. The ROUTING
predicates — :func:`is_bare_host` and :func:`host_anchored` — precede a signed
call to an address a network party named: a value that arrives inside an offer, or
inside a manifest that offer pointed at, is about to be concatenated into a URL or
dialled directly. The SHAPE predicate — :func:`is_bare_domain` — answers a
different question: whether a value is the form the wire contract admits at all.

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

from ramp_sdk._hostref import _parse_ref, anchored_parsed

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


def _normalize_domain(v: str) -> str:
    """Render the two spellings of one identity as one string.

    Runs only on values ``is_bare_domain`` has already accepted, so the input is
    ASCII and holds at most one colon followed by digits — which is what lets it
    split on that colon rather than parse a URL, and is why it reproduces the Go
    oracle exactly.
    """
    host, sep, port = v.rpartition(":")
    if not sep:
        host, port = v, ""
    host = host.lower()
    # A schemeless domain is read as https everywhere in this SDK, so 443 spelled
    # out and 443 left implicit are the same port. Any other port is kept, 80
    # included: folding it would be reading a scheme into a value that names none.
    if port in ("", "443"):
        return host
    return f"{host}:{port}"


# ---------------------------------------------------------------------------
# Routing predicates
# ---------------------------------------------------------------------------


def host_of(ref: str) -> str:
    """Extract the host (including any port) from a bare domain, a host:port pair,
    or a full URL.

    A ref with no scheme is read as though it carried https, since a bare domain
    is otherwise indistinguishable from a path.

    Raises ``ValueError`` when the reference cannot be read as a host at all.
    """
    return _parse_ref(ref)[0]


def is_bare_host(ref: str) -> bool:
    """Report whether ``ref`` is EXACTLY a host — nothing a URL could carry besides
    the authority.

    Answers False for a ref with a scheme, userinfo, a path, a query or a
    fragment, because :func:`host_of` had to strip something to reach the host. A
    port is NOT a strip: ``exchange.example:8443`` is a bare host, and the
    well-known resolver concatenates host-with-port unchanged.

    It exists for the callers that hand a network-supplied domain to code which
    builds a URL by concatenation. There, narrowing a rich reference to its host
    is the wrong repair: the value was never a domain, and accepting it silently
    means the far side chose the path that gets fetched, not just the host it is
    fetched from. Comparing against the extracted host is what makes the rejection
    structural rather than a blocklist of the separators anyone thought to name.

    This is NOT :func:`is_bare_domain`. A trailing root dot, a leading or trailing
    hyphen, an underscore, an empty label and a bracketed IPv6 literal are all
    usable hosts and none of them is a value the wire rule accepts. A caller
    vetting a value it is about to dial wants this one; a caller vetting a value
    that arrived in a message wants :func:`is_bare_domain`.
    """
    host = host_of(ref)
    # A trailing colon parses as a host with an empty port and would otherwise
    # compare equal to itself. It is not a domain anyone meant to write, and the
    # callers here concatenate the value into a URL, so it is refused rather than
    # quietly normalized away.
    if host.endswith(":"):
        return False
    return host == ref


def host_anchored(anchor: str, candidate: str) -> bool:
    """Report whether ``candidate`` is anchored to ``anchor`` — the same host and
    port, or a subdomain of that host on that port.

    Either side may be a bare domain, a host:port pair or a full URL; a reference
    that does not parse raises ``ValueError``, which callers treat as "not
    anchored".

    The use is checking a value a remote document supplied against the host that
    served that document: it may point at itself or at one of its own subdomains,
    and nothing else. Without it, a host could redirect a signed request — or a
    revocation poll — to an unrelated third-party address that a dial-time address
    guard would happily allow, because the address is perfectly public.

    The PORT is part of the comparison. What is being anchored is a place a signed
    call is sent, and a different port is a different service — one the party that
    published the anchor need not control. A DEFAULT port and its omission are the
    same port, so ``https://x``, ``https://x:443`` and ``x`` all anchor to one
    another; refusing an operator who merely wrote ``:443`` out in full would be a
    spelling check wearing a security check's clothes.

    The SCHEME is still not compared. Whether a leg may run in the clear is the
    guarded transport's decision, made in one place from one flag. Its only job
    here is choosing which port counts as the default — and a side that NAMED no
    scheme borrows the other's for that purpose, rather than being assumed to mean
    https. Both anchors in this SDK arrive schemeless: a WBA directory's authority
    and an ``Offer.exchange`` host are bare ``host[:port]`` values. Assuming https
    for them meant an anchor of ``a.example:80`` kept its port (80 is not https's
    default) while the candidate ``http://a.example:80`` folded it away — the same
    authority reaching two answers, which silently un-anchored every plaintext
    directory that spelled ``:80`` in full.
    """
    return anchored_parsed(_parse_ref(anchor), _parse_ref(candidate))
