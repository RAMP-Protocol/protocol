"""Audience check and bare-domain shape — Python port of the sdk/go oracle
(helpers/hosts.go, helpers/audience.go).

Addressed requests carry the recipient's bare domain in a body field. That field
is the only agent-authenticated statement of intended recipient that survives a
relay: each hop signs its own ``@target-uri``, so on a Broker path the agent's
signature covers the *Broker's* URL and the Exchange never receives an agent
signature over its own. The body field rides inside the agent's content-digest
instead, which a relaying Broker cannot alter without breaking the inner
signature.

Pure string work, no IO. Byte-parity-guarded against the Go oracle by the shared
vectors at ``sdk/go/helpers/testdata/audience-vectors.json``.
"""

from __future__ import annotations

import re
from typing import Literal

# BARE_DOMAIN_PATTERN is the wire shape of a domain-valued field: a bare domain
# with an optional ":port", never a URL. It carries the same bytes as the Go
# ``helpers.BareDomainPattern`` and as the protovalidate rule on every
# domain-valued field in ramp.proto — one definition, so the check a client makes
# before sending and the check the wire makes on arrival cannot answer
# differently. The parity suite asserts these bytes against the shared vectors.
BARE_DOMAIN_PATTERN = (
    r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"(:[0-9]{1,5})?$"
)

# MAX_BARE_DOMAIN_LEN mirrors the protovalidate ``string.max_len`` on the same
# fields, so this SDK cannot accept a pattern-valid but over-length value the
# server then rejects.
MAX_BARE_DOMAIN_LEN = 260

# Matched with fullmatch, NOT match. Python's ``$`` also matches just before a
# trailing newline, so ``match`` would accept "exchange.example\n" — a value Go's
# RE2 refuses. fullmatch requires the whole string, which restores the oracle's
# anchoring. The shared vectors carry that exact case.
_BARE_DOMAIN_RE = re.compile(BARE_DOMAIN_PATTERN)


def is_bare_domain(v: str) -> bool:
    """Report whether ``v`` is a bare domain of the shape the wire admits.

    The length is checked FIRST so no unbounded input reaches the pattern: this
    engine backtracks, and Go's RE2 does not, so the Go oracle would be safe
    either way and this port would not be. The order costs nothing in agreement —
    a value whose length differs between code points, UTF-16 units and bytes
    contains something outside ASCII, and the pattern refuses it regardless.
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

    ``self_domain`` is this Exchange's own bare domain. ``claimed`` holds the
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
