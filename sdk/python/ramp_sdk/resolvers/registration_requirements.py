"""Reading what one Exchange asks of a registration — the terms revision that
submitting one accepts, and the schema its registration_data must match — out of that
Exchange's own ``/.well-known/ramp.json``. Python port of the Go oracle
(``resolvers/registrationrequirements.go``).

EVERY READ IS A FRESH FETCH, and that is the whole design. The protocol requires it in
as many words: a registering client MUST read the terms digest from a freshly fetched
manifest rather than a cached copy. A cached ENDPOINT is fine — a wrong one fails
loudly — but a cached DIGEST is not, because a client cannot detect staleness locally,
so a warm cache would make it echo a value the Exchange has already stopped accepting
and retry the same refusal until the cache expired.

That is why this is a SEPARATE face rather than a third method on the endpoint
resolver. That resolver is built out of exactly the mechanism this value may not touch
— a per-host TTL cache with single-flight coalescing on top — and it exposes no bypass.
A face that holds no document cache leaves no cache slot to reuse, which is what makes
the rule structural rather than a convention callers remember.

Not even the compiled validator is held. Memoising it is a cache, and the useful key
for one is a property of a deployment's threat model rather than of the protocol; an
application that wants it wraps this face.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from ramp_sdk.hosts import is_bare_domain
from ramp_sdk.regschema import (
    RegistrationSchema,
    SchemaVerdict,
    compile_registration_schema,
)
from ramp_sdk.resolvers._http import fetch_strict, guarded_client
from ramp_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    ExchangeNotPermittedError,
    ManifestNotExchangeError,
)
from ramp_sdk._hostref import _invalid_host
from ramp_sdk.resolvers.wellknown import AllowFn

__all__ = [
    "RegistrationRequirements",
    "WellKnownRequirementsReader",
]


@dataclass(frozen=True)
class RegistrationRequirements:
    """What one Exchange asks of a registration.

    Both members are optional in the contract, and their absence is a normal answer
    rather than a failure: an Exchange publishing neither accepts registration data
    uninspected and records no terms acceptance.
    """

    #: The manifest's ``terms_digest``, ``None`` when the Exchange publishes none. Copy
    #: it onto ``RegisterRequest.terms_digest`` unchanged: the request signature covers
    #: the echo, and that echo is the durable record of which terms revision the
    #: operator accepted.
    terms_digest: str | None = None
    #: Validates ``registration_data`` before anything is signed. ``None`` in TWO cases
    #: — the Exchange publishes none, and it publishes one this SDK refuses — and
    #: ``verdict`` is what tells them apart. Both are deliberately the same VALUE,
    #: because the contract requires a client that cannot check locally to send anyway:
    #: a local check that cannot run must not become a local veto.
    schema: RegistrationSchema | None = None
    #: The SDK's answer for the published schema. ``NOT_PUBLISHED`` is the ordinary
    #: absent case; ``ACCEPTED`` means ``schema`` is usable; anything else names why a
    #: published schema was refused, which is worth logging and is never worth refusing
    #: the registration over.
    verdict: SchemaVerdict = "not_published"


class WellKnownRequirementsReader:
    """Read registration requirements from an Exchange's own well-known manifest.

    ``ttl`` and ``now`` are deliberately absent from the constructor: this face caches
    nothing, so it has no freshness to compute.
    """

    def __init__(
        self,
        *,
        scheme: str = "https",
        http: httpx.Client | None = None,
        allow: AllowFn | None = None,
    ) -> None:
        self._scheme = scheme or "https"
        # The domain is CALLER-NAMED — an agent registers at whichever Exchange it
        # means to transact with, and that domain routinely arrives at runtime rather
        # than from configuration. That is REQUEST-DERIVED provenance, which takes the
        # SSRF-guarded transport; a fixed operator-chosen URL is what takes the plain
        # one. A deployment that must reach a private or loopback Exchange injects its
        # own client here, or opts out through the SKIP_SSRF / ALLOW_INSECURE flags.
        self._http = http if http is not None else guarded_client()
        self._allow = allow

    def resolve_registration_requirements(self, exchange: str) -> RegistrationRequirements:
        """Fetch ``exchange``'s manifest and report what it asks of a registration.

        The answer is never served from a cache; see the module doc for why that is the
        point rather than an omission.

        Two refusals come before anything is dialled, and both are here rather than at
        the call site because they are properties of building this URL and of this
        deployment's policy, not of any one caller's plans.

        The SHAPE predicate is the contract's ``is_bare_domain``, not the routing tier's
        ``is_bare_host``. The two are kept apart deliberately and this leg is where the
        difference bites: nothing upstream has run the contract's rule, and the URL
        below is built by concatenation, so a value carrying a path or userinfo would
        choose WHAT is fetched rather than merely where from.

        A refused schema is never an exception: the verdict is returned alongside a
        ``None`` schema, because the contract requires a client that cannot check
        locally to send anyway and let the Exchange decide.
        """
        if not is_bare_domain(exchange):
            raise _invalid_host(exchange, "not a bare domain")
        if self._allow is not None and not self._allow(exchange):
            raise ExchangeNotPermittedError(f"exchange {exchange} not permitted by policy")
        url = f"{self._scheme}://{exchange}/.well-known/ramp.json"
        raw_body = fetch_strict(self._http, url)
        try:
            # Decoded ONCE, and the member below is sliced out of this text and
            # re-encoded. The round trip is exact for valid UTF-8 — including a byte
            # order mark, which the schema rules refuse and which must therefore
            # survive to reach them — and invalid UTF-8 raises here, where it reads as
            # an undecodable manifest rather than as a schema fault.
            body = raw_body.decode("utf-8")
            doc = json.loads(body)
        except ValueError as exc:
            raise DirectoryUnavailableError(f"manifest decode {url}") from exc
        if not isinstance(doc, dict):
            raise DirectoryUnavailableError(f"manifest at {url} is not a JSON object")
        if not _describes_exchange(doc):
            raise ManifestNotExchangeError(f"host={exchange}")
        digest = doc.get("terms_digest")
        # Compiled from the bytes AS SERVED, because every cap the registration-schema
        # rules state is defined over those bytes. The member is sliced out of the body
        # rather than re-serialised from the parsed value: json.loads discards
        # whitespace and reformats numbers, and a document that minifies under the cap
        # while exceeding it on the wire would be refused by an Exchange and accepted
        # here — the two-privately-chosen-limits failure the contract's numbers exist to
        # prevent.
        raw = _raw_member(body, "account_registration", "data_schema")
        schema: RegistrationSchema | None = None
        verdict: SchemaVerdict = "not_published"
        if raw is not None:
            schema, verdict = compile_registration_schema(raw)
        return RegistrationRequirements(
            terms_digest=digest if isinstance(digest, str) else None,
            schema=schema,
            verdict=verdict,
        )


def _describes_exchange(doc: dict[str, Any]) -> bool:
    """proto-JSON renders an enum as its name or its number, so both are accepted. An
    absent or unrecognised role is not an Exchange."""
    role = doc.get("role")
    return role == "ROLE_EXCHANGE" or role == 2  # noqa: PLR1714 - two distinct wire forms


_DECODER = json.JSONDecoder()
#: RFC 8259 whitespace, and nothing wider — the same four bytes the blank-schema rule
#: counts.
_WS = " \t\r\n"


def _raw_member(body: str, *path: str) -> bytes | None:
    """Return the EXACT served bytes of a nested object member, or ``None`` when any
    step of the path is absent.

    ``body`` has already parsed as JSON when this runs, so the walk below is over
    known-well-formed input and needs no error path — it returns ``None`` for anything
    it cannot walk, and the caller reads that as "no schema published", which is the
    safe direction.

    Value extents come from ``JSONDecoder.raw_decode`` rather than a hand-rolled
    skipper: it already knows where every JSON value ends, and a second implementation
    of that is a second place to get strings and escapes wrong.
    """
    start = 0
    for step, key in enumerate(path):
        found = _member_extent(body, start, key)
        if found is None:
            return None
        if step == len(path) - 1:
            return body[found[0] : found[1]].encode("utf-8")
        start = found[0]
    return None


def _member_extent(body: str, start: int, key: str) -> tuple[int, int] | None:
    """Find ``key`` in the object beginning at ``start`` and return the ``[start, end)``
    of its VALUE."""
    i = _skip_ws(body, start)
    if i >= len(body) or body[i] != "{":
        return None
    i = _skip_ws(body, i + 1)
    if i < len(body) and body[i] == "}":
        return None
    while True:
        try:
            name, i = _DECODER.raw_decode(body, i)
        except ValueError:
            return None
        if not isinstance(name, str):
            return None
        i = _skip_ws(body, i)
        if i >= len(body) or body[i] != ":":
            return None
        value_start = _skip_ws(body, i + 1)
        try:
            _, value_end = _DECODER.raw_decode(body, value_start)
        except ValueError:
            return None
        if name == key:
            return value_start, value_end
        i = _skip_ws(body, value_end)
        if i < len(body) and body[i] == ",":
            i = _skip_ws(body, i + 1)
            continue
        return None


def _skip_ws(body: str, i: int) -> int:
    while i < len(body) and body[i] in _WS:
        i += 1
    return i
