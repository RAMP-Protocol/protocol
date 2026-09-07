"""Which transport each resolver takes when the caller injects none.

Why this is a test and not a sentence
-------------------------------------
The rule is that a resolver's default follows its URL's PROVENANCE: a fixed,
operator-chosen address takes the plain client, a host another party named takes the
guarded one. That rule is written down in three places — the Go oracle's
``WellKnownOptions.HTTP`` comment, ``docs/design-history.md``, and the published threat
model, which states it per language in a table.

It has now drifted from the code twice. The scheme guard was added to the dial and not
walked back through its callers, so a doc sentence beginning "every fetch" stayed standing
after it stopped being true; and this port mirrored the oracle's options struct without
mirroring the rule, then explained the result in a docstring that had also stopped being
true. Prose cannot detect either. A socket can.

SO: CHANGING ANY ROW BELOW OBLIGES AN EDIT TO THE PUBLISHED THREAT MODEL
(``website/src/content/docs/security/threat-model.mdx``), which names these postures per
language. That is the whole point of the gate — the failure is the reminder.

One row records a gap, not a decision
-------------------------------------
``endpoint resolver`` REACHES here and REFUSES in Go. That is not a considered
divergence: the host is an ``Offer.exchange`` domain, so by the rule above it belongs on
the guarded transport in every language, and this port has not caught up. It is tracked
separately, and the threat model names it. Do not read this row as endorsement — read it
as the thing that will fail, loudly and on purpose, in the change that fixes it.

What is not here
----------------
The WBA directory resolver's guarded default is pinned already, by
``test_resolvers_wba_ssrf.py`` and its Go and TypeScript counterparts; its guard is
additionally not opt-outable, which those cover and this would not. Asserting it twice
would be one behaviour with two owners.

This is deliberately NOT a shared corpus. A ``*-vectors.json`` has to be replayed by all
three languages against the same expectations, and the expectations here legitimately
DIFFER per language — that difference is the subject.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Callable
from typing import Any

import pytest

from ramp_sdk.resolvers import (
    WellKnownEndpointResolver,
    WellKnownKeyResolver,
    WellKnownRequirementsReader,
)


def _dial_observed(exercise: Callable[[str], Any]) -> bool:
    """Whether a resolver reached the loopback origin.

    A guarded default refuses the reserved address before the request leaves the process,
    so "the handler ran" is the observable that separates the two transports.
    """
    reached = False

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
            nonlocal reached
            reached = True
            # Anchored to the host that served it, so the endpoint face's own
            # same-host rule cannot be what refuses.
            body = (
                b'{"role":"ROLE_EXCHANGE","endpoint":"https://'
                + self.headers.get("Host", "").encode()
                + b'","keys":[]}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # The exception is deliberately swallowed: a guarded refusal and a happy answer
        # are both expected outcomes, and ``reached`` is what says which.
        try:
            exercise(f"127.0.0.1:{port}")
        except Exception:  # noqa: BLE001 - the outcome under test is the dial, not the error
            pass
    finally:
        server.shutdown()
        server.server_close()
    return reached


def _key(host: str) -> Any:
    return WellKnownKeyResolver(f"http://{host}/.well-known/ramp.json").resolve("ex.v1")


def _endpoint(host: str) -> Any:
    return WellKnownEndpointResolver(scheme="http").resolve_endpoint(host)


def _requirements(host: str) -> Any:
    return WellKnownRequirementsReader(scheme="http").resolve_registration_requirements(host)


#: ``reaches`` is True where the default is the PLAIN client.
_ROWS = [
    pytest.param(
        _key,
        True,
        "its URL is a fixed, operator-chosen JWKS address — nobody else can point it, "
        "and an on-prem directory may legitimately be private",
        id="key resolver dials plain",
    ),
    pytest.param(
        _endpoint,
        True,
        "its host is an Offer.exchange domain, so another party chose the address and the "
        "rule says guarded. Go already refuses here; this port has not caught up",
        id="endpoint resolver dials plain - a tracked gap, not a decision",
    ),
    pytest.param(
        _requirements,
        False,
        "its host is a RegisterRequest.exchange domain, named by the caller per call",
        id="requirements reader dials guarded",
    ),
]


@pytest.mark.parametrize(("exercise", "reaches", "why"), _ROWS)
def test_resolver_transport_defaults(
    exercise: Callable[[str], Any],
    reaches: bool,
    why: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Both guards are env-driven, so the flags are cleared rather than inherited from
    # whatever shell ran the suite: without this a developer with SKIP_SSRF set sees the
    # guarded rows fail for a reason that has nothing to do with the defaults.
    for name in ("SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)

    got = _dial_observed(exercise)
    verb = {True: "reached", False: "refused"}
    assert got == reaches, (
        f"default transport {verb[got]} the loopback origin, want {verb[reaches]} — {why}. "
        "If this change is intended, the per-language table in the published threat model "
        "has to change with it."
    )
