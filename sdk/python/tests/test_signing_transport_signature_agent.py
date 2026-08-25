"""SigningTransport.signature_agent — bound into the base, and carried on the wire.

Signature-Agent is a COVERED component: the sign seam binds its value into the
signature base unconditionally, empty included. A verifier rebuilds that base from the
request it RECEIVED, so binding is only half of it — the header has to arrive, or the
verifier reads the covered name off signature-input, finds nothing under it, and
refuses the request.

(a) signature_agent="https://agent.example" → the header carries that directory, and
    'signature-agent' appears in the Signature-Input covered-component list.

(b) default signature_agent='' → the header is still carried, EMPTY. This is the
    static-bootstrap case, and it used to assert the opposite: that a caller who
    configured no directory received no header. That read as a tidy conditional and
    was the defect written down as intent — a request signed that way was refused by
    every conformant verifier. The empty value is the point: it is what lets the peer
    rebuild a base that bound an empty directory.

The whole emitted set is pinned against the Go oracle by the shared corpus, in
test_signrequest_parity.py; this file covers the two signature_agent shapes directly.
"""

from __future__ import annotations

from ramp_sdk.signing_transport import SigningTransport


def _make_transport(*, signature_agent: str = "") -> SigningTransport:
    """Construct a SigningTransport with a fixed seed and optional signature_agent."""
    return SigningTransport(
        signer_seed=bytes(range(1, 33)),
        keyid="agent.test.v1",
        now=lambda: 1_700_000_000.0,
        # RED: signature_agent is not yet an accepted parameter.
        signature_agent=signature_agent,  # type: ignore[call-arg]
    )


# ---- (a) signature_agent configured → header present + covered ------------


def test_signature_agent_header_present_when_configured() -> None:
    """When signature_agent is set, signed.headers carries 'Signature-Agent'."""
    transport = _make_transport(signature_agent="https://agent.example")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/ramp.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    header_keys_lower = {k.lower() for k in signed.headers}
    assert "signature-agent" in header_keys_lower, (
        f"Expected 'Signature-Agent' header; got headers: {list(signed.headers.keys())}"
    )


def test_signature_agent_covered_in_signature_input_when_configured() -> None:
    """When signature_agent is set, the Signature-Input covered list includes it."""
    transport = _make_transport(signature_agent="https://agent.example")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/ramp.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    sig_input = signed.headers.get("signature-input") or signed.headers.get("Signature-Input") or ""
    assert '"signature-agent"' in sig_input, (
        f"Expected 'signature-agent' in Signature-Input covered set; got: {sig_input!r}"
    )


# ---- (b) default (empty) signature_agent → header present, EMPTY ----------


def test_signature_agent_header_is_carried_empty_when_not_configured() -> None:
    """Default (signature_agent='') still carries Signature-Agent, with an empty value.

    The static-bootstrap case. The covered set binds the empty directory, so the header
    has to arrive for the verifier to rebuild the base — an absent one is refused, not
    tolerated. Measured: a request signed without it is answered
    ``header "signature-agent" missing from request``.

    Authorization is asserted beside it because the two are one mechanism: both are
    covered unconditionally, and fixing only the first leaves the second failing the
    identical way.
    """
    transport = _make_transport(signature_agent="")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/ramp.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    emitted = {k.lower(): v for k, v in signed.headers.items()}
    assert emitted.get("signature-agent") == "", (
        f"empty signature_agent must still be CARRIED, not dropped; headers: {emitted}"
    )
    assert emitted.get("authorization") == "", (
        f"empty authorization must still be CARRIED, not dropped; headers: {emitted}"
    )
