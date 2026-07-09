"""Sub-task D (TDD red) — SigningTransport.signature_agent binding.

MUST FAIL TODAY because SigningTransport.__init__ does not accept a
signature_agent keyword argument.  Constructing it with one raises:
  TypeError: SigningTransport.__init__() got an unexpected keyword argument
  'signature_agent'

Test shape mirrors test_client_binding_smoke.py (sign_outbound invocation).

(a) signature_agent="https://agent.example" → 'signature-agent' header
    present in signed.headers AND 'signature-agent' in the Signature-Input
    covered-component list.
    [RED TODAY — TypeError on construction]

(b) default signature_agent='' → NO 'signature-agent' header.
    [RED TODAY — TypeError on construction; once implemented, pins the
    conditional so a future change cannot accidentally stamp the header when
    the caller did not configure one]
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


# ---- (b) default (empty) signature_agent → header absent ------------------


def test_no_signature_agent_header_when_not_configured() -> None:
    """Default (signature_agent='') produces NO Signature-Agent header.

    This test pins the conditional: a caller that does not configure
    signature_agent must not receive the header on the wire.
    """
    transport = _make_transport(signature_agent="")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/ramp.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    header_keys_lower = {k.lower() for k in signed.headers}
    assert "signature-agent" not in header_keys_lower, (
        f"Unexpected 'Signature-Agent' header with empty signature_agent; "
        f"headers: {list(signed.headers.keys())}"
    )
