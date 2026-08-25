"""sdk/python httpx client-binding smoke.

MCP shim (src/mcp) is a CLIENT: httpsig.SigningTransport auto-signs every outbound
httpx POST to the Broker (RFC 9421), receives offers, and today does NOT verify
their signatures — the exact gap ADR-020 §4 names. This is the ONLY in-repo Python
consumer this binding is built for. The smoke drives MCP's real shape through
the opt-in sdk/python httpx client binding (a SigningTransport analogue = the Go
RoundTripper analogue over core's sign seam) AND the core Verifier:

  - a client signs an outbound request via the core sign seam (RFC 9421 over the
    exact body bytes);
  - a returned offer is verified through the core Verifier with an INJECTED
    resolver → {verified, rejected}.

The binding composes the shipped L1 (httpsig.sign_request); the core adds NO new
crypto. This smoke pins the BINDING WIRING (client sign face + Verifier consumption
of a returned offer), the outermost surface MCP actually adopts.

RED now for TWO expected reasons:
  1. sdk/python/ramp_sdk/core does not exist yet (sign seam + Verifier import
     cannot resolve).
  2. sdk/python/ramp_sdk/signing_transport (the outbound-sign face) does not exist
     yet.
Referencing both by their planned paths keeps this smoke RED until the implement
step lands the core + httpx client binding.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# RED: sdk/python/ramp_sdk/core does not exist yet (TDD red).
from ramp_sdk.core import (  # type: ignore[import-not-found]
    Mode,
    StaticOfferKeyResolver,
    Verifier,
)

# RED (also): the opt-in httpx client binding does not exist yet.
from ramp_sdk.signing_transport import SigningTransport  # type: ignore[import-not-found]


def _raw_pub(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_client_signs_outbound_request_via_core_sign_seam() -> None:
    # MCP's client sign face: the SigningTransport wraps an outbound httpx request
    # and signs it via the core over the EXACT body bytes (Content-Digest). The
    # smoke asserts the transport emits a signed request carrying the RFC 9421
    # Signature-Input / Signature headers — the seam MCP adopts.
    signer_seed = bytes(range(1, 33))
    transport = SigningTransport(signer_seed=signer_seed, keyid="agent.test.v1")

    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/ramp.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    emitted = {k.lower() for k in signed.headers}
    assert "signature-input" in emitted
    assert "signature" in emitted
    assert "content-digest" in emitted
    # The two covered headers whose value may be empty. Membership alone is the point
    # here: a signed request that omits either is refused by a conformant verifier, and
    # this smoke test passed for the whole life of that defect without them.
    assert "authorization" in emitted
    assert "signature-agent" in emitted


def test_client_verifies_returned_offer_through_verifier() -> None:
    # MCP receives offers from the Broker and (the gap this closes) verifies them.
    # With an injected resolver, a returned offer flows through the core Verifier
    # into {verified, rejected}. This smoke pins the CONSUMPTION wiring, not the
    # JCS-byte parity (that is test_core_offer_verify_parity.py vs the shared
    # matrix). An offer with no resolvable key is rejected under Strict (fail-closed).
    exchange_priv = Ed25519PrivateKey.generate()
    resolver = StaticOfferKeyResolver({"exchange.example": _raw_pub(exchange_priv)})
    verifier = Verifier(mode=Mode.STRICT, resolver=resolver, now=lambda: 1_700_000_000)

    # An offer whose exchange has NO resolvable key → rejected (fail-closed),
    # observed through the same Verifier surface MCP would call.
    unresolvable = {"offer_id": "o1", "exchange": "unknown.example"}
    result = verifier.sort([unresolvable])
    assert len(result.verified) == 0
    assert len(result.rejected) == 1
    assert result.rejected[0].reason is not None
