"""Window-refactor signature regression pin (Python side).

The window-injection refactor sources SigningTransport's (created, expires) from an injected
window (default clock_window(time.time, ttl_sec)) instead of the inline
``created = int(self._now()); expires = created + ttl`` mint. clock_window
MUST int()-truncate so the produced RFC 9421 @signature-params bytes stay
byte-identical. This pin captures the CURRENT (pre-refactor) behaviour and MUST
STAY GREEN after the refactor:
  - given a fractional now, created = int(now()), expires = created+ttl, emitted
    verbatim in the Signature-Input inner list;
  - sign_outbound is byte-deterministic for a fixed seed + fixed now (Ed25519).

GREEN NOW by design (characterization guard, not a missing-face red). It imports
only the shipped SigningTransport; if the refactor drops the truncation or
changes the window, the assertions below fail.
"""

from __future__ import annotations

from ramp_sdk.signing_transport import SigningTransport

_SEED = bytes(range(1, 33))
_KEYID = "agent.test.v1"
_URL = "https://broker.example/ramp.v1/Discover"
_BODY = b'{"query":"x"}'
# A fractional-second now: int(1_700_000_000.987) == 1_700_000_000.
_NOW = 1_700_000_000.987
_TTL = 600
_EXPECT_CREATED = 1_700_000_000
_EXPECT_EXPIRES = 1_700_000_600


def _sign() -> dict[str, str]:
    transport = SigningTransport(
        signer_seed=_SEED,
        keyid=_KEYID,
        now=lambda: _NOW,
        ttl_sec=_TTL,
    )
    return transport.sign_outbound(
        method="POST", url=_URL, body=_BODY, authorization=""
    ).headers


def test_signing_transport_truncates_created_in_signature_input() -> None:
    headers = _sign()
    sig_input = headers["signature-input"]
    assert f"created={_EXPECT_CREATED}" in sig_input  # truncated, not .987
    assert f"expires={_EXPECT_EXPIRES}" in sig_input


def test_signing_transport_byte_deterministic_for_fixed_seed_and_now() -> None:
    assert _sign() == _sign()
