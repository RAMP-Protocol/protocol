"""sdk/python core expiry timezone-awareness regression — TDD red for ov97t.3.

Pin: ``_expired`` must treat an offset-less RFC 3339 ``expires_at`` as UTC,
matching the Go oracle (protobuf ``Timestamp.AsTime()`` always returns UTC).

Before the fix, ``datetime.fromisoformat`` on an offset-less string returns a
tz-naive datetime whose ``.timestamp()`` is computed in the **host local time**,
not UTC.  On a UTC CI host the bug is invisible; on any other host (America/New_York
= UTC-5 in winter) the offset shifts the expiry comparison by the UTC offset, so
a past-UTC offer is incorrectly accepted.

To make the red host-independent this module forces ``TZ=America/New_York`` inside
each test (via a session-scope fixture that mutates ``os.environ`` and calls
``time.tzset``).  Under that TZ the naive ``2020-01-01T00:00:00`` (which is
``2020-01-01T05:00:00Z`` on a UTC-5 host) has ``.timestamp() == 1577854800``;
``now_unix`` is set to ``1577836801`` (one second after the Z-epoch
``2020-01-01T00:00:00Z``), so the naive interpretation sees the offer as NOT YET
expired (+/- 18000 seconds of slack), while the correct UTC interpretation sees it
as expired.

Three vectors (all driven through the PUBLIC ``Verifier.sort`` surface with a
real signed offer):

  A. Z-suffixed past expires_at  -> rejected "offer expires_at is in the past"
  B. offset-less past expires_at -> rejected IDENTICALLY   (the BUG vector; FAILS pre-fix)
  C. future Z-suffixed expires_at -> verified (smoke-check: freshness gate does not fire)

RED now because ``_expired`` has the tz-naive bug; vector B accepts the offer
instead of rejecting it.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_sdk.core import (  # type: ignore[import-not-found]
    Mode,
    StaticOfferKeyResolver,
    Verifier,
    canonical_offer_payload,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 2020-01-01T00:00:00Z  — a point in the past (Unix 1577836800).
# now_unix is ONE SECOND LATER so the offer is expired under a correct UTC
# interpretation.
_PAST_EPOCH: int = 1577836800  # Unix epoch of 2020-01-01T00:00:00Z
_NOW_UNIX: int = _PAST_EPOCH + 1  # one second after expiry

# A safely-future timestamp: 2030-01-01T00:00:00Z (Unix 1893456000).
_FUTURE_EPOCH: int = 1893456000

_EXCHANGE = "test.example.com"

# ---------------------------------------------------------------------------
# Key pair — generated ONCE per test module (deterministic seed for stability).
# A fixed seed means the signed offer bytes are reproducible across runs; it is
# NOT a security concern (this is test data, never production data).
# ---------------------------------------------------------------------------
_SEED = bytes.fromhex("a3471b00efaeebacb2a09de40b619e2c4f683fa728065ba943802b2bf6e2e866")
_PRIV = Ed25519PrivateKey.from_private_bytes(_SEED)
_PUB_RAW: bytes = _PRIV.public_key().public_bytes_raw()


def _make_offer(expires_at: str) -> dict[str, object]:
    """Build and sign a minimal offer with the given ``expires_at`` string.

    The offer is signed over its canonical JCS payload (signature and
    signature_algorithm fields absent during signing — mirror of the Go oracle).
    """
    offer_body: dict[str, object] = {
        "exchange": _EXCHANGE,
        "offer_id": "test-expiry-tz-offer",
        "expires_at": expires_at,
    }
    payload = canonical_offer_payload(offer_body)
    sig_hex = _PRIV.sign(payload).hex()
    return {**offer_body, "signature": sig_hex, "signature_algorithm": "EdDSA"}


def _make_verifier() -> Verifier:
    """Return a STRICT Verifier with the module key and clock fixed at _NOW_UNIX."""
    resolver = StaticOfferKeyResolver({_EXCHANGE: _PUB_RAW})
    return Verifier(mode=Mode.STRICT, resolver=resolver, now=lambda: _NOW_UNIX)


# ---------------------------------------------------------------------------
# TZ-forcing fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def force_non_utc_tz(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force TZ=America/New_York for every test in this module.

    America/New_York is UTC-5 in January (EST), so a tz-naive datetime whose
    underlying epoch is 1577836800 (2020-01-01T00:00:00 UTC) will be read as
    2020-01-01T05:00:00 local-time by the buggy ``.timestamp()`` path, producing
    a timestamp of 1577854800 — 18000 seconds AFTER _NOW_UNIX.  That means the
    buggy code sees the offer as not-yet-expired, while the correct code (treating
    naive as UTC) sees it as expired by 1 second.

    The fixture restores TZ afterward (monkeypatch handles undo automatically).
    """
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    yield  # type: ignore[misc]
    # monkeypatch restores TZ; re-sync libc after restore
    time.tzset()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_vector_a_z_suffix_past_is_rejected() -> None:
    """Vector A: Z-suffixed past expires_at is rejected (baseline correctness).

    '2020-01-01T00:00:00Z' is UTC-aware; fromisoformat produces a tz-aware
    datetime regardless of host TZ, so _expired correctly returns True.
    Both pre-fix and post-fix code must reject this vector.
    """
    offer = _make_offer("2020-01-01T00:00:00Z")
    verifier = _make_verifier()

    result = verifier.sort([offer])

    assert len(result.verified) == 0, "expired Z-suffixed offer must not be verified"
    assert len(result.rejected) == 1
    rejection = result.rejected[0]
    assert rejection.reason is not None
    assert "expires_at" in rejection.reason, (
        f"expected expiry rejection, got: {rejection.reason!r}"
    )


def test_vector_b_offset_less_past_is_rejected_identically() -> None:
    """Vector B (BUG VECTOR): offset-less past expires_at must be rejected as UTC.

    '2020-01-01T00:00:00' (no Z, no offset) represents the same instant as
    '2020-01-01T00:00:00Z' under the correct UTC interpretation.  The bug makes
    Python interpret it as America/New_York local time (UTC-5), shifting the
    expiry decision: the buggy code sees .timestamp() = 1577854800, which is
    18000 seconds AFTER _NOW_UNIX = 1577836801, so the offer is NOT expired
    under the buggy path -- it is incorrectly placed in `verified`.

    This test MUST FAIL before the fix (TDD red) and pass after.
    """
    offer = _make_offer("2020-01-01T00:00:00")  # offset-less, same epoch as Z vector
    verifier = _make_verifier()

    result = verifier.sort([offer])

    assert len(result.verified) == 0, (
        "offset-less past expires_at must be rejected as UTC (same as Z-suffix vector)"
    )
    assert len(result.rejected) == 1
    rejection = result.rejected[0]
    assert rejection.reason is not None
    assert "expires_at" in rejection.reason, (
        f"expected expiry rejection, got: {rejection.reason!r}"
    )


def test_vector_c_future_expires_at_is_verified() -> None:
    """Vector C: a future expires_at (Z-suffixed) is verified successfully.

    The freshness gate must NOT fire for an offer that has not yet expired.
    The signed offer is well-formed and the key is known, so it lands in verified.
    """
    # Build with a future Z-suffix timestamp (2030-01-01T00:00:00Z).
    offer = _make_offer("2030-01-01T00:00:00Z")
    verifier = _make_verifier()

    result = verifier.sort([offer])

    assert len(result.verified) == 1, "future valid offer must be verified"
    assert len(result.rejected) == 0
