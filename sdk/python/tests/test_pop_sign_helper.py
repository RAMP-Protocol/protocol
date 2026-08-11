"""Sub-task A — ramp_sdk.pop.sign_agent_binding + top-level __all__.

The sign oracle is the pop-vectors.json 'valid' vector: it carries
signer_seed_hex (the raw seed of the key that produced the stored signature),
so the sign face re-signs the same inputs and byte-compares against the stored
Signature-Input / Signature (deterministic Ed25519).
"""

from __future__ import annotations

import re

import pytest

from conftest import GO_TESTDATA, load_json

from ramp_sdk.pop import sign_agent_binding, verify_agent_binding

_POP_VECTORS = load_json(GO_TESTDATA / "pop-vectors.json")


def _valid_vector() -> dict[str, object]:
    """Return the 'valid' pop vector (expected_valid=True)."""
    for v in _POP_VECTORS:
        if v.get("expected_valid"):
            return v  # type: ignore[return-value]
    raise KeyError("no valid pop vector found")


def _seed_of(v: dict[str, object]) -> bytes:
    """The raw Ed25519 seed that produced the vector's signature."""
    return bytes.fromhex(str(v["signer_seed_hex"]))


def _parse_created_expires(signature_input: str) -> tuple[int, int]:
    """Extract the created and expires integers from a Signature-Input string."""
    created_m = re.search(r";created=(\d+)", signature_input)
    expires_m = re.search(r";expires=(\d+)", signature_input)
    assert created_m is not None, "no created in signature_input"
    assert expires_m is not None, "no expires in signature_input"
    return int(created_m.group(1)), int(expires_m.group(1))


# ---- (a) sign vs oracle ---------------------------------------------------


def test_sign_agent_binding_matches_go_oracle() -> None:
    """sign_agent_binding with the oracle seed reproduces the stored signature byte-for-byte."""
    v = _valid_vector()
    sig_input_raw = str(v["signature_input"])
    created, expires = _parse_created_expires(sig_input_raw)
    url = str(v["url"])

    presented_key, sig_input_value, sig_value = sign_agent_binding(
        url=url,
        signer_seed=_seed_of(v),
        created=created,
        expires=expires,
    )

    # The oracle emitted presented_key_b64url and the Signature-Input / Signature header
    # values.  Assert exact byte-for-byte parity (deterministic Ed25519).
    assert presented_key == str(v["presented_key_b64url"]), (
        f"presented key mismatch: got {presented_key!r}, want {v['presented_key_b64url']!r}"
    )
    assert sig_input_value == sig_input_raw, (
        f"Signature-Input mismatch:\n  got  {sig_input_value!r}\n  want {sig_input_raw!r}"
    )
    assert sig_value == str(v["signature"]), (
        f"Signature mismatch: got {sig_value!r}, want {v['signature']!r}"
    )


# ---- (b) round-trip through verify_agent_binding -------------------------


def test_sign_then_verify_round_trips() -> None:
    """Signing then immediately verifying (within the window) returns ok=True."""
    v = _valid_vector()
    sig_input_raw = str(v["signature_input"])
    created, expires = _parse_created_expires(sig_input_raw)
    url = str(v["url"])
    agent_id = str(v["agent_id"])

    presented_key, sig_input_value, sig_value = sign_agent_binding(
        url=url,
        signer_seed=_seed_of(v),
        created=created,
        expires=expires,
    )

    headers = {
        "x-ramp-agent-key": presented_key,
        "signature-input": sig_input_value,
        "signature": sig_value,
    }
    result = verify_agent_binding(
        method="GET",
        url=url,
        headers=headers,
        agent_id=agent_id,
        now=created + 1,  # within the window
    )
    assert result.ok is True, f"verify rejected a freshly-signed PoP: {result.reason}"


# ---- (c) negative: expired window rejects --------------------------------


@pytest.mark.parametrize(
    "now_offset",
    [1],  # 1 second past expires
    ids=["1s_past_expires"],
)
def test_sign_agent_binding_rejects_when_expired(now_offset: int) -> None:
    """verify_agent_binding rejects a valid signature when now >= expires."""
    v = _valid_vector()
    sig_input_raw = str(v["signature_input"])
    created, expires = _parse_created_expires(sig_input_raw)
    url = str(v["url"])
    agent_id = str(v["agent_id"])

    presented_key, sig_input_value, sig_value = sign_agent_binding(
        url=url,
        signer_seed=_seed_of(v),
        created=created,
        expires=expires,
    )

    headers = {
        "x-ramp-agent-key": presented_key,
        "signature-input": sig_input_value,
        "signature": sig_value,
    }
    result = verify_agent_binding(
        method="GET",
        url=url,
        headers=headers,
        agent_id=agent_id,
        now=expires + now_offset,  # past the window
    )
    assert result.ok is False, "verify should reject an expired PoP"
    assert result.reason is not None


# ---- top-level re-export -------------------------------------------------


def test_sign_agent_binding_in_ramp_sdk_all() -> None:
    """ramp_sdk.__all__ includes sign_agent_binding after the implement step."""
    import ramp_sdk

    assert "sign_agent_binding" in ramp_sdk.__all__


# ---- control bytes in the target URI -------------------------------------


def test_sign_agent_binding_refuses_control_bytes_in_the_url() -> None:
    """A control byte in the URL must be refused, not signed.

    The signature base is line-delimited and the URL is written into it verbatim,
    so a newline would add or split a component line and the signed bytes would
    stop describing the request a verifier reconstructs. Mirrors the Go signer's
    refusal (helpers.SignAgentBinding / ErrInvalidPoPInput); Python raises rather
    than exporting a sentinel, which is the mapped-correct shape.
    """
    import pytest
    from ramp_sdk.pop import sign_agent_binding

    seed = bytes(range(32))
    for name, url in {
        "newline": 'https://cdn.test/a\n"@authority": evil.test',
        "carriage return": "https://cdn.test/a\r",
        "nul": "https://cdn.test/a\x00",
        "delete": "https://cdn.test/a\x7f",
    }.items():
        with pytest.raises(ValueError, match="control byte"):
            sign_agent_binding(url=url, signer_seed=seed, created=1, expires=2)
        assert name  # names are for the failure message only


def test_sign_agent_binding_still_signs_an_ordinary_url() -> None:
    """The refusal is narrow: a normal URL, and a percent-encoded one, still sign."""
    from ramp_sdk.pop import sign_agent_binding

    seed = bytes(range(32))
    for url in ("https://cdn.test/a?agent_id=x", "https://cdn.test/a%20b%2Fc"):
        key, sig_input, sig = sign_agent_binding(
            url=url, signer_seed=seed, created=1, expires=2
        )
        assert key and sig_input.startswith("sig1=") and sig.startswith("sig1=:")
