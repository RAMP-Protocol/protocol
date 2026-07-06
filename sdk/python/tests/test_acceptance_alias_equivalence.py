"""Sub-task B (TDD red) — ramp_sdk.acceptance aliases to JCS core; old symbols produce
the JCS bytes, not the superseded deterministic-protobuf bytes.

MUST FAIL TODAY because:
  - ramp_sdk.sign_offer_acceptance still delegates to the proto-binary
    canonical_acceptance_payload (acceptance.py), NOT to the JCS form in
    ramp_sdk.core.sign_offer_acceptance_jcs.
  - ramp_sdk.canonical_acceptance_payload returns proto-binary bytes beginning
    with proto field tags (0x0a …), not a UTF-8 JCS string.

The test is parametrized over acceptance-vectors.json (canonicalization="jcs")
which the Go oracle already regenerated to the JCS form.  Asserting the OLD
top-level symbols produce the SAME (hex, alg) as the CORE JCS symbols pins
the redirect the implementation will make.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# The JCS forms — these already exist in core.py and are the CANONICAL names.
from ramp_sdk.core import jcs_acceptance_payload, sign_offer_acceptance_jcs

# The OLD top-level symbols — today they point at the proto-binary form and
# will be redirected to the JCS forms in the implement step.
from ramp_sdk import (
    canonical_acceptance_payload,
    sign_offer_acceptance,
)

_DOC = load_json(GO_TESTDATA / "acceptance-vectors.json")
_VECTORS = _DOC["vectors"]


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_sign_offer_acceptance_alias_equals_jcs_core(vector: dict[str, object]) -> None:
    """ramp_sdk.sign_offer_acceptance is byte-identical to ramp_sdk.core.sign_offer_acceptance_jcs.

    FAILING today because acceptance.py's sign_offer_acceptance uses the proto-binary
    canonical_acceptance_payload, while core's sign_offer_acceptance_jcs uses
    jcs_acceptance_payload — they produce different signatures over different bytes.
    The implement step redirects acceptance.py to delegate to core.
    """
    seed = bytes.fromhex(str(vector["seed_hex"]))
    kwargs = {
        "seed": seed,
        "offer_sig": str(vector["offer_sig"]),
        "requester_id": str(vector["requester_id"]),
        "requester_domain": str(vector["requester_domain"]),
        "idempotency_key": str(vector["idempotency_key"]),
    }

    alias_sig, alias_alg = sign_offer_acceptance(**kwargs)
    core_sig, core_alg = sign_offer_acceptance_jcs(**kwargs)

    assert alias_alg == core_alg, (
        f"[{vector['name']}] algorithm mismatch: alias={alias_alg!r} core={core_alg!r}"
    )
    assert alias_sig == core_sig, (
        f"[{vector['name']}] signature mismatch:\n"
        f"  alias (proto-binary today, should be JCS): {alias_sig!r}\n"
        f"  core  (JCS, canonical):                    {core_sig!r}"
    )


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_canonical_acceptance_payload_alias_equals_jcs_payload(
    vector: dict[str, object],
) -> None:
    """ramp_sdk.canonical_acceptance_payload matches ramp_sdk.core.jcs_acceptance_payload.

    FAILING today because canonical_acceptance_payload returns the proto-binary
    varint-encoded wire bytes (0x0a …), NOT the UTF-8 JCS bytes the JCS oracle produces.
    The implement step makes canonical_acceptance_payload an alias for jcs_acceptance_payload.
    """
    kwargs = {
        "offer_sig": str(vector["offer_sig"]),
        "requester_id": str(vector["requester_id"]),
        "requester_domain": str(vector["requester_domain"]),
        "idempotency_key": str(vector["idempotency_key"]),
    }

    alias_payload = canonical_acceptance_payload(**kwargs)
    core_payload = jcs_acceptance_payload(**kwargs)

    assert alias_payload == core_payload, (
        f"[{vector['name']}] canonical payload mismatch:\n"
        f"  alias (proto-binary today, should be JCS): {alias_payload!r}\n"
        f"  core  (JCS, canonical):                    {core_payload!r}"
    )


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_sign_offer_acceptance_matches_oracle_signature_hex(
    vector: dict[str, object],
) -> None:
    """ramp_sdk.sign_offer_acceptance produces the oracle signature_hex.

    The oracle (acceptance-vectors.json) was regenerated to JCS; the old proto-binary
    form produces a DIFFERENT hex.  After the redirect, the alias must match.
    """
    seed = bytes.fromhex(str(vector["seed_hex"]))
    sig_hex, alg = sign_offer_acceptance(
        seed=seed,
        offer_sig=str(vector["offer_sig"]),
        requester_id=str(vector["requester_id"]),
        requester_domain=str(vector["requester_domain"]),
        idempotency_key=str(vector["idempotency_key"]),
    )
    assert alg == "EdDSA"
    assert sig_hex == str(vector["signature_hex"]), (
        f"[{vector['name']}] signature_hex mismatch:\n"
        f"  got (proto-binary today):  {sig_hex!r}\n"
        f"  want (JCS oracle):         {vector['signature_hex']!r}"
    )
