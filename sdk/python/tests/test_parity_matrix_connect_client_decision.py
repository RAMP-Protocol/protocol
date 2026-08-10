"""Doc-guard: the Go-only Connect client divergence must be a RECORDED decision.

The whole point of the Connect-client parity work is to END the silent absence:
Go ships a typed Connect client and Python + TS do not. docs/sdk-parity-matrix.md
must carry that as a DECISION bullet, mirroring the sibling server-handler one, so
the gap cannot silently reappear or be miscounted as "parity complete".

The decision is OPEN, not settled. The API-surface design document governs, and it
specifies a thin Connect-unary JSON client for TypeScript and Python carrying the
SAME verb names — so what stays divergent is the transport implementation, not the
API. An earlier wording called this a "deliberate runtime-native divergence,
DECISION resolved"; that was an allowlist reason written in the grammar of a
decision, and it was substantively wrong, since every RAMP RPC is unary and
nothing about it is runtime-native.

This guard asserts only that the bullet EXISTS and still names the client and its
verbs. It deliberately does not assert the resolved-versus-open wording: that is
the part expected to change when the other two languages gain their client.
"""

from __future__ import annotations

from pathlib import Path

# tests/ -> sdk/python -> sdk -> repo root; the matrix doc lives at repo docs/.
_MATRIX = Path(__file__).resolve().parents[3] / "docs" / "sdk-parity-matrix.md"


def test_connect_client_divergence_is_a_recorded_decision() -> None:
    """docs/sdk-parity-matrix.md records the Go-only Connect client as intentional."""
    text = _MATRIX.read_text(encoding="utf-8")
    assert "DECISION —" in text, "parity matrix carries no DECISION bullets"
    # The Connect-client decision must name the client and the runtime-native rationale.
    lowered = text.lower()
    assert "connect client" in lowered or "connect-client" in lowered, (
        "no Connect-client decision recorded in the parity matrix — the Go-only "
        "typed client gap is still silent"
    )
    # It must name the verbs it covers, so a reader can tell what "the Go client"
    # means without reading the code.
    assert "discover" in lowered and "execute" in lowered, (
        "the Connect-client decision must name the verbs the Go client covers, "
        "which is what scopes the divergence"
    )
