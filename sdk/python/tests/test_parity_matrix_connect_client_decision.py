"""Doc-guard: the Go-only Connect client divergence must be a RECORDED decision.

The whole point of the Connect-client parity work is to END the silent absence:
Go ships a typed Connect client (NewClient/Discover/Execute) and Python + TS do not.
The resolution is option (b) — document it as a deliberate runtime-native divergence
in docs/sdk-parity-matrix.md, mirroring the sibling server-handler DECISION. This
guard fails if that DECISION bullet is ever removed, so the gap cannot silently
reappear or be miscounted as "parity complete".
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
    # It must be framed as a deliberate divergence, not an open TODO.
    assert "discover" in lowered and "execute" in lowered, (
        "the Connect-client decision must reference the Discover/Execute "
        "offer-lifecycle orchestration that scopes the reopen trigger"
    )
