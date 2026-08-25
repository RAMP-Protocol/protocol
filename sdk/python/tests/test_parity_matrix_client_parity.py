"""Doc-guard: the client is at cross-language parity, and the record says so.

This file used to guard the opposite. Go shipped a typed Connect client and Python and TS
did not, and the guard's job was to keep that absence LOUD — a DECISION bullet in
docs/sdk-parity-matrix.md, so the gap could not silently reappear or be miscounted as
"parity complete". It deliberately did not assert the resolved-versus-open wording,
because that was the part expected to change when the other two languages gained their
client.

They have. The divergence was never settled: every RAMP RPC is unary, and the API-surface
design specified a thin Connect-unary JSON client for both, carrying the same verb names —
so what stayed divergent was the transport implementation, not the API. With the client
shipped in all three, the failure this file guards against inverts. The risk is no longer
a silent absence; it is a silent REGRESSION — the map quietly reclassifying the client as
Go-only again, and the matrix following it without anyone reading the sentence.

So the assertions are the mirror of what they were: the client symbols are MAPPED in both
languages, no allowlist reason survives on them, and no OPEN Connect-client decision is
left in the matrix claiming otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# tests/ -> sdk/python -> sdk -> repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_MATRIX = _REPO_ROOT / "docs" / "sdk-parity-matrix.md"
_MAP = _REPO_ROOT / "sdk" / "parity" / "symbol-map.json"

#: The client symbols that must carry a face in BOTH languages. Not the whole client
#: surface — the API-surface gate owns completeness — but the ones whose absence WAS the
#: divergence: the two client types, the failure a caller branches on, and the seam that
#: keeps a report's destination out of configuration.
_MUST_BE_MAPPED = (
    "connect.Client",
    "connect.BrokerClient",
    "connect.CallError",
    "connect.CallErrorKind",
    "connect.EndpointResolver",
    "resolvers.Content",
)


@pytest.fixture(scope="module")
def symbols() -> dict:
    return json.loads(_MAP.read_text(encoding="utf-8"))["symbols"]


@pytest.fixture(scope="module")
def exclusions() -> dict:
    return json.loads(_MAP.read_text(encoding="utf-8"))["go_exclusions"]


def test_the_client_carries_a_face_in_both_languages(symbols: dict) -> None:
    for name in _MUST_BE_MAPPED:
        entry = symbols.get(name)
        assert entry is not None, (
            f"{name} is no longer a mapped symbol — the client has been reclassified as a "
            "Go-only divergence, which it is not"
        )
        assert entry["python"], f"{name} has no Python face"
        assert entry["ts"], f"{name} has no TypeScript face"
        assert not entry["allowlist_reason"], (
            f"{name} carries an allowlist reason, which marks a divergence; it is mapped "
            f"in both languages: {entry['allowlist_reason']}"
        )


def test_the_client_is_not_recorded_as_a_go_only_exclusion(exclusions: dict) -> None:
    present = [name for name in _MUST_BE_MAPPED if name in exclusions]
    assert not present, (
        "client symbols moved back into go_exclusions, which reads as 'Go has this and the "
        f"others cannot': {present}"
    )


def test_no_open_connect_client_decision_survives_in_the_matrix() -> None:
    """The matrix is generated, so a stale bullet means a stale reason in the map."""
    lowered = _MATRIX.read_text(encoding="utf-8").lower()
    for bullet in lowered.split("\n"):
        if not bullet.startswith("- **decision"):
            continue
        assert "connect **client**" not in bullet, (
            "the matrix still carries the OPEN Connect-client decision, which the shipped "
            f"TypeScript and Python clients contradict: {bullet}"
        )


def test_the_matrix_names_the_client_at_parity() -> None:
    """A reader must be able to see the resolution without opening the symbol map."""
    text = _MATRIX.read_text(encoding="utf-8")
    assert "| `Client` | `Client` | `Client` |" in text, (
        "the generated parity table no longer lists the client as mapped in all three "
        "languages"
    )
