"""Drift gate: docs/sdk-parity-matrix.md is generated, never hand-edited.

The parity matrix is rendered from two artifacts this same suite already enforces
against the code — sdk/parity/symbol-map.json (test_api_surface_parity.py) and the
committed corpora (test_corpus_replay_completeness.py). This test asserts the committed
matrix matches a fresh render, so an edit to the surface or the corpora that isn't
reflected in the doc fails CI here — the doc cannot silently drift the way the three
hand-maintained parity docs it replaced did.

Fix on failure: run `python3 scripts/gen-parity-matrix.py` and commit the result.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_GENERATOR = _REPO_ROOT / "scripts" / "gen-parity-matrix.py"


def test_parity_matrix_is_not_stale() -> None:
    result = subprocess.run(
        [sys.executable, str(_GENERATOR), "--check"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "docs/sdk-parity-matrix.md is out of sync with sdk/parity/symbol-map.json "
        "and/or the committed corpora. Run 'python3 scripts/gen-parity-matrix.py' and "
        f"commit.\n{result.stderr}"
    )
