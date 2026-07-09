"""Shared pytest fixtures/paths for the sdk/python parity suites (ixs7u.6).

The parity suites assert sdk/python's `ramp_sdk` L1 helpers against the SHARED
Go-oracle vectors (never against copied app fixtures — Core Invariant). This
module centralizes the on-disk locations of those shared corpora so every suite
resolves them the same way, mirroring the sdk/ts sibling's relative-path imports
(`../../go/helpers/testdata/*.json`, `../../../conformance/corpus/crossfield.json`).

MINIMAL by intent: this file only exposes paths + a JSON loader. It creates no
package state and imports nothing from `ramp_sdk` (which does not exist yet), so
it never masks the module-missing red the suites are meant to surface.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

# sdk/python/tests/conftest.py -> repo root is parents[3]
# (tests -> python -> sdk -> <repo root>).
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

GO_TESTDATA = _REPO_ROOT / "sdk" / "go" / "helpers" / "testdata"
CONFORMANCE_CORPUS = _REPO_ROOT / "conformance" / "corpus"


def load_json(path: pathlib.Path) -> Any:
    """Read+parse a shared corpus/vector file. Fails the test if it is absent.

    A missing vector file is a legitimate TDD-red signal for the two vectors the
    Go emitter has not yet produced (sign-request-vectors.json,
    acceptance-vectors.json); pytest surfaces the FileNotFoundError as a failure.
    """
    return json.loads(path.read_text())
