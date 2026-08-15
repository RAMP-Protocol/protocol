"""Shared pytest fixtures/paths for the sdk/python parity suites.

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
# The fetching resolvers (WBA / well-known / endpoint) and their SSRF + revocation
# corpora live in the sdk/go/resolvers L2 package (the I/O layer, extracted from
# helpers). GO_TESTDATA stays the L1 crypto-vector home; this is its L2 sibling.
GO_RESOLVERS_TESTDATA = _REPO_ROOT / "sdk" / "go" / "resolvers" / "testdata"
CONFORMANCE_CORPUS = _REPO_ROOT / "conformance" / "corpus"
# The Go->Python/TS symbol mapping the API-surface parity gate already
# maintains. Suites that need the local name of a Go symbol read it from here
# instead of keeping a private copy, so the two cannot disagree.
SYMBOL_MAP = _REPO_ROOT / "sdk" / "parity" / "symbol-map.json"


def load_json(path: pathlib.Path) -> Any:
    """Read+parse a shared corpus/vector file. Fails the test if it is absent.

    A missing vector file is a legitimate TDD-red signal for the two vectors the
    Go emitter has not yet produced (sign-request-vectors.json,
    acceptance-vectors.json); pytest surfaces the FileNotFoundError as a failure.
    """
    return json.loads(path.read_text())
