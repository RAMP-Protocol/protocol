"""Cross-language WBA-directory URL-builder parity (Python side).

sdk/python ``wba_directory_url`` MUST reproduce the sdk/go ``WBADirectoryURL``
oracle's built URL for EVERY vector in
``sdk/go/resolvers/testdata/wba-url-vectors.json``. Each vector is
``{label, scheme, host, expected_url}`` — ``scheme`` / ``host`` are the two
explicit builder args (scheme empty→https, host arrives ALREADY-JOINED), and
``expected_url`` is the string the REAL Go builder emitted.

The builder is a PURE string function: ``scheme://host`` + the single shared
``/.well-known/http-message-signatures-directory`` path constant, with empty
scheme defaulting to https and NO env read / NO port-join / NO scheme-in-host
detection (those stay consumer glue). Replaying the corpus is the sanctioned
arithmetic proof that the Python builder — the one the app cleanup will call in
place of its three hand-rolled ``{scheme}://{host}{WBA_PATH}`` copies — agrees
with the Go/TS builders byte-for-byte at the seam the three languages must never
disagree on: https-default, explicit-http, host-with-port, and IPv6 pass-through
of an already-bracketed host.

TDD-red: ``wba_directory_url`` does not exist in ``ramp_sdk.resolvers`` yet, and
``sdk/go/resolvers/testdata/wba-url-vectors.json`` is not emitted yet — so both
the import and the corpus load fail until the builder + corpus land.
"""

from __future__ import annotations

from typing import Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json

# RED: `wba_directory_url` is not defined/exported from ramp_sdk.resolvers yet.
from ramp_sdk.resolvers import wba_directory_url  # type: ignore[attr-defined]

# RED: the Go emitter has not produced this corpus yet → load_json raises
# FileNotFoundError at import time, failing collection for the RIGHT reason.
_CORPUS = load_json(GO_RESOLVERS_TESTDATA / "wba-url-vectors.json")

# The corpus MUST cover exactly these behaviors (stated here as the contract so a
# thinner corpus fails this suite, not just the completeness gate):
#   - https-default   : empty scheme defaults to https
#   - explicit-http   : explicit non-default scheme is honored verbatim
#   - host-with-port  : a host carrying :port is passed through unchanged
#   - ipv6-passthrough: an already-bracketed IPv6 host is not mangled
_REQUIRED_LABELS = frozenset(
    {"https-default", "explicit-http", "host-with-port", "ipv6-passthrough"}
)


def test_wba_url_corpus_nonempty() -> None:
    assert len(_CORPUS["vectors"]) > 0


def test_wba_url_corpus_covers_required_behaviors() -> None:
    labels = {v["label"] for v in _CORPUS["vectors"]}
    missing = _REQUIRED_LABELS - labels
    assert not missing, f"corpus is missing required vectors: {sorted(missing)}"


@pytest.mark.parametrize(
    "vec",
    _CORPUS["vectors"],
    ids=[v["label"] for v in _CORPUS["vectors"]],
)
def test_wba_url_matches_go_oracle(vec: dict[str, Any]) -> None:
    assert wba_directory_url(vec["scheme"], vec["host"]) == vec["expected_url"]
