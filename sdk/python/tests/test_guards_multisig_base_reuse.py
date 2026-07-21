"""Structural guard for the "forked signature-base builder" disease.

DISEASE: the RFC 9421 5-component request signature-base
(@method @target-uri content-digest authorization signature-agent) is rendered by
hardcoding those lines. Before the multisig work there was exactly ONE such
renderer -- ``_signature_base`` in ``ramp_sdk/httpsig.py``. The multisig
append/verify faces MUST compose that generalized builder (via its optional
``chain_link`` arg), NOT fork a second copy of the 5-line template. A fork is how
a future covered-component change silently drifts one path out of byte-parity with
the Go oracle.

This guard pins the invariant class-level: exactly one module under ``ramp_sdk``
renders the 5-component request base, and it is ``httpsig.py``. A new face that
forks the template adds a second renderer and trips this guard.

The 2-component GET-PoP base (``pop.py::signature_base``) is a DISTINCT byte
contract and is intentionally NOT counted -- the fingerprint below requires the
content-digest + authorization + signature-agent lines that only the 5-component
request base carries, so the GET-PoP base never matches.

The detector is REGEX-based and whitespace-tolerant on purpose; the
"would-be-missed" meta-test feeds a reformatted fork and asserts it is still
caught.
"""

from __future__ import annotations

import pathlib
import re

_RAMP_SDK = pathlib.Path(__file__).resolve().parents[1] / "ramp_sdk"
_CANONICAL_RENDERER = "httpsig.py"

# The three signature-base lines that distinguish the 5-component request base
# from the 2-component GET-PoP base.
_FINGERPRINT: tuple[re.Pattern[str], ...] = (
    re.compile(r'"content-digest":\s*\{'),
    re.compile(r'"authorization":\s*\{'),
    re.compile(r'"signature-agent":\s*\{'),
)


def _renders_request_base(source: str) -> bool:
    """Pure predicate: does this source render the 5-component request base?"""
    return all(pat.search(source) for pat in _FINGERPRINT)


def _request_base_renderers() -> list[str]:
    return [
        path.name
        for path in sorted(_RAMP_SDK.glob("*.py"))
        if _renders_request_base(path.read_text(encoding="utf8"))
    ]


class TestNoForkedRequestSignatureBase:
    def test_exactly_one_request_base_renderer(self) -> None:
        assert _request_base_renderers() == [_CANONICAL_RENDERER]

    def test_multisig_verify_reuses_shared_base(self) -> None:
        src = (_RAMP_SDK / "server_verify.py").read_text(encoding="utf8")
        assert not _renders_request_base(src)
        # It must import + call the shared builder rather than re-render lines.
        assert "_signature_base" in src

    def test_append_face_reuses_shared_base(self) -> None:
        src = (_RAMP_SDK / "httpsig.py").read_text(encoding="utf8")
        assert "def append_signature" in src
        append_body = src[src.index("def append_signature") :]
        assert "_signature_base" in append_body

    # --- meta-tests: exercise the detector against synthetic source ----------
    def test_meta_positive_catches_forked_template(self) -> None:
        fork = "\n".join(
            [
                "lines = [",
                '    f\'"@method": {m}\',',
                '    f\'"@target-uri": {u}\',',
                '    f\'"content-digest": {d}\',',
                '    f\'"authorization": {a}\',',
                '    f\'"signature-agent": {s}\',',
                "]",
            ]
        )
        assert _renders_request_base(fork)

    def test_meta_negative_ignores_pop_base(self) -> None:
        pop_base = "\n".join(
            [
                "lines = [",
                '    f\'"@method": {method}\',',
                '    f\'"@target-uri": {url}\',',
                '    f\'"@signature-params": {raw_params}\',',
                "]",
            ]
        )
        assert not _renders_request_base(pop_base)

    def test_meta_would_be_missed_catches_reformatted_fork(self) -> None:
        reformatted = "\n".join(
            [
                "lines = [",
                '    f\'"content-digest":   {digest_header}\',',
                '    f\'"authorization":\t{authorization}\',',
                '    f\'"signature-agent":  {signature_agent}\',',
                "]",
            ]
        )
        assert _renders_request_base(reformatted)
