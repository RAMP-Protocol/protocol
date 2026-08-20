"""Structural guard for the IO-leaf invariant.

Three packages bear IO: the resolver faces (``ramp_sdk/resolvers/``), which fetch
JWKS / WBA directories / ramp.json, and the client (``ramp_sdk/client/``) with its
blocking facade (``ramp_sdk/sync/``), which speak the RAMP RPCs and the delivery
fetch. All of them dial over an injected transport whose default is a maintained
``httpx`` client with the SSRF guard. The pure L1 modules (``core``, ``httpsig``,
``pop``, ``server_verify``, ``keyresolver``, ``thumbprint``, ``b64``, ...) are
transport-neutral by contract -- they own no keys, open no sockets, and MUST NOT
depend on any of them. Dependency flows one way only: the IO packages ->
pure-modules (they reuse thumbprint, b64, the signing and verifying faces), never
the reverse. A pure module that imports ``ramp_sdk.resolvers``,
``ramp_sdk.client``, ``httpx``, or raw ``urllib`` would drag IO into the
transport-neutral core -- the httpx dependency is scoped to the IO tree -- and is
exactly the regression this guard bans.

The pure set is the TOP-LEVEL ``ramp_sdk/*.py`` modules; the IO packages are
subpackages and so are outside it by construction. ``__init__.py`` is the public
aggregator and legitimately re-exports every face, so it is excluded too.
"""

from __future__ import annotations

import pathlib
import re

_RAMP_SDK = pathlib.Path(__file__).resolve().parents[1] / "ramp_sdk"

# The public aggregator re-exports everything; the resolvers package IS the IO
# tree. Everything else under ramp_sdk/*.py is the pure, transport-neutral set.
_NON_PURE = {"__init__.py"}

_FORBIDDEN = (
    re.compile(r"(?:from|import)\s+ramp_sdk\.(?:resolvers|client|sync)\b"),
    re.compile(r"(?:from|import)\s+ramp_sdk\.(?:resolvers|client|sync)$", re.MULTILINE),
    # The maintained HTTP client is scoped to the IO tree; a pure module importing
    # httpx (or httpcore, or raw urllib) would drag IO into the trust core.
    re.compile(r"\bimport\s+httpx\b"),
    re.compile(r"\bfrom\s+httpx\b"),
    re.compile(r"\bimport\s+httpcore\b"),
    re.compile(r"\bimport\s+urllib\b"),
    re.compile(r"\bfrom\s+urllib\b"),
)


def _imports_io(source: str) -> bool:
    return any(pat.search(source) for pat in _FORBIDDEN)


def _pure_modules() -> list[pathlib.Path]:
    return [p for p in sorted(_RAMP_SDK.glob("*.py")) if p.name not in _NON_PURE]


class TestResolverIoLeaf:
    def test_no_pure_module_imports_the_io_tree(self) -> None:
        offenders = [p.name for p in _pure_modules() if _imports_io(p.read_text(encoding="utf8"))]
        assert offenders == []

    def test_resolvers_reuse_pure_primitives(self) -> None:
        wba = (_RAMP_SDK / "resolvers" / "wba.py").read_text(encoding="utf8")
        assert "thumbprint" in wba
        http = (_RAMP_SDK / "resolvers" / "_http.py").read_text(encoding="utf8")
        # The IO tree is where the maintained httpx client legitimately lives.
        assert "httpx" in http

    # --- meta-tests: exercise the detector against synthetic source ----------
    def test_meta_positive_catches_resolvers_import(self) -> None:
        assert _imports_io("from ramp_sdk.resolvers import WBAKeyResolver")

    def test_meta_positive_catches_httpx_import(self) -> None:
        assert _imports_io("import httpx")
        assert _imports_io("from httpx import Client")

    def test_meta_positive_catches_urllib_import(self) -> None:
        assert _imports_io("import urllib.request")

    def test_meta_negative_passes_pure_import(self) -> None:
        assert not _imports_io("from ramp_sdk.thumbprint import thumbprint")
