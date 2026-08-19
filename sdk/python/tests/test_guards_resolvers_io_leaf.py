"""Structural guard for the resolver IO-leaf invariant.

The resolver faces (``ramp_sdk/resolvers/``) are the SDK's ONLY IO-bearing tree:
they fetch JWKS / WBA directories / ramp.json over an injected transport (default
a maintained ``httpx`` client with the SSRF guard). The pure L1 modules
(``core``, ``httpsig``, ``pop``, ``server_verify``, ``keyresolver``,
``thumbprint``, ``b64``, ...) are transport-neutral by contract -- they own no
keys, open no sockets, and MUST NOT depend on the IO tree. Dependency flows one
way only: ``resolvers`` -> pure-modules (it reuses thumbprint + b64), never the
reverse. A pure module that imports ``ramp_sdk.resolvers``, ``httpx``, or raw
``urllib`` would drag IO into the transport-neutral core -- the httpx dependency
is scoped to the IO tree -- and is exactly the regression this guard bans.

``__init__.py`` is the public aggregator and legitimately re-exports the resolver
faces, so it is excluded from the pure set.
"""

from __future__ import annotations

import pathlib
import re

_RAMP_SDK = pathlib.Path(__file__).resolve().parents[1] / "ramp_sdk"

# The public aggregator re-exports everything; the resolvers package IS the IO
# tree. Everything else under ramp_sdk/*.py is the pure, transport-neutral set.
_NON_PURE = {"__init__.py"}

_FORBIDDEN = (
    re.compile(r"(?:from|import)\s+ramp_sdk\.resolvers\b"),
    re.compile(r"(?:from|import)\s+ramp_sdk\.resolvers$", re.MULTILINE),
    # The maintained HTTP client is scoped to the IO tree; a pure module importing
    # httpx (or httpcore, or raw urllib) would drag IO into the trust core.
    re.compile(r"\bimport\s+httpx\b"),
    re.compile(r"\bfrom\s+httpx\b"),
    re.compile(r"\bimport\s+httpcore\b"),
    # urllib.parse is the ONE exception, and it is narrow on purpose: it is pure
    # string work (splitting and joining URI references) with no socket in it,
    # while urllib.request is a full HTTP client. Everything else under urllib
    # stays banned, which is why these two patterns name the submodule rather
    # than allowing "urllib" and hoping nobody reaches for .request.
    re.compile(r"\bimport\s+urllib\b(?!\.parse\b)"),
    re.compile(r"\bfrom\s+urllib\b(?!\.parse\b)"),
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
        assert _imports_io("from urllib.request import urlopen")
        assert _imports_io("import urllib")
        assert _imports_io("import urllib.error")

    def test_meta_negative_allows_the_pure_url_parser(self) -> None:
        # urllib.parse resolves a URI reference against a base. No socket, and no
        # way to reach urllib.request through it.
        assert not _imports_io("from urllib.parse import urljoin, urlsplit")
        assert not _imports_io("import urllib.parse")

    def test_meta_negative_passes_pure_import(self) -> None:
        assert not _imports_io("from ramp_sdk.thumbprint import thumbprint")
