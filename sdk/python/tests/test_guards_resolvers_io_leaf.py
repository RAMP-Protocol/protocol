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
    # urllib is banned FLATLY, with no carve-out for .parse.
    #
    # There was one for a while, because hosts.py took a URI reference apart with
    # urllib.parse.urlsplit. That import is gone: urlsplit deletes tabs and
    # newlines anywhere in the string, so it answered a different path from the
    # two other ports, and the module now reads the component as a substring the
    # way Go and TypeScript do. With no user left, the exclusion goes too —
    # exclusion lists in this repo only shrink.
    #
    # Restoring the flat ban also restores the guard's REACH. The carve-out had
    # to anchor to the start of a line to inspect every module on a multi-module
    # import, and anchoring stopped it seeing an import that is not the first
    # statement on its line. These two match anywhere on the line, as the httpx
    # entries above do.
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
        assert _imports_io("from urllib.request import urlopen")
        assert _imports_io("import urllib")
        assert _imports_io("import urllib.error")
        # Every module on a multi-module import line, including .parse now that
        # the carve-out is gone.
        assert _imports_io("import urllib.parse, urllib.request")
        assert _imports_io("import urllib.parse")
        assert _imports_io("from urllib.parse import urlsplit")

    def test_meta_positive_catches_an_import_that_is_not_first_on_its_line(self) -> None:
        # The shapes the anchored carve-out pattern stopped seeing. A guard that
        # only reads lines beginning with the keyword is a guard against tidy
        # code, and tidy code was never the risk.
        assert _imports_io("x = 1; import urllib.request")
        assert _imports_io("if True: import urllib.request")
        assert _imports_io("import urllib.parse, \\\n    urllib.request")

    def test_meta_negative_passes_pure_import(self) -> None:
        assert not _imports_io("from ramp_sdk.thumbprint import thumbprint")
