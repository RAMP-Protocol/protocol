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

import ast
import pathlib

_RAMP_SDK = pathlib.Path(__file__).resolve().parents[1] / "ramp_sdk"

# The public aggregator re-exports everything; the resolvers package IS the IO
# tree. Everything else under ramp_sdk/*.py is the pure, transport-neutral set.
_NON_PURE = {"__init__.py"}

# The banned roots. The resolvers package IS the IO tree; httpx and httpcore
# are the maintained HTTP client, scoped to that tree. urllib is banned FLATLY,
# with no carve-out for .parse. urllib.parse is not IO, but its parsers repair
# and normalize where the guarded modules must refuse or read substrings —
# urlsplit deletes tab/CR/LF anywhere in the string — so a pure module reaching
# for it would silently diverge from the Go and TypeScript ports. No guarded
# module imports it, and exclusion lists in this repo only shrink.
_BANNED = ("ramp_sdk.resolvers", "httpx", "httpcore", "urllib")


def _hits(name: str) -> bool:
    return any(name == root or name.startswith(root + ".") for root in _BANNED)


def _imports_io(source: str) -> bool:
    # AST, not regex: every import form — a banned module in any position of a
    # multi-module line, continuation lines, aliases, parenthesized from-lists,
    # relative imports — is seen by construction, so the flat ban cannot be
    # bypassed by reordering. (A regex detector here was bypassable with
    # `import os, urllib.request`.) Prose mentions in comments and docstrings
    # no longer count: only real import statements do.
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            if any(_hits(alias.name) for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                # Guarded modules sit directly in ramp_sdk/, so a relative
                # import resolves against the ramp_sdk package.
                module = f"ramp_sdk.{module}" if module else "ramp_sdk"
            if _hits(module) or any(
                _hits(f"{module}.{alias.name}" if module else alias.name)
                for alias in node.names
            ):
                return True
    return False


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
        assert _imports_io("from ramp_sdk import resolvers")
        assert _imports_io("from . import resolvers")
        assert _imports_io("from .resolvers import WBAKeyResolver")

    def test_meta_positive_catches_httpx_import(self) -> None:
        assert _imports_io("import httpx")
        assert _imports_io("from httpx import Client")
        assert _imports_io("import sys, httpx")

    def test_meta_positive_catches_httpcore_import(self) -> None:
        # httpcore is a policy entry of its own: no pure module imports it
        # today, so only these asserts notice if its ban is dropped.
        assert _imports_io("import httpcore")
        assert _imports_io("from httpcore import ConnectionPool")
        assert _imports_io("import sys, httpcore")

    def test_meta_positive_catches_urllib_import(self) -> None:
        assert _imports_io("import urllib.request")
        assert _imports_io("from urllib.request import urlopen")
        assert _imports_io("import urllib")
        assert _imports_io("import urllib.error")
        # Every module on a multi-module import line, .parse included and in
        # any position — the ban is flat.
        assert _imports_io("import urllib.parse, urllib.request")
        assert _imports_io("import os, urllib.request")
        assert _imports_io("import urllib.request as r")
        assert _imports_io("import urllib.parse")
        assert _imports_io("from urllib.parse import urlsplit")

    def test_meta_positive_catches_an_import_that_is_not_first_on_its_line(self) -> None:
        # A guard that only reads lines beginning with the keyword is a guard
        # against tidy code, and tidy code was never the risk.
        assert _imports_io("x = 1; import urllib.request")
        assert _imports_io("if True: import urllib.request")
        assert _imports_io("import urllib.parse, \\\n    urllib.request")
        assert _imports_io("import os, \\\n    urllib.request")

    def test_meta_negative_passes_pure_import(self) -> None:
        assert not _imports_io("from ramp_sdk.thumbprint import thumbprint")
        assert not _imports_io("import os, sys")
        # A prose mention is not an import; only real import statements count.
        assert not _imports_io("x = 'urllib.parse strips tab/CR/LF'")
