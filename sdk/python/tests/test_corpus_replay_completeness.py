"""Hard gate: every shared corpus MUST be replayed by ALL THREE SDKs. No exemptions.

The shared-corpus convention (sdk/go emits a *-vectors.json oracle; sdk/python and
sdk/ts replay it) only prevents divergence if EVERY committed corpus is actually
consumed by all three languages. A corpus that is emitted but replayed by nobody is
an ORPHAN — it silently asserts nothing, and the very divergence the corpus was meant
to catch ships anyway. That is exactly how the SSRF redirect-depth and multi-address
gaps slipped through: their vector files existed but no test read them.

test_parity_corpora_nonempty.py guards a DIFFERENT failure (a CONSUMED corpus that is
present-but-empty). It cannot catch an orphan, because an orphan is not in its
registry. This gate closes the orphan hole from the other side: it ENUMERATES every
committed ``testdata/*-vectors.json`` and asserts each is referenced by a Go
emitter/consumer AND a Python replay AND a TS replay — so an emitted-but-unreplayed
corpus fails CI the moment it is committed.

A reference is necessary and NOT sufficient, which is the second gate below. A replay can
name a corpus and read none of its columns: the hex half of wire-names-vectors.json did
exactly that through two review rounds, asserting only that a verification returned false —
true of every vector either way — while the parity matrix counted the row as replayed by
three languages. So each language must also reference every COLUMN the corpus declares.
Derived from the committed JSON's own keys, so a column added by an emitter is covered the
day it lands rather than the day somebody remembers.

There is deliberately NO exemption mechanism — no allowlist, no opt-out, no per-corpus
waiver. A new shared corpus is replayed in all three languages in the same change, or
it does not land. The count of un-replayed corpora is zero, always, with no way to
make it anything else.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

from conftest import GO_CONNECT_TESTDATA, GO_RESOLVERS_TESTDATA, GO_TESTDATA

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

# The three SDK source trees and the file extension whose contents count as a
# "replay" reference for that language.
_LANG_TREES: dict[str, tuple[pathlib.Path, str]] = {
    "go": (_REPO_ROOT / "sdk" / "go", ".go"),
    "python": (_REPO_ROOT / "sdk" / "python", ".py"),
    "ts": (_REPO_ROOT / "sdk" / "ts", ".ts"),
}

# Directories that never hold hand-written replays (caches, deps, and the corpus
# files themselves) — skipped so the scan stays fast and cannot self-satisfy by
# finding the basename inside the corpus JSON.
_SKIP_DIR_PARTS = frozenset(
    {
        "node_modules",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "testdata",
        "dist",
        "build",
    }
)


def _corpus_files() -> list[pathlib.Path]:
    """Every committed shared corpus, across all three tier homes (L1 helpers, L2
    resolvers, L2 connect). Enumerated rather than listed by name, so a corpus added to
    any home is gated the day it is committed."""
    files: list[pathlib.Path] = []
    for d in (GO_TESTDATA, GO_RESOLVERS_TESTDATA, GO_CONNECT_TESTDATA):
        files.extend(sorted(d.glob("*-vectors.json")))
    return files


def _iter_sources(tree: pathlib.Path, ext: str) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for path in tree.rglob(f"*{ext}"):
        if _SKIP_DIR_PARTS.intersection(path.parts):
            continue
        out.append(path)
    return out


def _is_referenced(basename: str, tree: pathlib.Path, ext: str) -> bool:
    """Whether any source file under ``tree`` names ``basename`` (an import/load)."""
    return any(basename in p.read_text(encoding="utf8") for p in _iter_sources(tree, ext))


def test_corpus_enumeration_is_nonempty() -> None:
    """Guard the guard: an empty enumeration would make this gate vacuous."""
    assert _corpus_files(), (
        "no shared corpus files found — this completeness gate would run 0 cases"
    )


def test_every_corpus_is_replayed_by_all_three_sdks() -> None:
    """Each committed corpus MUST be consumed by go + python + ts. No exemptions."""
    orphans: list[str] = []
    for corpus in _corpus_files():
        basename = corpus.name
        for lang, (tree, ext) in _LANG_TREES.items():
            if not _is_referenced(basename, tree, ext):
                orphans.append(
                    f"{basename}: no {lang} replay — an orphaned corpus asserts nothing; "
                    f"add the {lang} replay (there is no exemption)"
                )
    assert not orphans, "orphaned shared corpora (emitted but not replayed):\n" + "\n".join(orphans)


def _declared_columns(doc: Any) -> dict[str, set[str]]:
    """The case lists a corpus declares, and the column names in each.

    Top level only. A corpus's own structure is ``{"<list name>": [ {case}, ... ]}``, and
    the keys of those cases are its columns; anything deeper is the PAYLOAD of a case — a
    message body, a schema under test — whose field names belong to the data, not to the
    corpus, and which no replay should be expected to name.
    """
    lists: dict[str, set[str]] = {}
    items = doc.items() if isinstance(doc, dict) else [("<root>", doc)]
    for name, value in items:
        if isinstance(value, list) and value and all(isinstance(e, dict) for e in value):
            columns: set[str] = set()
            for entry in value:
                columns |= set(entry.keys())
            lists[name] = columns
    return lists


def _references(text: str, column: str) -> bool:
    """Whether a replay names this column at all.

    Deliberately loose about HOW — a quoted key, an index, an attribute — because the three
    languages spell the same read differently and the bar is "does this replay look at the
    column", not "does it look at it in one particular way".
    """
    return re.search(r"""[\"'`\[.]""" + re.escape(column) + r"\b", text) is not None


def test_every_replay_reads_every_column_its_corpus_declares() -> None:
    """A corpus row counts as replayed only if the replay reads what the corpus records.

    The failure this closes is not hypothetical and not rare: three review rounds each
    turned up a replay asserting less than its matrix row claimed. Naming the file is what
    the gate above checks; reading the columns is what makes the naming mean something.
    """
    sources = {
        lang: "\n".join(
            path.read_text(encoding="utf8", errors="replace")
            for path in _iter_sources(tree, ext)
        )
        for lang, (tree, ext) in _LANG_TREES.items()
    }
    unread: list[str] = []
    for corpus in _corpus_files():
        doc = json.loads(corpus.read_text(encoding="utf-8"))
        for list_name, columns in _declared_columns(doc).items():
            for lang, text in sources.items():
                missing = sorted(c for c in columns if not _references(text, c))
                if missing:
                    unread.append(
                        f"{corpus.name} [{list_name}]: the {lang} replay never reads "
                        f"{missing} — a corpus column no replay looks at asserts nothing, "
                        f"and the parity matrix counts the row as replayed regardless"
                    )
    assert not unread, "corpus columns no replay reads:\n  " + "\n  ".join(unread)
