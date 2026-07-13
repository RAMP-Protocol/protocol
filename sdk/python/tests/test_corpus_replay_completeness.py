"""Durable ratchet: every shared corpus MUST be replayed by ALL THREE SDKs.

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

Exemptions are an explicit, documented allowlist that may only SHRINK: each entry is
re-verified to STILL be genuinely unreferenced, so the day a language adds the missing
replay the now-stale exemption fails and must be removed (a ratchet, not an escape hatch).
"""

from __future__ import annotations

import pathlib

from conftest import GO_RESOLVERS_TESTDATA, GO_TESTDATA

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

# Documented, shrink-only exemptions: (corpus basename, language) that is KNOWN to
# lack a replay, with the reason. Each is re-verified below to STILL be missing, so
# it fails (and must be deleted) once the replay is added.
_EXEMPT: dict[tuple[str, str], str] = {
    (
        "wire-canonical-vectors.json",
        "ts",
    ): (
        "TS has no wire-canonicalization replay of this corpus: sdk/ts's wire parity "
        "(wire.parity.test.ts) covers the wire-CONSTANTS corpus, and the canonical-bytes "
        "path is exercised Go+Python only (test_wire_canon.py). Remove this exemption when "
        "sdk/ts gains a wire-canonical replay."
    ),
}


def _corpus_files() -> list[pathlib.Path]:
    """Every committed shared corpus (both the L1 helpers and L2 resolvers homes)."""
    files: list[pathlib.Path] = []
    for d in (GO_TESTDATA, GO_RESOLVERS_TESTDATA):
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
    """Each committed corpus must be consumed by go + python + ts (or be exempt)."""
    orphans: list[str] = []
    for corpus in _corpus_files():
        basename = corpus.name
        for lang, (tree, ext) in _LANG_TREES.items():
            if (basename, lang) in _EXEMPT:
                continue
            if not _is_referenced(basename, tree, ext):
                orphans.append(
                    f"{basename}: no {lang} replay — an orphaned corpus asserts nothing; "
                    f"add a {lang} replay or an _EXEMPT entry (with a reason)"
                )
    assert not orphans, "orphaned shared corpora (emitted but not replayed):\n" + "\n".join(orphans)


def test_exemptions_are_still_needed() -> None:
    """The exemption allowlist may only SHRINK: each entry must name a corpus that
    STILL exists and is STILL genuinely unreferenced in that language. When the
    replay is added, its exemption goes stale and this test fails until it is removed."""
    present = {c.name for c in _corpus_files()}
    stale: list[str] = []
    for (basename, lang), reason in _EXEMPT.items():
        assert reason.strip(), f"exemption ({basename}, {lang}) must carry a reason"
        if basename not in present:
            stale.append(f"({basename}, {lang}): corpus no longer exists — drop the exemption")
            continue
        tree, ext = _LANG_TREES[lang]
        if _is_referenced(basename, tree, ext):
            stale.append(
                f"({basename}, {lang}): a {lang} replay now exists — drop this stale exemption"
            )
    assert not stale, "stale corpus-replay exemptions (the ratchet must shrink):\n" + "\n".join(
        stale
    )
