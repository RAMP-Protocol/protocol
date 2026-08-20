"""The installable TypeScript surface — is a declared module actually reachable?

This repo carries TWO manifests, both named ``@ramp-protocol/sdk-l1``:

* ``sdk/ts/package.json`` — the development-time map, and what the symbol-level
  parity gate reads.
* ``package.json`` at the repo root — what a CONSUMER resolves through. npm has no
  git-subdirectory support, so the package is pinned as a whole-repo git dependency
  and the root map is the one that ships. Its own description says it "Re-exports
  sdk/ts".

Those two drifted. The root map was written once as a snapshot of the sdk/ts map and
never updated as sdk/ts grew, so modules were declared in one and unreachable in the
other. Because ``exports`` is present and carries no ``"."`` entry and no ``"./*"``
wildcard, Node treats it as an EXHAUSTIVE allowlist: an unlisted subpath fails with
ERR_PACKAGE_PATH_NOT_EXPORTED, and there is no deep-path workaround. The file ships
inside the tarball and is simply not addressable.

Nothing caught it, because nothing read the root manifest. test_api_surface_parity.py
proves a SYMBOL exists in a module listed by ``sdk/ts/package.json``; it cannot see
whether that module is reachable once installed. The two gates are siblings and the
distinction is the point: that one checks the symbols, this one checks the door.

So this asserts the root map mirrors sdk/ts — same keys, each value rewritten with the
``sdk/ts/`` prefix the root map uses — except for subpaths listed in UNREACHABLE with a
stated reason. The list is proved USED and NECESSARY on every run, so it records real
remaining debt instead of quietly absorbing new drift.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_ROOT_PKG = _REPO_ROOT / "package.json"
_SDK_TS_PKG = _REPO_ROOT / "sdk" / "ts" / "package.json"

# Root values are the sdk/ts value with this prefix: "./src/wire.ts" -> "./sdk/ts/src/wire.ts".
_PREFIX = "./sdk/ts/"

#: Subpaths declared in sdk/ts and deliberately NOT mirrored into the installable root
#: map yet. Each entry is debt with a name, not an exemption from the rule.
#:
#: EMPTY, and it should stay that way. The nine that lived here were the modules the root
#: map had drifted away from — errordetail alone carries nine symbols the parity matrix
#: lists as cross-language, so for those the matrix over-claimed: the TypeScript face
#: existed in source and could not be imported. They were mirrored when the unary client
#: was built on top of them, since a client cannot compose over a module its own
#: consumers cannot resolve. A new entry is a new instance of that same drift.
UNREACHABLE: dict[str, str] = {}


def _exports(path: pathlib.Path) -> dict[str, str]:
    return json.loads(path.read_text(encoding="utf-8"))["exports"]


def _manifest(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


#: The manifest members that decide whether a declared module actually RESOLVES once
#: installed. The export map alone does not: `./resolvers` was exported and still
#: unimportable, because the root manifest did not depend on undici. A guard that compared
#: only the map would not have caught that, and would not catch it recurring.
_DEPENDENCY_KEYS = ("dependencies", "peerDependencies", "peerDependenciesMeta")


@pytest.fixture(scope="module")
def maps() -> tuple[dict[str, str], dict[str, str]]:
    root, sdk = _exports(_ROOT_PKG), _exports(_SDK_TS_PKG)
    assert sdk, "sdk/ts/package.json declares no exports — the gate would pass vacuously"
    assert root, "root package.json declares no exports — the gate would pass vacuously"
    return root, sdk


def test_every_sdk_ts_export_is_reachable_or_declared_unreachable(maps) -> None:
    """A module declared in sdk/ts must be importable by a consumer, or be listed as debt."""
    root, sdk = maps
    missing = [k for k in sdk if k not in root and k not in UNREACHABLE]
    assert not missing, (
        "declared in sdk/ts/package.json but absent from the installable root package.json, so "
        "a consumer importing it gets ERR_PACKAGE_PATH_NOT_EXPORTED:\n  "
        + "\n  ".join(sorted(missing))
        + "\n\nMirror it into the root exports map as "
        + f'"{_PREFIX}<path>", or add it to UNREACHABLE with a reason.'
    )


def test_mirrored_paths_use_the_root_prefix(maps) -> None:
    """A mirrored entry must point at the same file, through the root map's prefix."""
    root, sdk = maps
    wrong = [
        (k, root[k], _PREFIX + sdk[k][2:])
        for k in sdk
        if k in root and root[k] != _PREFIX + sdk[k][2:]
    ]
    assert not wrong, "root exports disagree with sdk/ts on the target file:\n  " + "\n  ".join(
        f"{k}: root has {got!r}, expected {want!r}" for k, got, want in wrong
    )


def test_root_export_targets_exist(maps) -> None:
    """A mirrored path that points at nothing is worse than a missing one — it fails at import."""
    root, _ = maps
    absent = [(k, v) for k, v in root.items() if not (_REPO_ROOT / v[2:]).is_file()]
    assert not absent, "root exports point at files that do not exist:\n  " + "\n  ".join(
        f"{k} -> {v}" for k, v in absent
    )


def test_unreachable_entries_are_used_and_necessary(maps) -> None:
    """Keep the debt list honest in both directions, so it cannot outlive its reasons."""
    root, sdk = maps
    for key, reason in UNREACHABLE.items():
        assert reason, f"UNREACHABLE[{key!r}] carries no reason"
        assert key in sdk, (
            f"stale entry: {key} is no longer declared in sdk/ts/package.json — drop it from UNREACHABLE"
        )
        assert key not in root, (
            f"stale entry: {key} IS mirrored into the root map now — drop it from UNREACHABLE"
        )


@pytest.mark.parametrize("key", _DEPENDENCY_KEYS)
def test_the_two_manifests_agree_on_what_a_declared_module_needs(key: str) -> None:
    """The root map is what a consumer resolves through, so it needs sdk/ts's dependencies.

    The bug this guards is not hypothetical and was not an export-map bug: ``./resolvers``
    was declared in both maps and still failed to import, because the root manifest did not
    list undici. Whether a module resolves depends on the dependency block as much as on
    the map, and ``peerDependenciesMeta`` is part of it — a peer marked optional in one
    manifest and required in the other changes whether an install succeeds at all.
    """
    root, sdk = _manifest(_ROOT_PKG), _manifest(_SDK_TS_PKG)
    theirs, ours = sdk.get(key, {}), root.get(key, {})
    missing = {k: v for k, v in theirs.items() if k not in ours}
    differing = {k: (v, ours[k]) for k, v in theirs.items() if k in ours and ours[k] != v}
    assert not missing, (
        f"root package.json is missing {key} that sdk/ts declares: {missing}. "
        "A consumer resolves through the root manifest, so a module needing these cannot "
        "be imported."
    )
    assert not differing, (
        f"root and sdk/ts disagree on {key}: "
        + ", ".join(f"{k}: sdk/ts={s!r} root={r!r}" for k, (s, r) in differing.items())
    )
