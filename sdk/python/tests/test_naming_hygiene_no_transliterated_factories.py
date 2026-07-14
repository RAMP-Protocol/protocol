"""Naming-hygiene guard: no transliterated new*/PascalCase factories on the TS/Python surface.

Go's idiomatic ``NewX`` constructor convention was transliterated into non-idiomatic
TS (`newWellKnownKeyResolver`, and worst `NewVerifier` which falsely implies a class)
and Python (`new_idempotency_key`) factory names. The sweep renames object factories
to ``create*`` and value generators to ``generate*``. This guard fails while any old
name is still publicly exported, so the rename cannot silently regress. Go ``NewX``
stays (idiomatic / revive-required) and is NOT in the TS/Python public surface this
guard inspects.
"""

from __future__ import annotations

import re
from pathlib import Path

import ramp_sdk

# tests/ -> sdk/python -> sdk -> <repo>
_REPO = Path(__file__).resolve().parents[3]
_TS = _REPO / "sdk" / "ts"

# The old TS public names the sweep must eliminate (object factories + one PascalCase
# + the idempotency value generator). Each is a public export; none may survive.
_FORBIDDEN_TS = (
    "newWellKnownKeyResolver",
    "newWellKnownEndpointResolver",
    "newWBAKeyResolver",
    "newStaticKeyResolver",
    "newCachedOfferKeyResolver",
    "newSigningTransport",
    "newWBAOfferDirectoryFetch",
    "NewVerifier",
    "newIdempotencyKey",
)


def _ts_public_export_text() -> str:
    """Concatenated source of every module reachable via package.json exports."""
    import json

    exports = json.loads((_TS / "package.json").read_text("utf-8")).get("exports", {})
    blob = []
    for target in exports.values():
        p = (_TS / str(target).lstrip("./")).resolve()
        if p.is_file():
            blob.append(p.read_text("utf-8"))
    return "\n".join(blob)


def test_no_transliterated_ts_factories_on_public_surface() -> None:
    """No new*-prefixed or PascalCase-transliterated factory is publicly exported in TS."""
    text = _ts_public_export_text()
    survivors = []
    for name in _FORBIDDEN_TS:
        # Match an export declaration or re-export of the forbidden name.
        if re.search(rf"export\s+(?:function|const|class)\s+{name}\b", text) or re.search(
            rf"export\s*\{{[^}}]*\b{name}\b", text
        ):
            survivors.append(name)
    assert not survivors, f"transliterated TS factories still exported: {survivors}"


def test_python_idempotency_generator_renamed() -> None:
    """Python exposes generate_idempotency_key, not the transliterated new_idempotency_key."""
    assert "new_idempotency_key" not in ramp_sdk.__all__, (
        "new_idempotency_key is still public — rename to generate_idempotency_key"
    )
    assert "generate_idempotency_key" in ramp_sdk.__all__, (
        "generate_idempotency_key not yet exported"
    )
