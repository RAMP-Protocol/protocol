"""Scopes / entitlements (ADR-020 §5) — Python port of the sdk/go oracle
(helpers/scopes.go). The subscriptions/entitlements a requester holds are a
SUPPLIED credential: the application hands the SDK what it holds and the SDK
plumbs it into the request. ``normalize_scopes``/``scopes_subset`` are pure,
byte-deterministic string ops pinned to the shared scopes-vectors.json.
"""

from __future__ import annotations


def normalize_scopes(scopes: list[str]) -> list[str]:
    """Return scopes with empty entries dropped, duplicates removed (first-seen),
    and a stable (lexicographic) order — so two callers supplying the same set
    produce identical bytes on the wire. No casing change, no trimming.

    The sdk/go oracle returns ``nil`` for empty/all-empty input; the Python face
    returns ``[]`` (the parity comparator treats null == []).
    """
    seen: set[str] = set()
    out: list[str] = []
    for s in scopes:
        if s == "" or s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return out


def scopes_subset(sub: list[str], superset: list[str]) -> bool:
    """Report whether every scope in ``sub`` is present in ``superset`` — the
    delegation-attenuation rule (Delegation.scopes MUST be a subset of the
    principal's granted scopes). An empty ``sub`` is always a subset.
    """
    return set(sub).issubset(superset)


def apply_scopes(scopes: list[str]) -> list[str]:
    """Functional analogue of the Go ApplyScopes (which mutates a proto
    Requester). The Python port has no generated Requester mutation face, so it
    returns the normalized scopes array the caller stamps onto its own request.
    """
    return normalize_scopes(scopes)
