"""Verifying-key resolution seam (ADR-020 §4) — the injection point for key lookup.

Mirrors the sdk/go split (sdk/go/helpers/keyresolver.go): the pure L1 verify takes
a resolved key directly; the resolver is how an application supplies keys — from a
well-known endpoint, a private registry, a preloaded set, a proxy, or mTLS. This
module carries only the PURE ``StaticKeyResolver``; the fetching well-known
resolver (IO) is the injected default that lives OUTSIDE the pure L1 verify.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class KeyResolver(Protocol):
    """Resolve the raw 32-byte Ed25519 public key for a keyid, or None if unknown."""

    def resolve(self, keyid: str | None) -> bytes | None:
        """Return the public key registered for ``keyid``, or None."""
        ...


class StaticKeyResolver:
    """Serve public keys from an in-memory map — for preloaded key sets and tests."""

    def __init__(self, keys: dict[str, bytes] | None = None) -> None:
        """Seed the resolver with a copy of ``keys``."""
        self._keys: dict[str, bytes] = dict(keys or {})

    def resolve(self, keyid: str | None) -> bytes | None:
        """Return the public key for ``keyid``, or None when unknown/absent."""
        if keyid is None:
            return None
        return self._keys.get(keyid)

    def put(self, keyid: str, pub: bytes) -> None:
        """Register a ``keyid -> public-key`` mapping (dynamic / test seeding)."""
        self._keys[keyid] = pub
