"""Typed error surface for the fetching resolver faces.

The Go oracle uses errors.Is-DISTINCT sentinels (ErrKeyRevoked / ErrKeyExpired /
ErrDirectoryUnavailable / ErrNoEndpoint / ErrUnknownKey) so a composite resolver
can HALT on a fail-closed verdict rather than fall through as if the key were
merely unknown. The port preserves that distinctness as distinct exception
classes: each fail-closed verdict is its own catchable class, and (critically)
``DirectoryUnavailableError`` is NOT a subclass of ``UnknownKeyError`` — an
outage must stay distinguishable from an unknown key.
"""

from __future__ import annotations


class ResolverError(Exception):
    """Base of every resolver verdict."""


class UnknownKeyError(ResolverError):
    """No key is known for the requested keyid/thumbprint (fall-through miss)."""


class KeyRevokedError(ResolverError):
    """The thumbprint is present in the directory host's revocation snapshot."""


class KeyExpiredError(ResolverError):
    """The key exists but ``now`` is outside its [not_before, not_after) window."""


class DirectoryUnavailableError(ResolverError):
    """A well-known directory/JWKS/manifest could not be fetched or decoded.

    Deliberately NOT a subclass of :class:`UnknownKeyError`: a fail-closed
    composite must be able to halt on a directory outage rather than fall
    through as if the key were merely unknown.
    """


class NoEndpointError(ResolverError):
    """A manifest was fetched and decoded but advertises no endpoint."""
