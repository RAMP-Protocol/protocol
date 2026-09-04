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


class RevocationUnevaluatedError(ResolverError):
    """The key resolved, but its directory declares a revocation_url whose
    snapshot has never been fetched (unreachable or not host-anchored) — so
    revocation was NEVER EVALUATED, which is DISTINCT from "evaluated and not
    revoked" (:class:`KeyRevokedError` is the revoked verdict).

    Only raised when the resolver is constructed with ``require_revocation=True``;
    the default keeps the prior best-effort behavior (a declared-but-unreachable
    revocation channel does not block resolution). It lets a caller that treats
    revocation as mandatory fail closed instead of trusting an unevaluated key.
    """


class DirectoryUnavailableError(ResolverError):
    """A well-known directory/JWKS/manifest could not be fetched or decoded.

    Deliberately NOT a subclass of :class:`UnknownKeyError`: a fail-closed
    composite must be able to halt on a directory outage rather than fall
    through as if the key were merely unknown.
    """


class NoEndpointError(ResolverError):
    """A manifest was fetched and decoded but advertises no endpoint."""


class EndpointRefusedError(ResolverError):
    """A manifest was read and advertises an endpoint this resolver will not hand
    back: one on a host or port unrelated to the domain that served the manifest,
    or one carrying userinfo.

    DISTINCT from :class:`NoEndpointError` and from
    :class:`DirectoryUnavailableError` because it is a VERDICT — the Exchange
    answered, and the answer is not usable. A caller that classifies retryability
    reads this as final rather than as something to try again in a moment.
    """


class ExchangeNotPermittedError(ResolverError):
    """The deployment's allow overlay excluded this Exchange domain, before anything
    was dialled.

    It says nothing about whether the Exchange exists or answers, only that this
    deployment declined to ask, so the remedy is a configuration change rather than a
    retry. Peer of Go ``ErrExchangeNotPermitted`` / TS ``ExchangeNotPermitted``.
    """


class ManifestNotExchangeError(ResolverError):
    """The document served at the domain's well-known path describes some other role.

    Registration requirements are an Exchange's to publish, so a manifest claiming to
    be an agent, a broker or a publisher is refused rather than read for members it
    has no business carrying. A manifest naming no role at all is refused the same
    way: the field is required by the contract, and reading silence as assent would
    make the check advisory. Peer of Go ``ErrManifestNotExchange`` / TS
    ``ManifestNotExchange``.
    """


class ManifestVersionRefusedError(ResolverError):
    """A ``/.well-known/ramp.json`` was fetched and parsed but carries a
    ``WellKnownManifest.ver`` this resolver does not accept: an unrecognised major
    version, a value that is not ``MAJOR.MINOR``, or no version at all. The rule is
    :func:`ramp_sdk.wire.manifest_version_refusal`.

    Like :class:`EndpointRefusedError` it is a VERDICT — final, not a transport
    failure to retry — and it is never cached. The gate runs before any other
    member of the document is read, for the reason stated once on
    ``WellKnownManifest.ver`` in the proto.
    """
