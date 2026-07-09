"""M-6: require_revocation fails closed on an UNEVALUATED revocation channel.

Port of the Go oracle's TestWBAKeyResolver_RequireRevocationUnevaluated. A
directory that declares a revocation_url whose snapshot never lands (here:
cross-host, so the host-anchor guard refuses the poll) leaves revocation
UNEVALUATED. The default best-effort mode still resolves the key; the
require_revocation mode fails closed with RevocationUnevaluatedError — DISTINCT
from KeyRevokedError ("evaluated and revoked").
"""

from __future__ import annotations

import pytest
from resolvers_harness import (
    ANCHOR,
    HOUR,
    MutableClock,
    Origin,
    loopback_fetch,
    make_key,
    revocation_json,
    wba_file_json,
    wba_jwk,
)

from ramp_sdk.resolvers import (
    KeyRevokedError,
    RevocationUnevaluatedError,
    WBAKeyResolver,
)


def test_require_revocation_unevaluated_fails_closed() -> None:
    key = make_key()

    # A revocation host the resolver must NOT follow: it declares the key as
    # revoked, but sits on a different host than the directory, so the anchor
    # guard refuses the poll and no snapshot ever lands.
    evil = Origin()
    directory = Origin()
    try:
        evil.set_revocation(revocation_json(ANCHOR, [key.tp]))
        directory.set_wba(
            wba_file_json(
                [wba_jwk(key.x, ANCHOR - HOUR, ANCHOR + HOUR)],
                revocation_url=evil.revocation_url(),  # cross-host → not anchored
            )
        )

        # Default (best-effort): resolves despite the unevaluated revocation channel.
        best = WBAKeyResolver(http=loopback_fetch, scheme="http", now=MutableClock(ANCHOR))
        assert best.resolve(key.tp, directory.url) == key.raw_pub

        # require_revocation: fail closed — revocation_url declared, no snapshot.
        strict = WBAKeyResolver(
            http=loopback_fetch,
            scheme="http",
            now=MutableClock(ANCHOR),
            require_revocation=True,
        )
        with pytest.raises(RevocationUnevaluatedError) as excinfo:
            strict.resolve(key.tp, directory.url)
        # Unevaluated must be DISTINCT from revoked.
        assert not isinstance(excinfo.value, KeyRevokedError)
    finally:
        evil.close()
        directory.close()
