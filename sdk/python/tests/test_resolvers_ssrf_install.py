"""The SSRF guard must actually ATTACH, and must fail closed if it can't.

The guard installs by assigning ``transport._pool._network_backend`` — httpx/httpcore
PRIVATE internals. A future release that renamed them would turn a bare assignment
into a silent no-op (Python creates a dead attribute, no error), leaving a pre-auth
fetch path UNGUARDED while the suite stays green. These tests pin two things:

  1. ``ssrf_guard`` / ``async_ssrf_guard`` leave the guarded backend actually
     installed on the transport's connection pool (the positive contract);
  2. ``_install_guarded_backend`` RAISES rather than returning an unguarded
     transport when the private seam it depends on is absent (a rename of
     ``_pool`` or ``_network_backend``) — the fail-closed backstop behind the
     pyproject version ceiling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from ramp_sdk.resolvers._http import (
    _AsyncGuardedBackend,
    _GuardedBackend,
    _install_guarded_backend,
    async_ssrf_guard,
    ssrf_guard,
)

if TYPE_CHECKING:
    import httpx


def test_ssrf_guard_installs_guarded_backend() -> None:
    transport = ssrf_guard()
    try:
        assert isinstance(transport._pool._network_backend, _GuardedBackend)
    finally:
        transport.close()


def test_async_ssrf_guard_installs_guarded_backend() -> None:
    transport = async_ssrf_guard()
    assert isinstance(transport._pool._network_backend, _AsyncGuardedBackend)


class _PoolWithoutBackend:
    """Stands in for a future ConnectionPool that renamed ``_network_backend``."""


class _TransportWithRenamedBackend:
    def __init__(self) -> None:
        self._pool = _PoolWithoutBackend()


class _TransportWithoutPool:
    """Stands in for a future httpx transport that renamed ``_pool``."""


def test_install_fails_closed_when_backend_attr_absent() -> None:
    fake = cast("httpx.HTTPTransport", _TransportWithRenamedBackend())
    with pytest.raises(RuntimeError, match="UNGUARDED"):
        _install_guarded_backend(fake, _GuardedBackend())


def test_install_fails_closed_when_pool_absent() -> None:
    fake = cast("httpx.HTTPTransport", _TransportWithoutPool())
    with pytest.raises(RuntimeError, match="UNGUARDED"):
        _install_guarded_backend(fake, _GuardedBackend())
