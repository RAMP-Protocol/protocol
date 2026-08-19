"""``EndpointRefusedError`` is reachable from the package root.

The endpoint rule's verdict is the one a caller classifies retryability on — it says
the Exchange answered and the answer is unusable, so the call is final rather than
worth another try. Its five sibling resolver verdicts are all re-exported at the
package root; this one was not, so ``ramp_sdk.EndpointRefusedError`` did not exist
while ``ramp_sdk.resolvers.EndpointRefusedError`` did.

The API-surface gate cannot see that split: it takes the UNION of the two ``__all__``
lists, so a name present in either satisfies it. This asserts the placement the gate
is blind to, following the per-symbol home tests already in this suite.
"""

from __future__ import annotations

import ramp_sdk
from ramp_sdk.resolvers import EndpointRefusedError


def test_endpoint_refused_error_is_exported_from_the_package_root() -> None:
    assert "EndpointRefusedError" in ramp_sdk.__all__
    assert ramp_sdk.EndpointRefusedError is EndpointRefusedError


def test_it_sits_beside_its_siblings() -> None:
    """Every resolver verdict a caller classifies on has the same home."""
    for sibling in (
        "ResolverError",
        "NoEndpointError",
        "DirectoryUnavailableError",
        "UnknownKeyError",
        "KeyRevokedError",
        "KeyExpiredError",
    ):
        assert sibling in ramp_sdk.__all__
