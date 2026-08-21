"""Non-empty-corpus guard for the sdk/python cross-language parity suite.

The parity suites parametrize over the case lists loaded from the shared
Go-oracle corpora (``@pytest.mark.parametrize("vector", load_json(...)["vectors"])``
and friends). A corpus file that is PRESENT but holds an EMPTY case list is a
silent vacuity vector: ``parametrize`` over an empty sequence emits ZERO test
items, the parity dimension is skipped, and the job stays green having asserted
nothing. Neither the collection-error path (a MISSING file / MISSING binding)
nor pytest's exit-5 (zero total collection) catches a single emptied corpus.

This guard closes that vector. For every committed corpus the parity suite
depends on it asserts the consumed case list is NON-EMPTY, with a message
naming the corpus and the dimension it would otherwise vacuum. It asserts COUNT
only — never vector bytes (``test_offer_sign_parity`` and the other parity
suites own the byte-equality claims) — so it adds no duplicated assertion.

Paths and the JSON loader come from ``conftest`` (``load_json`` / ``GO_TESTDATA``
/ ``CONFORMANCE_CORPUS``); the extraction of each corpus's case list mirrors how
the consuming parity test reads it, so an emptied corpus fails here the same way
it would silently vanish there.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from conftest import (
    CONFORMANCE_CORPUS,
    GO_CONNECT_TESTDATA,
    GO_RESOLVERS_TESTDATA,
    GO_TESTDATA,
    load_json,
)

if TYPE_CHECKING:
    import pathlib
    from collections.abc import Callable
    from typing import Any


def _vectors(doc: Any) -> Any:
    """Case list under the ``vectors`` key (the common corpus shape)."""
    return doc["vectors"]


def _whole(doc: Any) -> Any:
    """Case list IS the top-level document (a bare JSON array corpus)."""
    return doc


# (corpus path, case-list extractor, dimension name) — one entry per parity
# dimension that parametrizes over a shared corpus. The extractor mirrors the
# consuming test's read, so "non-empty here" == "non-empty at the parametrize".
_CORPUS_SPECS: list[tuple[pathlib.Path, Callable[[Any], Any], str]] = [
    (GO_TESTDATA / "offer-verify-vectors.json", _vectors, "offer-verify"),
    (GO_TESTDATA / "acceptance-vectors.json", _vectors, "acceptance"),
    (GO_TESTDATA / "hashurl-vectors.json", _vectors, "hashurl"),
    (GO_TESTDATA / "multisig-chain-vectors.json", _vectors, "multisig-chain"),
    (GO_TESTDATA / "money-vectors.json", _vectors, "money"),
    (GO_TESTDATA / "idempotency-validate-vectors.json", _vectors, "idempotency-validate"),
    (GO_TESTDATA / "thumbprint-vectors.json", _vectors, "thumbprint"),
    (GO_TESTDATA / "sign-request-vectors.json", _vectors, "sign-request"),
    (GO_TESTDATA / "verify-request-neg-vectors.json", _vectors, "verify-request-neg"),
    (GO_TESTDATA / "wire-canonical-vectors.json", _vectors, "wire-canonical"),
    (GO_TESTDATA / "wire-constants-vectors.json", _vectors, "wire-constants"),
    (GO_TESTDATA / "error-detail-vectors.json", _vectors, "error-detail"),
    (GO_TESTDATA / "pop-vectors.json", _whole, "pop"),
    (GO_TESTDATA / "signedurl-vectors.json", _whole, "signedurl"),
    (GO_TESTDATA / "scopes-vectors.json", lambda d: d["normalize"], "scopes-normalize"),
    (GO_TESTDATA / "scopes-vectors.json", lambda d: d["subset"], "scopes-subset"),
    (GO_TESTDATA / "audience-vectors.json", lambda d: d["bare_domain"], "bare-domain"),
    (GO_TESTDATA / "audience-vectors.json", lambda d: d["audience"], "audience"),
    (GO_TESTDATA / "registration-schema-vectors.json", lambda d: d["compile"], "regschema-compile"),
    (
        GO_TESTDATA / "registration-schema-vectors.json",
        lambda d: d["validate"],
        "regschema-validate",
    ),
    (GO_TESTDATA / "registration-schema-vectors.json", lambda d: d["pattern"], "regschema-pattern"),
    (GO_TESTDATA / "registration-schema-vectors.json", lambda d: d["match"], "regschema-match"),
    (
        GO_TESTDATA / "registration-schema-vectors.json",
        lambda d: d["registration_data"],
        "regschema-registration-data",
    ),
    (GO_TESTDATA / "host-rule-vectors.json", lambda d: d["host_of"], "host-of"),
    (GO_TESTDATA / "host-rule-vectors.json", lambda d: d["is_bare_host"], "is-bare-host"),
    (GO_TESTDATA / "host-rule-vectors.json", lambda d: d["host_anchored"], "host-anchored"),
    (
        GO_RESOLVERS_TESTDATA / "endpoint-vet-vectors.json",
        lambda d: d["endpoint_vet"],
        "endpoint-vet",
    ),
    (
        GO_CONNECT_TESTDATA / "connect-error-vectors.json",
        _vectors,
        "connect-error-envelope",
    ),
    (
        GO_CONNECT_TESTDATA / "transport-failure-vectors.json",
        lambda d: d["transport_failures"],
        "transport-failure",
    ),
    (
        GO_TESTDATA / "wire-names-vectors.json",
        lambda d: d["snake_from_json_name"],
        "wire-names-snake",
    ),
    (GO_TESTDATA / "wire-names-vectors.json", lambda d: d["hex_decode"], "wire-names-hex"),
    (
        GO_CONNECT_TESTDATA / "client-request-vectors.json",
        _vectors,
        "client-request",
    ),
    (
        GO_RESOLVERS_TESTDATA / "content-fetch-vectors.json",
        _vectors,
        "content-fetch",
    ),
    (CONFORMANCE_CORPUS / "crossfield.json", _whole, "crossfield"),
]


def test_corpus_registry_is_nonempty() -> None:
    """Guard the guard: an emptied ``_CORPUS_SPECS`` would itself vacuum."""
    assert len(_CORPUS_SPECS) > 0, (
        "the parity-corpus registry is empty -> this non-empty guard would "
        "itself run 0 cases and every parity dimension would be unguarded"
    )


@pytest.mark.parametrize(
    ("path", "extract", "dimension"),
    _CORPUS_SPECS,
    ids=[spec[2] for spec in _CORPUS_SPECS],
)
def test_parity_corpus_is_nonempty(
    path: pathlib.Path,
    extract: Callable[[Any], Any],
    dimension: str,
) -> None:
    """A present-but-empty corpus must fail loudly, not vacuum its gate."""
    cases = extract(load_json(path))
    assert len(cases) > 0, (
        f"parity corpus {path.name} is empty -> the {dimension} parity gate "
        f"would run 0 cases and pass vacuously"
    )
