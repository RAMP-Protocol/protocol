"""Source-level adoption guard for the sdk/python L1 relocation (ixs7u.6).

Mirrors the sdk/ts sibling (sdk/ts/tests/library_adoption_guard.test.ts). It pins
that the canonical sdk/python helpers keep composing the generated artifacts + the
fixed byte contract, so a future edit cannot silently re-introduce the disease the
port eliminated (a hand-rolled Pydantic wire mirror instead of the generated
gen/python models, or a drifted canonical thumbprint JWK string).

SCOPE — deliberately sdk/python/ramp_sdk ONLY. A tree-wide ban would false-fire on
the app modules, which MUST still exist until their deletion in the downstream
adoption ticket (ixs7u.8). The behavioral guard for byte-parity is the parity
suite (test_*_parity.py vs the Go oracle vectors); this file adds the source-level
guard.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

_SRC = pathlib.Path(__file__).resolve().parents[1] / "ramp_sdk"


@dataclass(frozen=True)
class SiteGuard:
    file: str
    forbidden: list[str] = field(default_factory=list)
    required: list[str] = field(default_factory=list)


def _read_source(name: str) -> str:
    return (_SRC / name).read_text()


def eval_site(src: str, guard: SiteGuard) -> list[str]:
    """Pure predicate: forbidden substrings must be ABSENT, required must be PRESENT."""
    violations: list[str] = []
    for bad in guard.forbidden:
        if bad in src:
            violations.append(f"{guard.file} still contains disease instance {bad!r}")
    for req in guard.required:
        if req not in src:
            violations.append(f"{guard.file} is missing the canonical marker {req!r}")
    return violations


def test_thumbprint_preserves_fixed_canonical_jwk_byte_contract() -> None:
    # The exact member order / literal is the cross-language byte contract (Go
    # go-jose + TS emit the same string). A reorder or reformat silently breaks
    # byte-parity with the oracle.
    violations = eval_site(
        _read_source("thumbprint.py"),
        SiteGuard(file="thumbprint.py", required=['{"crv":"Ed25519","kty":"OKP","x":"']),
    )
    assert violations == []


def test_crossfield_composes_the_generated_models() -> None:
    # The cross-field layer must compose ONTO the generated wire.models, never
    # hand-declare a parallel Pydantic wire mirror.
    violations = eval_site(
        _read_source("crossfield.py"),
        SiteGuard(
            file="crossfield.py",
            required=["from wire.models import"],
        ),
    )
    assert violations == []


def test_acceptance_reuses_the_generated_payload_type() -> None:
    violations = eval_site(
        _read_source("acceptance.py"),
        SiteGuard(
            file="acceptance.py",
            required=["from wire.models import AgentAcceptancePayload"],
        ),
    )
    assert violations == []


# ---- Meta-tests: prove the guard catches a regression and passes clean source.
def test_meta_catches_reintroduced_mirror_and_missing_import() -> None:
    bad = "class License(BaseModel):\n    id: str\n"
    guard = SiteGuard(
        file="synthetic.py",
        forbidden=["class License(BaseModel):"],
        required=["from wire.models import"],
    )
    assert len(eval_site(bad, guard)) == 2


def test_meta_passes_clean_composed_source() -> None:
    good = "from wire.models import License\n"
    guard = SiteGuard(
        file="synthetic.py",
        forbidden=["class License(BaseModel):"],
        required=["from wire.models import"],
    )
    assert eval_site(good, guard) == []
