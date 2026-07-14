"""Symbol-level API-surface parity gate (go oracle -> python + ts).

The shared-corpus completeness gate (test_corpus_replay_completeness.py) locks the
BYTES of vectored behaviors but is blind to a MISSING SYMBOL — that is exactly how
the TS SDK once shipped without ``CachedOfferKeyResolver`` / ``SigningTransport``: no
byte diverged because the face simply was not there. This gate closes that hole from
the symbol side.

Go is the oracle. Every exported Go symbol under
``sdk/go/{helpers,resolvers,core,connect,connectserver}`` must be, in
``sdk/parity/symbol-map.json``, EITHER

  * a ``symbols`` entry — mapped to the public Python and/or TS name (or null where a
    language exposes no public symbol of that name), OR
  * a ``go_exclusions`` entry — a Go-idiomatic symbol with a written reason it has no
    1:1 cross-language public face.

The gate then asserts four properties:

  (i)   PRESENCE     — every non-null mapped python/ts name is actually present in the
                       live surface (a renamed/removed face fails CI).
  (ii)  COMPLETENESS — every live Go public symbol is a map key or an exclusion (a NEW
                       unmapped Go symbol fails CI — the map cannot silently omit).
  (iii) SHRINK-ONLY  — the allowlist of deliberate divergences only ever DECREASES;
                       full divergences (both null) are backed by a DECISION bullet in
                       the parity matrix, partial gaps (one-sided null) by an inline
                       allowlist_reason naming a tracked follow-up.
  (iv)  NON-VACUITY  — a symbol present in ONE language but null in the other with NO
                       allowlist_reason is an UNDOCUMENTED gap and fails CI. Presence
                       only asserts non-null names, so a bare null is invisible to it;
                       this property forces every gap to be RESOLVED (name filled) or
                       DOCUMENTED (reason). BOTH directions are held at hard zero.

The Go surface is read with ``go doc``; the TS surface is read by scanning every module
listed in ``sdk/ts/package.json`` ``exports`` for BOTH inline
``export function/const/class/interface/type/enum`` declarations AND ``export {...}``
re-exports — a barrel-only scan would miss inline faces like ``createSigningTransport``,
the exact class of symbol this gate exists to catch.

TS object factories carry the create* prefix and value generators the generate* prefix
(Go NewX stays idiomatic); sdk/parity/symbol-map.json holds the mapped names.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

# JSON shapes read out of symbol-map.json.
ParityMap = dict[str, Any]
Entry = dict[str, Any]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SDK_GO = _REPO_ROOT / "sdk" / "go"
_SDK_TS = _REPO_ROOT / "sdk" / "ts"
_MAP_PATH = _REPO_ROOT / "sdk" / "parity" / "symbol-map.json"
_MATRIX = _REPO_ROOT / "docs" / "sdk-parity-matrix.md"

_GO_PACKAGES = ("helpers", "resolvers", "core", "connect", "connectserver")

# RATCHET — this baseline may only ever DECREASE. Each allowlisted symbol is a
# deliberate, DOCUMENTED cross-language divergence, in one of two flavors:
#   * FULL divergence (python AND ts BOTH null) — backed by a DECISION bullet in
#     docs/sdk-parity-matrix.md reached via decision_anchor (connect.Client /
#     connect.NewClient and the two connectserver handler bindings).
#   * PARTIAL gap (one language present, the other genuinely absent) — backed by an
#     inline allowlist_reason naming the one-sided divergence. The 10 partial gaps are
#     all language-idiom folds absorbed from the old BASELINE_PY_ONLY_GAP ratchet —
#     seven Go NewX constructor funcs that fold into Python class constructors, and
#     three Go/TS options types that fold into Python constructor kwargs. Each carries
#     a per-entry reason; none is a symbol Python is missing. (The two former
#     ErrUnknownKey partial gaps are RESOLVED: TS now exports the UnknownKey error
#     class, completing the resolver error taxonomy in all three languages.)
# A change that RAISES this number adds a new silent divergence and MUST be reviewed as
# such: bumping the constant is the whole tell. Never raise it to make a red gate green —
# map the symbol (fill the name) or record the divergence. Moved 6 -> 16 ONLY by
# documenting the ten previously-OPAQUE Python-null gaps (BASELINE_PY_ONLY_GAP 19 -> 0
# in the same change — 19 undocumented divergences became 10 documented ones and 9
# exported Python symbols; that trade is the one sanctioned growth shape — every entry
# must arrive with its reason, never bare), then shrunk 16 -> 14 by resolving the two
# ErrUnknownKey gaps.
BASELINE_ALLOWLIST = 14

# HARD ZERO (was a shrink-only ratchet at 19) — undocumented TS-present / Python-null
# gaps. The PRESENCE check skips nulls, so absent this ceiling a NEW Python-null gap
# would ship GREEN — the exact blind spot this gate closes, in the Python direction.
# The original 19 were resolved to zero: 9 became exported Python symbols (the
# Verifier/Result/Mode/VerifiedOffer/RejectedOffer family, the two *_SIGNATURE_ALGORITHM
# constants, content_digest, and the RejectReason Literal), and 10 genuine language-idiom
# folds (Go NewX -> Python class ctor; Go/TS options types -> Python ctor kwargs) moved
# under BASELINE_ALLOWLIST with per-entry reasons. Both directions now sit at hard zero:
# every new gap must be RESOLVED (fill the python name) or DOCUMENTED (allowlist_reason),
# never left bare. Do not raise this from 0.
BASELINE_PY_ONLY_GAP = 0


# --------------------------------------------------------------------------- #
# Surface enumerators
# --------------------------------------------------------------------------- #
def _go_available() -> bool:
    return shutil.which("go") is not None


_SECTION_RE = re.compile(r"^(CONSTANTS|VARIABLES|FUNCTIONS|TYPES)\s*$")
_TOP_FUNC_RE = re.compile(r"^func ([A-Z][A-Za-z0-9_]*)\(")
_TOP_TYPE_RE = re.compile(r"^type ([A-Z][A-Za-z0-9_]*)\b")
_TOP_CONST_RE = re.compile(r"^const ([A-Z][A-Za-z0-9_]*)\b")
_TOP_VAR_RE = re.compile(r"^var ([A-Z][A-Za-z0-9_]*)\b")
_GROUP_OPEN_RE = re.compile(r"^(const|var) \($")
_GROUP_ENTRY_RE = re.compile(r"^\t([A-Z][A-Za-z0-9_]*) ")


def _parse_go_doc(text: str) -> set[str]:
    """Extract exported top-level symbol names from ``go doc -all`` output.

    Grouped ``const (...)`` / ``var (...)`` blocks are expanded (plain ``go doc``
    truncates them with ``...``). Methods (``func (recv T) M``) are NOT captured — they
    are part of their type, matching the top-level surface.
    """
    syms: set[str] = set()
    section: str | None = None
    in_group = False
    for line in text.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1)
            in_group = False
            continue
        if section in ("CONSTANTS", "VARIABLES"):
            if _GROUP_OPEN_RE.match(line):
                in_group = True
                continue
            if in_group:
                if line == ")":
                    in_group = False
                    continue
                gm = _GROUP_ENTRY_RE.match(line)
                if gm:
                    syms.add(gm.group(1))
                continue
            single = _TOP_CONST_RE.match(line) or _TOP_VAR_RE.match(line)
            if single:
                syms.add(single.group(1))
        elif section == "FUNCTIONS":
            fm = _TOP_FUNC_RE.match(line)
            if fm:
                syms.add(fm.group(1))
        elif section == "TYPES":
            tm = _TOP_TYPE_RE.match(line) or _TOP_FUNC_RE.match(line)
            if tm:
                syms.add(tm.group(1))
    return syms


def enumerate_go() -> dict[str, str]:
    """pkg-qualified -> bare name for every exported symbol in the SDK Go packages."""
    go_bin = shutil.which("go")
    assert go_bin is not None  # callers gate on _go_available()
    out: dict[str, str] = {}
    for pkg in _GO_PACKAGES:
        proc = subprocess.run(  # noqa: S603 — fixed argv, resolved `go` binary, repo-local package path
            [go_bin, "doc", "-all", f"./sdk/go/{pkg}"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        for name in _parse_go_doc(proc.stdout):
            out[f"{pkg}.{name}"] = name
    return out


def enumerate_python() -> set[str]:
    """The public Python surface: ramp_sdk.__all__ + ramp_sdk.resolvers.__all__."""
    import ramp_sdk
    from ramp_sdk import resolvers

    return set(ramp_sdk.__all__) | set(resolvers.__all__)


_TS_INLINE_RE = re.compile(
    r"^export\s+(?:async\s+)?(?:function|const|class|interface|type|enum)\s+"
    r"([A-Za-z_$][\w$]*)"
)
_TS_REEXPORT_OPEN_RE = re.compile(r"export\s+(?:type\s+)?\{")
_TS_REEXPORT_NAME_RE = re.compile(r"^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$")


def _scan_ts_module_text(text: str) -> set[str]:
    """Extract the public names a TS module exports.

    Handles BOTH inline ``export function/const/class/interface/type/enum <name>`` AND
    ``export { A, type B, C as D } from "..."`` re-export blocks. A barrel-only scan
    would miss every inline face (e.g. ``createSigningTransport``) — precisely the symbols
    this gate is built to protect.
    """
    names: set[str] = set()
    for line in text.splitlines():
        m = _TS_INLINE_RE.match(line.strip())
        if m:
            names.add(m.group(1))
    idx = 0
    while True:
        m = _TS_REEXPORT_OPEN_RE.search(text, idx)
        if not m:
            break
        close = text.find("}", m.end())
        if close == -1:
            break
        block = text[m.end() : close]
        for raw in block.split(","):
            part = re.sub(r"^type\s+", "", raw.strip())
            if not part:
                continue
            nm = _TS_REEXPORT_NAME_RE.match(part)
            if nm:
                names.add(nm.group(2) or nm.group(1))
        idx = close + 1
    return names


def enumerate_ts() -> set[str]:
    """The public TS surface: every symbol exported by a module in package.json exports."""
    pkg = json.loads((_SDK_TS / "package.json").read_text(encoding="utf-8"))
    names: set[str] = set()
    for rel in pkg["exports"].values():
        module = _SDK_TS / rel.lstrip("./")
        names |= _scan_ts_module_text(module.read_text(encoding="utf-8"))
    return names


# --------------------------------------------------------------------------- #
# Pure check helpers (shared by the live gate and its guard-the-guard meta-tests)
# --------------------------------------------------------------------------- #
def _load_map() -> ParityMap:
    loaded: ParityMap = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
    return loaded


def presence_failures(
    symbols: dict[str, Entry], py_surface: set[str], ts_surface: set[str]
) -> list[str]:
    """Every non-null mapped python/ts name must be present in its live surface."""
    failures: list[str] = []
    for key, entry in symbols.items():
        if entry.get("allowlist_reason"):
            continue  # documented divergence — presence deliberately not asserted
        py = entry.get("python")
        ts = entry.get("ts")
        if py is not None and py not in py_surface:
            failures.append(f"{key}: mapped Python name {py!r} absent from ramp_sdk surface")
        if ts is not None and ts not in ts_surface:
            failures.append(f"{key}: mapped TS name {ts!r} absent from package.json exports")
    return failures


def undocumented_gaps(symbols: dict[str, Entry]) -> tuple[list[str], list[str]]:
    """Split the asymmetric-null entries that carry NO allowlist_reason.

    A symbol present in one language but ``null`` in the other is a GAP. The PRESENCE
    check only asserts NON-null names, so a bare null is invisible to it — an
    undocumented claim that "this language legitimately lacks the face" that nobody
    verified. This is the exact hole the gate exists to kill.

    Returns ``(ts_gaps, py_gaps)`` where ts_gaps are python-present / ts-null and py_gaps
    are ts-present / python-null. Allowlisted entries (documented divergences) are
    excluded from both.
    """
    ts_gaps: list[str] = []
    py_gaps: list[str] = []
    for key, entry in symbols.items():
        if entry.get("allowlist_reason"):
            continue
        py = entry.get("python")
        ts = entry.get("ts")
        if py is not None and ts is None:
            ts_gaps.append(key)
        elif ts is not None and py is None:
            py_gaps.append(key)
    return ts_gaps, py_gaps


def completeness_failures(go_symbols: dict[str, str], parity_map: ParityMap) -> list[str]:
    """Every live Go public symbol must be a map key or an explicit exclusion."""
    mapped = set(parity_map["symbols"])
    excluded = set(parity_map["go_exclusions"])
    accounted = mapped | excluded
    return [
        f"{key} ({name}): live Go public symbol is neither in symbol-map.json 'symbols' "
        f"nor 'go_exclusions' — an unmapped Go symbol is invisible to the gate"
        for key, name in sorted(go_symbols.items())
        if key not in accounted
    ]


# --------------------------------------------------------------------------- #
# (ii) COMPLETENESS — needs the Go toolchain
# --------------------------------------------------------------------------- #
def test_every_go_public_symbol_is_mapped_or_excluded() -> None:
    if not _go_available():
        pytest.skip(
            "LOUD SKIP: `go` toolchain not on PATH — cannot enumerate the Go oracle "
            "surface, so the COMPLETENESS half of the API-parity gate cannot run. CI's "
            "sdk-l1 job has actions/setup-go and DOES run it; a green local run without "
            "Go is NOT a green gate."
        )
    parity_map = _load_map()
    failures = completeness_failures(enumerate_go(), parity_map)
    assert not failures, "unmapped Go public symbols:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------- #
# (i) PRESENCE — Python + TS surfaces only (no Go toolchain needed)
# --------------------------------------------------------------------------- #
def test_mapped_symbols_present_in_python_and_ts() -> None:
    parity_map = _load_map()
    failures = presence_failures(parity_map["symbols"], enumerate_python(), enumerate_ts())
    assert not failures, "mapped symbols missing from the live surface:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------- #
# (iv) SHRINK-ONLY allowlist
# --------------------------------------------------------------------------- #
def test_allowlist_is_shrink_only_and_decision_backed() -> None:
    parity_map = _load_map()
    matrix = _MATRIX.read_text(encoding="utf-8")
    allowlisted = {k: v for k, v in parity_map["symbols"].items() if v.get("allowlist_reason")}

    assert len(allowlisted) <= BASELINE_ALLOWLIST, (
        f"allowlist grew to {len(allowlisted)} > baseline {BASELINE_ALLOWLIST}. The "
        "allowlist is SHRINK-ONLY: map the symbol or record a DECISION, never raise "
        "the baseline to make the gate green."
    )
    assert "DECISION" in matrix, "parity matrix carries no DECISION bullets"

    for key, entry in allowlisted.items():
        py = entry.get("python")
        ts = entry.get("ts")
        if py is None and ts is None:
            # FULL divergence — neither language exposes the face. Must be a RECORDED
            # matrix DECISION, reached via decision_anchor, not a silent gap.
            anchor = entry.get("decision_anchor")
            assert anchor, f"{key}: full-divergence allowlist entry lacks a decision_anchor"
            assert anchor in matrix, (
                f"{key}: decision_anchor {anchor!r} not found in docs/sdk-parity-matrix.md — "
                "an allowlisted full divergence must be a RECORDED decision, not a silent gap"
            )
        else:
            # PARTIAL gap — one language has the face, the other is genuinely absent. A
            # tracked follow-up documented inline by a non-empty allowlist_reason (no
            # matrix DECISION yet; the reason names why the face is one-sided).
            reason = entry.get("allowlist_reason")
            assert isinstance(reason, str) and reason.strip(), (
                f"{key}: partial-gap allowlist entry needs a non-empty allowlist_reason "
                "naming the one-sided divergence"
            )


def test_map_entries_are_structurally_sound() -> None:
    parity_map = _load_map()
    for key, entry in parity_map["symbols"].items():
        for field in ("python", "ts", "allowlist_reason"):
            assert field in entry, f"{key}: symbol entry missing required field {field!r}"
        if entry["allowlist_reason"] is None:
            # a plain mapping must map at least one language, else it is really an exclusion
            assert entry["python"] is not None or entry["ts"] is not None, (
                f"{key}: mapped to neither Python nor TS and not allowlisted — belongs "
                "in go_exclusions with a reason"
            )


# --------------------------------------------------------------------------- #
# (v) NON-VACUITY — every gap is RESOLVED or DOCUMENTED (no silent nulls)
# --------------------------------------------------------------------------- #
def test_every_gap_is_resolved_or_documented() -> None:
    """A one-sided null with no allowlist_reason is an UNDOCUMENTED gap — forbidden.

    Without this, the PRESENCE check silently accepts every ``ts: null`` /
    ``python: null`` entry that lacks a reason, because presence only asserts NON-null
    names. That is how a real missing face ships GREEN. This is the assertion that makes
    the gate non-vacuous.

    TS direction (python present, ts null): HARD zero — every real TS face is now in
    package.json exports (money / idempotency / scopes / hashurl / wire / core.window /
    verify-multisig-request / verify-request), including the UnknownKey error class
    that completed the resolver error taxonomy in all three languages.

    Python direction (ts present, python null): HARD zero (BASELINE_PY_ONLY_GAP = 0) —
    the original 19 gaps were each resolved (Python face exported) or documented
    (per-entry allowlist_reason), so a NEW undocumented one cannot slip in green.
    """
    symbols = _load_map()["symbols"]
    ts_gaps, py_gaps = undocumented_gaps(symbols)

    assert not ts_gaps, (
        "undocumented Python-present / TS-null gaps — the presence check SKIPS these, so "
        "each is a silently-accepted TS gap. Resolve the TS face (add its module to "
        "package.json exports and map the name) or add an allowlist_reason:\n  "
        + "\n  ".join(ts_gaps)
    )
    assert len(py_gaps) <= BASELINE_PY_ONLY_GAP, (
        f"TS-present / Python-null gaps grew to {len(py_gaps)} > baseline "
        f"{BASELINE_PY_ONLY_GAP}. This ratchet is SHRINK-ONLY: resolve the Python face or "
        "document the divergence — never raise the baseline to make the gate green.\n  "
        + "\n  ".join(py_gaps)
    )


# --------------------------------------------------------------------------- #
# (iii)+(v) GUARD-THE-GUARD — prove the enumerator + gate actually BITE
# --------------------------------------------------------------------------- #
def test_non_vacuity_check_bites_on_an_undocumented_null_pure() -> None:
    """An undocumented one-sided null MUST be caught in BOTH directions (guard-the-guard).

    Pure in-test simulation. If ``undocumented_gaps`` regresses to ignoring bare nulls,
    a future missing face ships GREEN — the exact blind spot (i)(v) exist to kill.
    """
    synthetic = {
        "helpers.MappedBoth": {"python": "p", "ts": "t", "allowlist_reason": None},
        "helpers.TsGap": {"python": "only_py", "ts": None, "allowlist_reason": None},
        "helpers.PyGap": {"python": None, "ts": "onlyTs", "allowlist_reason": None},
        "helpers.Documented": {"python": "px", "ts": None, "allowlist_reason": "tracked follow-up"},
    }
    ts_gaps, py_gaps = undocumented_gaps(synthetic)
    assert ts_gaps == ["helpers.TsGap"], ts_gaps
    assert py_gaps == ["helpers.PyGap"], py_gaps


def test_ts_scanner_extracts_an_inline_export_pure() -> None:
    """The TS scanner MUST see inline exports, not just barrel re-exports.

    Pure in-test simulation — does not touch real source. If this regresses to
    barrel-only, an inline face like createSigningTransport becomes invisible and a future
    missing inline export ships GREEN.
    """
    synthetic = (
        "// a plain module, not a barrel\n"
        "import { foo } from './x.ts';\n"
        "export async function createSigningTransport<R>(signer: S): R {\n"
        "  return signer as R;\n"
        "}\n"
        "export const OFFER_SIGNATURE_ALGORITHM = 'EdDSA';\n"
        "export interface SigningTransportOptions {}\n"
    )
    found = _scan_ts_module_text(synthetic)
    assert "createSigningTransport" in found, "inline `export function` not detected"
    assert "OFFER_SIGNATURE_ALGORITHM" in found, "inline `export const` not detected"
    assert "SigningTransportOptions" in found, "inline `export interface` not detected"


def test_ts_enumerator_finds_the_inline_signing_transport_face() -> None:
    """The LIVE TS surface must expose the inline createSigningTransport (guard-the-guard).

    createSigningTransport is `export function` inline in core/signing-transport.ts — the
    SigningTransport family whose past TS absence motivated this gate. If the enumerator
    cannot see it, the gate is blind exactly where it matters.
    """
    assert "createSigningTransport" in enumerate_ts()


def test_gate_bites_when_a_mapped_face_goes_missing() -> None:
    """Removing a mapped face from a language surface MUST turn the gate RED.

    This is the "would have caught TS shipping without CachedOfferKeyResolver /
    SigningTransport" proof: both are mapped, so dropping them from the TS surface must
    produce presence failures.
    """
    parity_map = _load_map()
    py = enumerate_python()
    ts = enumerate_ts()

    # sanity: with the true surfaces there are no presence failures
    assert not presence_failures(parity_map["symbols"], py, ts)

    crippled_ts = ts - {"CachedOfferKeyResolver", "createSigningTransport"}
    failures = presence_failures(parity_map["symbols"], py, crippled_ts)
    assert any("CachedOfferKeyResolver" in f for f in failures), failures
    assert any("createSigningTransport" in f for f in failures), failures


def test_completeness_bites_on_an_unmapped_go_symbol() -> None:
    """A live Go public symbol absent from BOTH map halves MUST turn the gate RED."""
    parity_map = _load_map()
    injected = {"helpers.FakeUnmappedSymbol": "FakeUnmappedSymbol"}
    failures = completeness_failures(injected, parity_map)
    assert any("FakeUnmappedSymbol" in f for f in failures), failures
