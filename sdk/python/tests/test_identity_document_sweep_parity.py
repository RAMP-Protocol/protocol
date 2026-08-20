"""Identity-document DIFFERENTIAL SWEEP replay (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/identity-document-sweep.parity.test.ts.

Replays sdk/go/helpers/testdata/identity-document-sweep-vectors.json, which is
thousands of machine-generated base/reference pairs recorded from the real Go
face. Its emitter header explains why it exists; the short version is that a
hand-written corpus holds only the inputs someone thought of, and three review
rounds of those passed in all three languages while the ports still answered
differently for an apostrophe in a query, a second hash in a fragment, a dot
segment in the manifest URL, and a second colon in an authority.

This file is what makes the sweep a permanent gate rather than a script someone
has to remember to run after the next toolchain upgrade moves a parser. The Go
oracle still reads its scheme and authority through ``net/url``; this port and
the TypeScript one read every component of the answer as substrings.

ONE test rather than one per case, unlike the intent corpus beside it: the cases
are positionally named because there is nothing to name, so a per-case test id
would carry no information, and 2789 of them would be noise in every run. The
failure message lists the first mismatches with both inputs, which is what a
person actually needs.
"""

from __future__ import annotations

from conftest import GO_TESTDATA, load_json
from ramp_sdk.hosts import resolve_identity_document

_VECTORS = load_json(GO_TESTDATA / "identity-document-sweep-vectors.json")["identity_document_sweep"]

# Every refusal this resolver documents carries this prefix.
_REFUSAL_PREFIX = "identity document: "


def _answer(manifest_url: str, ref: str) -> str | None:
    """Resolve one case, or report WHY it was refused rather than only THAT it was.

    ``ValueError`` alone is too weak a pin: the resolver parses a port with
    ``int()``, which raises the same class, so a stray one from inside the
    resolver would be counted as a correct refusal. A refusal outside the
    documented family is returned as its own string, which makes it a mismatch
    instead.
    """
    try:
        return resolve_identity_document(manifest_url, ref)
    except ValueError as exc:
        if not str(exc).startswith(_REFUSAL_PREFIX):
            return f"FOREIGN RAISE: {exc}"
        return None


def test_the_sweep_corpus_is_populated() -> None:
    # A corpus that lost its cases would pass the loop below in silence.
    assert len(_VECTORS) > 1000
    assert any(v["accepted"] for v in _VECTORS)
    assert any(not v["accepted"] for v in _VECTORS)


def test_every_sweep_case_answers_as_the_oracle_does() -> None:
    mismatches: list[str] = []
    for v in _VECTORS:
        got = _answer(v["manifest_url"], v["ref"])
        want = v["resolved"] if v["accepted"] else None
        if got != want:
            mismatches.append(
                f"{v['name']}: base={v['manifest_url']!r} ref={v['ref']!r} "
                f"oracle={want!r} python={got!r}"
            )
    assert not mismatches, "\n".join(
        [f"{len(mismatches)} of {len(_VECTORS)} sweep cases disagree with the Go oracle:"]
        + mismatches[:20]
    )
