"""sdk/python multi-member Signature-Input parser parse-edge units (o3szv R2).

The canonical Go golden vectors (multisig-chain-vectors.json) are well-behaved
(no comma/paren inside a quoted keyid, no backslash escapes, canonical
whitespace), so passing every vector does NOT gate the Python parser's
correctness on an ADVERSARIAL Signature-Input. Go itself delegates the dictionary
parse to dunglas/httpsfv and only hand-rolls the verbatim-inner split
(raw_inner_by_label / split_top_level_members). The Python port hand-rolls both,
so these parse-edge units are the correct level (parser primitives → unit tests)
— they pin the exact quoted-string / backslash-escape / top-level-comma behavior
the RFC 8941 dictionary grammar requires.

Faces under test (do NOT exist yet — RED):
  ramp_sdk.multisig_parse.split_top_level_members — split one SFV dictionary
    header value on TOP-LEVEL commas, honoring quoted strings + backslash escapes
    (mirrors Go splitTopLevelMembers).
  ramp_sdk.multisig_parse.raw_inner_by_label — the VERBATIM member value after
    ``label=`` for each label (mirrors Go rawInnerByLabel), so each hop's base
    terminates with the signer's exact @signature-params bytes.
  ramp_sdk.multisig_parse.parse_multisig_signature_input — full multi-label parse;
    returns None (clean reject) on a malformed header, never a mis-slice.

RED until ramp_sdk/multisig_parse.py exists: the import raises ImportError.
"""

from __future__ import annotations

# RED: ramp_sdk.multisig_parse does not exist yet (TDD red step).
from ramp_sdk.multisig_parse import (  # type: ignore[import-not-found]
    parse_multisig_signature_input,
    raw_inner_by_label,
    split_top_level_members,
)


def test_splits_on_top_level_commas_into_one_member_per_label() -> None:
    raw = 'sig1=("@method" "@target-uri"), sig2=("@method" "signature";key="sig1")'
    assert split_top_level_members(raw) == [
        'sig1=("@method" "@target-uri")',
        ' sig2=("@method" "signature";key="sig1")',
    ]


def test_does_not_split_on_a_comma_inside_a_quoted_string() -> None:
    # A keyid may legally contain a comma inside its quotes; a naive comma split
    # would tear the member in two and mis-slice both labels.
    raw = 'sig1=("@method");keyid="agent,demo.v1", sig2=("@method");keyid="broker.relay.a"'
    parts = split_top_level_members(raw)
    assert len(parts) == 2
    assert 'keyid="agent,demo.v1"' in parts[0]
    assert 'keyid="broker.relay.a"' in parts[1]


def test_honors_backslash_escapes_inside_a_quoted_string() -> None:
    # The escaped quote (\") must NOT close the string, so the following comma
    # stays inside quotes and does not split the member.
    raw = 'sig1=("@method");keyid="a\\",b", sig2=("@method");keyid="c"'
    parts = split_top_level_members(raw)
    assert len(parts) == 2
    assert 'keyid="a\\",b"' in parts[0]
    assert 'keyid="c"' in parts[1]


def test_preserves_the_verbatim_inner_value_per_label() -> None:
    # raw_inner_by_label returns everything after ``label=`` byte-for-byte — the
    # signer's exact @signature-params tail the verify base must terminate with.
    raw = (
        'sig1=("@method" "@target-uri");keyid="agent.v1";created=1700000000, '
        'sig2=("@method" "signature";key="sig1");keyid="broker.relay.a"'
    )
    inner = raw_inner_by_label([raw])
    assert inner["sig1"] == '("@method" "@target-uri");keyid="agent.v1";created=1700000000'
    assert inner["sig2"] == '("@method" "signature";key="sig1");keyid="broker.relay.a"'


def test_cleanly_rejects_a_malformed_header_rather_than_mis_slicing() -> None:
    # An unterminated inner list must be REJECTED (None), not partially sliced into
    # a bogus covered set.
    malformed = 'sig1=("@method" "@target-uri";keyid="agent.v1"'
    assert parse_multisig_signature_input([malformed]) is None
