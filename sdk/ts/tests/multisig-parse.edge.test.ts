// sdk/ts multi-member Signature-Input parser parse-edge units. The canonical Go
// golden vectors (multisig-chain-vectors.json) are well-
// behaved (no comma/paren inside a quoted keyid, no backslash escapes, canonical
// whitespace), so passing every vector does NOT gate the TS parser's correctness
// on an ADVERSARIAL Signature-Input. Go itself delegates the dictionary parse to
// dunglas/httpsfv and only hand-rolls the verbatim-inner split (rawInnerByLabel /
// splitTopLevelMembers). The TS port hand-rolls both, so these parse-edge units
// are the correct level (parser primitives → unit tests) — they pin the exact
// quoted-string / backslash-escape / top-level-comma behavior the RFC 8941
// dictionary grammar requires.
//
// Faces under test (do NOT exist yet — RED):
//   core/multisig-parse.ts::splitTopLevelMembers — split one SFV dictionary
//     header value on TOP-LEVEL commas, honoring quoted strings + backslash
//     escapes (mirrors Go splitTopLevelMembers).
//   core/multisig-parse.ts::rawInnerByLabel — the VERBATIM member value after
//     "label=" for each label (mirrors Go rawInnerByLabel), so each hop's base
//     terminates with the signer's exact @signature-params bytes.
//   core/multisig-parse.ts::parseMultisigSignatureInput — full multi-label parse;
//     returns undefined (clean reject) on a malformed header, never a mis-slice.
//
// RED until core/multisig-parse.ts exists.

import { describe, it, expect } from "vitest";
// RED: core/multisig-parse.ts does not exist yet (TDD red step).
import {
  splitTopLevelMembers,
  rawInnerByLabel,
  parseMultisigSignatureInput,
} from "../core/multisig-parse.ts";

describe("sdk/ts multi-member Signature-Input parse edges", () => {
  it("splits on top-level commas into one member per label", () => {
    const raw = 'sig1=("@method" "@target-uri"), sig2=("@method" "signature";key="sig1")';
    expect(splitTopLevelMembers(raw)).toEqual([
      'sig1=("@method" "@target-uri")',
      ' sig2=("@method" "signature";key="sig1")',
    ]);
  });

  it("does NOT split on a comma inside a quoted string (quoted keyid)", () => {
    // A keyid may legally contain a comma inside its quotes; a naive comma split
    // would tear the member in two and mis-slice both labels.
    const raw = 'sig1=("@method");keyid="agent,demo.v1", sig2=("@method");keyid="broker.relay.a"';
    const parts = splitTopLevelMembers(raw);
    expect(parts).toHaveLength(2);
    expect(parts[0]).toContain('keyid="agent,demo.v1"');
    expect(parts[1]).toContain('keyid="broker.relay.a"');
  });

  it("honors backslash escapes inside a quoted string", () => {
    // The escaped quote (\") must NOT close the string, so the following comma
    // stays inside quotes and does not split the member.
    const raw = 'sig1=("@method");keyid="a\\",b", sig2=("@method");keyid="c"';
    const parts = splitTopLevelMembers(raw);
    expect(parts).toHaveLength(2);
    expect(parts[0]).toContain('keyid="a\\",b"');
    expect(parts[1]).toContain('keyid="c"');
  });

  it("preserves the VERBATIM inner value per label", () => {
    // rawInnerByLabel returns everything after `label=` byte-for-byte — the
    // signer's exact @signature-params tail the verify base must terminate with.
    const raw =
      'sig1=("@method" "@target-uri");keyid="agent.v1";created=1700000000, sig2=("@method" "signature";key="sig1");keyid="broker.relay.a"';
    const inner = rawInnerByLabel([raw]);
    expect(inner["sig1"]).toBe(
      '("@method" "@target-uri");keyid="agent.v1";created=1700000000',
    );
    expect(inner["sig2"]).toBe(
      '("@method" "signature";key="sig1");keyid="broker.relay.a"',
    );
  });

  it("cleanly rejects a malformed header (missing close paren) rather than mis-slicing", () => {
    // An unterminated inner list must be REJECTED (undefined), not partially
    // sliced into a bogus covered set.
    const malformed = 'sig1=("@method" "@target-uri";keyid="agent.v1"';
    expect(parseMultisigSignatureInput([malformed])).toBeUndefined();
  });
});
