// Wire→canonical parity (TypeScript side) — the shared corpus is the un-fakeable
// oracle: sdk/go emits sdk/go/helpers/testdata/wire-canonical-vectors.json (each
// vector {name, wire_json, canonical_json}, all Offers), and Go + Python + now TS
// all replay it. For every vector, JCS(fromWireOffer(wire_json)) MUST byte-equal
// JCS(canonical_json). A divergence is a real bug in the TS inversion (the wire→
// canonical presence rules), never a reason to weaken the assertion or edit the
// corpus. This is the TS half that closes the corpus-replay-completeness ratchet
// (sdk/python tests/test_corpus_replay_completeness.py); the corpus is read-only.

import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";

import vectorsFile from "../../go/helpers/testdata/wire-canonical-vectors.json";
import { fromWireOffer } from "../core/wire-canon.ts";

type WireCanonVector = {
	name: string;
	wire_json: Record<string, unknown>;
	canonical_json: Record<string, unknown>;
};
type WireCanonVectorsFile = { canonicalization: string; vectors: WireCanonVector[] };

const vectors = (vectorsFile as unknown as WireCanonVectorsFile).vectors;

describe("fromWireOffer matches the sdk/go wire-canonical-vectors oracle", () => {
	it("wire-canonical vector set is non-empty (guard against vacuous parity)", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`${v.name}: jcs(fromWireOffer(wire)) === jcs(canonical)`, () => {
			const got = canonicalize(fromWireOffer(v.wire_json));
			const want = canonicalize(v.canonical_json);
			// Both sides are objects → JCS is always defined; guard so an undefined
			// pair can never masquerade as a passing (vacuous) equality.
			expect(typeof got).toBe("string");
			expect(typeof want).toBe("string");
			expect(got).toBe(want);
		});
	}
});
