// Wire-constants parity (TypeScript side): the SDK exposes every constant in
// the shared vector file with the exact value the Go oracle carries.
//
// The vectors at sdk/go/helpers/testdata/wire-constants-vectors.json carry
// {name, value}, referenced from the real Go exported constants and never
// hand-typed. The Python sibling is sdk/python/tests/test_wire_parity.py.
//
// SCOPE IS DERIVED, NOT LISTED. The Go identifier and the TS identifier do not
// always match: the wire constants keep their Go spelling, while the two
// signature algorithms are OFFER_SIGNATURE_ALGORITHM and
// ACCEPTANCE_SIGNATURE_ALGORITHM and live in offer-sign.ts / acceptance.ts.
// That translation is already maintained in sdk/parity/symbol-map.json for the
// API-surface gate, so this suite reads it from there.
//
// An earlier version kept a private Go-name -> export map instead. That made
// the check opt-in: a vector with no entry asserted "expected undefined to be
// defined" rather than reporting an unported constant, and two vectors did
// exactly that. Reading the mapping from the shared file makes it opt-out — a
// new vector must be mapped and ported, and cannot pass by being unlisted.
import { describe, it, expect } from "vitest";
import * as wire from "../src/wire.ts";
import * as offerSign from "../src/offer-sign.ts";
import * as acceptance from "../src/acceptance.ts";
import vectorsFile from "../../go/helpers/testdata/wire-constants-vectors.json";
import symbolMap from "../../parity/symbol-map.json";

type WireVector = { name: string; value: string };
type WireVectorsFile = { vectors: WireVector[] };
type SymbolMapFile = { symbols: Record<string, { ts?: string | null }> };

const vectors = (vectorsFile as WireVectorsFile).vectors;

// The modules a vectored constant may be exported from. A constant that lands
// in a module absent here fails the lookup below rather than passing silently,
// so this list is a scope declaration, not an allow-list.
const surface: Record<string, unknown> = {
	...(wire as Record<string, unknown>),
	...(offerSign as Record<string, unknown>),
	...(acceptance as Record<string, unknown>),
};

// Bare Go identifier -> the TS name symbol-map.json pins it to. Map keys are
// package-qualified (helpers.ProtocolVersion) while a vector names the bare
// identifier, and one identifier can appear under two packages — the Go layer
// defines RequestIDHeader in both helpers and core. Agreeing duplicates
// collapse to one entry; a disagreement is left to fail loudly.
const tsName = new Map<string, string>();
for (const [qualified, entry] of Object.entries(
	(symbolMap as SymbolMapFile).symbols,
)) {
	const bare = qualified.split(".").pop() as string;
	const name = entry.ts;
	if (name === undefined || name === null) continue;
	const seen = tsName.get(bare);
	if (seen !== undefined && seen !== name) {
		throw new Error(
			`symbol-map.json maps ${bare} to two different TS names: ${seen} and ${name}`,
		);
	}
	tsName.set(bare, name);
}

describe("sdk/ts wire constants match the sdk/go oracle vectors", () => {
	it("wire-constants vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`${v.name} is mapped to a TS symbol`, () => {
			expect(
				tsName.has(v.name),
				`${v.name} has a wire-constant vector but no TS symbol in sdk/parity/symbol-map.json — port it and map it, or drop the vector`,
			).toBe(true);
		});

		it(`${v.name} === ${JSON.stringify(v.value)}`, () => {
			const name = tsName.get(v.name) as string;
			expect(
				name in surface,
				`${v.name} maps to ${name}, which none of the modules this suite imports export`,
			).toBe(true);
			expect(surface[name]).toBe(v.value);
		});
	}
});
