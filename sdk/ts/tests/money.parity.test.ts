// Money parity (TypeScript side) — TDD red for djeue.
//
// sdk/ts `canonicalizeMoney` MUST reproduce the sdk/go oracle byte-for-byte.
// The shared vectors at sdk/go/helpers/testdata/money-vectors.json carry
// {input, canonical, valid} derived from Go CanonicalizeMoney (Parse+Format).
//
// The load-bearing cases (R1/R4): Go round-trips shopspring and drops leading
// zeros (007→7, 00.5→0.5, 0010.20→10.2, 000→0) AND never emits exponent
// notation for a high-precision small fraction (0.0000001 stays plain). A naive
// TS string surface that only trims TRAILING zeros diverges — the vector catches
// it. Invalid inputs (empty, negative, leading '+', '1e3', '.5') MUST throw.
//
// RED now purely because sdk/ts/src/money.ts does not exist yet (the import
// below cannot resolve). The implement step adds that module.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/money.ts does not exist yet (TDD red — missing face).
import { canonicalizeMoney } from "../src/money.ts";
import vectorsFile from "../../go/helpers/testdata/money-vectors.json";

type MoneyVector = {
	name: string;
	input: string;
	canonical: string;
	valid: boolean;
};
type MoneyVectorsFile = { vectors: MoneyVector[] };

const vectors = (vectorsFile as MoneyVectorsFile).vectors;

describe("sdk/ts canonicalizeMoney matches the sdk/go oracle vectors", () => {
	it("money vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		if (v.valid) {
			it(`canonicalizeMoney(${JSON.stringify(v.input)}) === ${JSON.stringify(v.canonical)}`, () => {
				expect(canonicalizeMoney(v.input)).toBe(v.canonical);
			});
		} else {
			it(`canonicalizeMoney(${JSON.stringify(v.input)}) rejects (invalid wire money)`, () => {
				expect(() => canonicalizeMoney(v.input)).toThrow();
			});
		}
	}
});
