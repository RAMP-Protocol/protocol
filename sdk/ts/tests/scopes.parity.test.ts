// Scopes parity (TypeScript side) (parity guard).
//
// sdk/ts `normalizeScopes`/`scopesSubset` MUST reproduce the sdk/go oracle
// byte-for-byte. The shared vectors at
// sdk/go/helpers/testdata/scopes-vectors.json are the cross-language guard:
//   - normalize: {input:string[], normalized:string[]|null}
//     (Go returns nil for empty/all-empty input → JSON null)
//   - subset:    {sub:string[], super:string[], expected:boolean}
//
// These faces now exist; the suite is green and guards cross-language parity.
import { describe, it, expect } from "vitest";
import { normalizeScopes, scopesSubset } from "../src/scopes.ts";
import vectorsFile from "../../go/helpers/testdata/scopes-vectors.json";

type NormalizeVector = {
	name: string;
	input: string[];
	normalized: string[] | null;
};
type SubsetVector = {
	name: string;
	sub: string[] | null;
	super: string[] | null;
	expected: boolean;
};
type ScopesVectorsFile = {
	normalize: NormalizeVector[];
	subset: SubsetVector[];
};

const vectors = vectorsFile as ScopesVectorsFile;

describe("sdk/ts normalizeScopes matches the sdk/go oracle vectors", () => {
	it("normalize vector set is non-empty", () => {
		expect(vectors.normalize.length).toBeGreaterThan(0);
	});

	for (const v of vectors.normalize) {
		it(`normalizeScopes(${v.name}) === ${JSON.stringify(v.normalized)}`, () => {
			const got = normalizeScopes(v.input);
			// Go emits `null` for empty/all-empty; the TS face returns []. The
			// comparator treats null == [] so the empty-input vector matches.
			const want = v.normalized ?? [];
			expect(got).toEqual(want);
		});
	}
});

describe("sdk/ts scopesSubset matches the sdk/go oracle vectors", () => {
	it("subset vector set is non-empty", () => {
		expect(vectors.subset.length).toBeGreaterThan(0);
	});

	for (const v of vectors.subset) {
		it(`scopesSubset(${v.name}) === ${v.expected}`, () => {
			const got = scopesSubset(v.sub ?? [], v.super ?? []);
			expect(got).toBe(v.expected);
		});
	}
});
