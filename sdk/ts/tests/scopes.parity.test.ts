// Scopes parity (TypeScript side) — TDD red for djeue.
//
// sdk/ts `normalizeScopes`/`scopesSubset` MUST reproduce the sdk/go oracle
// byte-for-byte. The shared vectors at
// sdk/go/helpers/testdata/scopes-vectors.json are the cross-language guard:
//   - normalize: {input:string[], normalized:string[]|null}
//     (Go returns nil for empty/all-empty input → JSON null, R5)
//   - subset:    {sub:string[], super:string[], expected:boolean}
//
// RED now purely because sdk/ts/src/scopes.ts does not exist yet (the import
// below cannot resolve). The implement step adds that module, at which point
// this goes green with NO change to the assertions.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/scopes.ts does not exist yet (TDD red — missing face).
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
			// R5: Go emits `null` for empty/all-empty; the TS face returns []. The
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
