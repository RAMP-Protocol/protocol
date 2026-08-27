// License-term parity (TypeScript side) (parity guard).
//
// sdk/ts `canonicalRestrictionToken` / `knownRestrictionToken` /
// `normalizeLicenseTerm` / `validateLicenseTerm` / `validateResourceEntry` MUST
// reproduce the sdk/go oracle. The shared vectors at
// sdk/go/helpers/testdata/licenseterm-vectors.json carry five lists:
//   - fold:      {name, kind, token, canonical}
//   - normalize: {name, term, normalized}          (proto-JSON, snake_case)
//   - known:     {name, kind, token, known}
//   - validate:  {name, term, violation|null, warnings[]}
//   - entry:     {name, entry, ok, structural, term_rules[], warnings[]}
// Every finding is {rule, path, token, message}; the message is the exact wire
// string, so the comparison is byte-for-byte, not shape-for-shape.
import { describe, expect, it } from "vitest";
import vectorsFile from "../../go/helpers/testdata/licenseterm-vectors.json";
import {
	RULE_PRICING_UNIT_REGISTERED,
	RULE_QUOTA_METRIC_REGISTERED,
	canonicalRestrictionToken,
	knownRestrictionToken,
	normalizeLicenseTerm,
	validateLicenseTerm,
	validateResourceEntry,
} from "../src/licenseterm.ts";

type Finding = { rule: string; path: string; token: string; message: string };
type Obj = Record<string, unknown>;
type Vectors = {
	fold: { name: string; kind: string; token: string; canonical: string }[];
	normalize: { name: string; term: Obj; normalized: Obj }[];
	known: { name: string; kind: string; token: string; known: boolean }[];
	validate: { name: string; term: Obj; violation: Finding | null; warnings: Finding[] }[];
	entry: { name: string; entry: Obj; ok: boolean; structural: boolean; term_rules: string[]; warnings: Finding[] }[];
};

const vectors = vectorsFile as Vectors;
const TERM_RULES = new Set([RULE_PRICING_UNIT_REGISTERED, RULE_QUOTA_METRIC_REGISTERED]);

describe("sdk/ts license-term faces match the sdk/go oracle vectors", () => {
	it("every list is non-empty", () => {
		for (const list of [vectors.fold, vectors.normalize, vectors.known, vectors.validate, vectors.entry]) {
			expect(list.length).toBeGreaterThan(0);
		}
	});

	for (const v of vectors.fold) {
		it(`fold ${v.name}: canonicalRestrictionToken(${v.kind}, ${JSON.stringify(v.token)})`, () => {
			expect(canonicalRestrictionToken(v.kind, v.token)).toBe(v.canonical);
		});
	}

	for (const v of vectors.normalize) {
		it(`normalize ${v.name}`, () => {
			const input = structuredClone(v.term);
			expect(normalizeLicenseTerm(v.term)).toEqual(v.normalized);
			expect(v.term).toEqual(input); // the input is never modified
			expect(normalizeLicenseTerm(normalizeLicenseTerm(v.term))).toEqual(v.normalized); // idempotent
		});
	}

	for (const v of vectors.known) {
		it(`known ${v.name}: knownRestrictionToken(${v.kind}, ${JSON.stringify(v.token)})`, () => {
			expect(knownRestrictionToken(v.kind, v.token)).toBe(v.known);
		});
	}

	for (const v of vectors.validate) {
		it(`validate ${v.name}`, () => {
			const verdict = validateLicenseTerm(v.term);
			expect(verdict.violation).toEqual(v.violation);
			expect(verdict.warnings).toEqual(v.warnings);
		});
	}

	for (const v of vectors.entry) {
		it(`entry ${v.name}`, () => {
			const input = structuredClone(v.entry);
			const verdict = validateResourceEntry(v.entry);
			expect(v.entry).toEqual(input);
			expect(verdict.ok).toBe(v.ok);
			const termRules = verdict.violations.filter((x) => TERM_RULES.has(x.rule)).map((x) => x.rule);
			const structural = verdict.violations.some((x) => !TERM_RULES.has(x.rule));
			expect(structural).toBe(v.structural);
			expect(termRules).toEqual(v.term_rules);
			expect(verdict.warnings).toEqual(v.warnings);
		});
	}
});
