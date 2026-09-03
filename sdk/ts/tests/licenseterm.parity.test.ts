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
import crossfieldCorpus from "../../../conformance/corpus/crossfield.json";
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
	entry: {
		name: string;
		entry: Obj;
		ok: boolean;
		structural: boolean;
		cross_field_rules: string[];
		term_rules: Finding[];
		warnings: Finding[];
	}[];
};

const vectors = vectorsFile as Vectors;
// The ingest-tier reject ids, read out of the corpus's own per-term list — an
// ingest-tier reject IS an id that list can carry as a violation. Reading them beats
// listing them here, the same trade the cross-field set below already makes: a
// classification written down in four places is one that can disagree with itself.
const TERM_RULES = new Set(
	vectors.validate.flatMap((v) => (v.violation ? [v.violation.rule] : [])),
);

// Guard the guard. A derivation that stopped reading the column would leave an empty
// set and quietly move every term reject into the structural bucket, where the entry
// assertions would still pass. Both long-standing ids are reachable from that list,
// so requiring them pins that it is still being read.
for (const id of [RULE_PRICING_UNIT_REGISTERED, RULE_QUOTA_METRIC_REGISTERED]) {
	if (!TERM_RULES.has(id)) {
		throw new Error(`the per-term list carries no ${id} — the column this classification is derived from has moved`);
	}
}

// The registered cross-field rule ids, read from the generated cross-field corpus —
// corpusgen emits one mutant per message-level CEL rule, so its `rules` are the
// descriptor's own set. Reading them beats listing them here: the corpus records ids
// the descriptor owns, and this side must classify by the same set or a violation
// lands in the wrong column. A superset is harmless — an id no entry can reach never
// appears in a verdict.
const CROSS_FIELD_RULES = new Set(
	(crossfieldCorpus as { rules?: string[] }[]).flatMap((c) => c.rules ?? []),
);

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
			// Three columns, three strengths — the same split the emitter records:
			// whole findings for the SDK-owned ingest tier, ids for the cross-field
			// rules the proto owns, and a bare boolean for the field-level ids that
			// are Zod's here and protovalidate's in the oracle.
			const termRules = verdict.violations.filter((x) => TERM_RULES.has(x.rule));
			const crossField = verdict.violations
				.filter((x) => CROSS_FIELD_RULES.has(x.rule))
				.map((x) => x.rule);
			const structural = verdict.violations.some(
				(x) => !TERM_RULES.has(x.rule) && !CROSS_FIELD_RULES.has(x.rule),
			);
			expect(structural).toBe(v.structural);
			expect(crossField).toEqual(v.cross_field_rules);
			expect(termRules).toEqual(v.term_rules);
			expect(verdict.warnings).toEqual(v.warnings);
		});
	}
});
