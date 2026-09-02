// An ill-typed value gets a VERDICT, not an exception, and is not mistaken for a
// well-typed one.
//
// Neither case here has a shared vector, and neither can get one from the Go oracle:
// the Go face takes a *rampv1.ResourceEntry, so "a string where an entry should be" is
// not a value it can construct, and Restriction.permitted is []string, so "a number
// where a token should be" is not either — let alone marshal into a corpus. The behaviour is a
// property of the two JSON ports, whose faces take whatever a caller parsed.
//
// It is reachable the ordinary way. The pre-check exists for feeds, a JSONL line is
// parsed before it is checked, and a malformed line parses to a string, a number,
// a list or null just as easily as to an object. Answering that with a thrown
// TypeError rather than a verdict makes a publisher's loop over a feed die on the
// first bad row instead of reporting it beside the others.
//
// The rule ID is deliberately NOT asserted equal to Python's. Field-level wire
// violations carry each engine's own vocabulary — Zod's issue codes here, Pydantic's
// error types there — which is the recorded reason the shared corpus compares them
// as a boolean. What the two ports owe each other is the SHAPE of the answer: a
// verdict, refused, with at least one violation.
//
// Mirrors sdk/python/tests/test_licenseterm_non_object.py.
import { describe, expect, it } from "vitest";

import {
	RULE_RESTRICTION_CANONICAL_DISJOINT,
	validateLicenseTerm,
	validateResourceEntry,
} from "../src/licenseterm.ts";

describe("validateResourceEntry on a value that is not an object", () => {
	for (const [label, value] of [
		["null", null],
		["a string", "not-an-entry"],
		["a number", 5],
		["an array", []],
	] as const) {
		it(`refuses ${label} with a verdict rather than throwing`, () => {
			// biome-ignore lint/suspicious/noExplicitAny: the point is the untyped caller
			const verdict = validateResourceEntry(value as any);
			expect(verdict.ok).toBe(false);
			expect(verdict.violations.length).toBeGreaterThan(0);
			expect(verdict.warnings).toEqual([]);
		});
	}

	it("still reports a real entry as valid, so the guard has not swallowed the walk", () => {
		const verdict = validateResourceEntry({ domain: "e.co", path: "/a" });
		expect(verdict.ok).toBe(true);
	});
});

// The same division one level down, on the restriction token lists.
//
// Every other check in the file skips an empty token, on the reasoning that an empty
// string is the wire tier's business. The canonical-disjointness check cannot skip it —
// two empty strings really are one token named on both sides, which is what the Go
// oracle answers — so it has to tell an EMPTY token from an ILL-TYPED one. Coercing
// the latter to "" would report a collision on the empty token and name the wrong
// fault, while the real fault, "this element is not a string", is what the wire tier
// already reports beside it.
describe("canonical disjointness on ill-typed restriction tokens", () => {
	const term = (permitted: unknown[], prohibited: unknown[]) => ({
		restrictions: [{ kind: "RESTRICTION_KIND_FUNCTION", permitted, prohibited }],
	});

	it("does not read two ill-typed elements as a collision on the empty token", () => {
		// biome-ignore lint/suspicious/noExplicitAny: the point is the untyped caller
		const verdict = validateLicenseTerm(term(["ai-train", 5], ["search", null]) as any);
		expect(verdict.violation).toBeNull();
	});

	it("still refuses a token genuinely named on both sides", () => {
		// biome-ignore lint/suspicious/noExplicitAny: the point is the untyped caller
		const verdict = validateLicenseTerm(term(["scrape", 5], ["crawl", null]) as any);
		expect(verdict.violation?.rule).toBe(RULE_RESTRICTION_CANONICAL_DISJOINT);
		expect(verdict.violation?.token).toBe("crawl");
	});

	it("keeps the empty token colliding, which is what the Go oracle answers", () => {
		// biome-ignore lint/suspicious/noExplicitAny: the point is the untyped caller
		const verdict = validateLicenseTerm(term([""], [""]) as any);
		expect(verdict.violation?.rule).toBe(RULE_RESTRICTION_CANONICAL_DISJOINT);
		expect(verdict.violation?.token).toBe("");
	});
});
