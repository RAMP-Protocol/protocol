// A camelCase entry is refused, not silently accepted with its fields dropped.
//
// This one rule has no shared vector and cannot get one from the Go oracle: protojson
// ACCEPTS both spellings, so Go has no refusal to record. The refusal is a property of
// the two JSON ports, whose generated schemas STRIP what they do not recognise — an
// entry spelled `contentId` would otherwise parse cleanly into a message with every
// multiword field missing, and the pre-check would answer `ok: true` for a feed the
// Exchange will read as empty. Stock `protojson.Marshal` emits exactly that spelling,
// so it is the ordinary output of the obvious way to generate a feed.
//
// The null half of the same policy IS corpus-pinned (licenseterm-vectors.json carries
// the wire_form entries), so only this half needs saying by hand.
//
// Mirrors sdk/python/tests/test_licenseterm_wire_naming.py.
import { describe, expect, it } from "vitest";

import { JSON_NAME_ALIAS_ERROR } from "../../../gen/ts/wire/base.ts";
import { validateResourceEntry } from "../src/licenseterm.ts";

const SNAKE = {
	content_id: "a-42",
	domain: "publisher.example",
	path: "/premium/article-42.html",
} as const;

describe("the entry pre-check refuses a lowerCamelCase spelling", () => {
	it("refuses the alias and names the rule", () => {
		const verdict = validateResourceEntry({
			contentId: "a-42",
			domain: "publisher.example",
			path: "/premium/article-42.html",
		});

		expect(verdict.ok).toBe(false);
		expect(verdict.violations.map((v) => v.rule)).toContain(`field.${JSON_NAME_ALIAS_ERROR}`);
		// Reported at the message that carried the key, which for a root field is "".
		const violation = verdict.violations.find(
			(v) => v.rule === `field.${JSON_NAME_ALIAS_ERROR}`,
		);
		expect(violation?.path).toBe("");
		expect(violation?.token).toBe("");
		expect(violation?.message).toContain("contentId");
	});

	it("refuses one nested inside a term, not only at the root", () => {
		const verdict = validateResourceEntry({
			...SNAKE,
			terms: [
				{
					semantics: "TERM_SEMANTICS_ENUMERATED",
					pricing: { model: "PRICING_MODEL_FREE", rate: "0" },
					partLabel: "chapter one",
				},
			],
		});

		expect(verdict.ok).toBe(false);
		expect(verdict.violations.map((v) => v.rule)).toContain(`field.${JSON_NAME_ALIAS_ERROR}`);
	});

	it("accepts the snake_case spelling of the same entry", () => {
		expect(validateResourceEntry({ ...SNAKE }).ok).toBe(true);
	});

	// An unknown key is NOT an alias of a declared field, so it stays forward-compatible:
	// a field from a newer protocol version is dropped, never refused. Without this the
	// rule above would read as "reject anything unrecognised", which is a different and
	// much worse policy.
	it("still ignores a key that is not an alias of a declared field", () => {
		expect(validateResourceEntry({ ...SNAKE, from_a_later_version: 1 }).ok).toBe(true);
	});
});
