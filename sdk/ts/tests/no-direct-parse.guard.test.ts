import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the wire-policy seam.
//
// `sdk/ts/client/transport.ts` states the rule: every parse of a generated schema in
// this SDK goes through the seam, and a bare `safeParse` would skip the policy. The
// seam is `gen/ts/wire/base.ts` — `parseWire`, or `underWirePolicy` when a caller
// needs the issues rather than a yes/no — and it holds the two things a Zod schema
// cannot express: a `null` is how proto-JSON spells "this field has no value", for
// ANY field; and a lowerCamelCase `json_name` answer is refused, because the schemas
// STRIP what they do not recognise and would otherwise accept a message with every
// multiword field silently dropped.
//
// The rule was written down and nothing enforced it, which is how the publisher's
// entry pre-check came to parse around the seam and answer `ok: true` for a camelCase
// entry that loses `content_id`. That is the failure this guard exists to make loud.
//
// The two allowed sites below are pre-existing and each carries its own reason. An
// allowlist with no reason is a hold-back list; this one has to say why every time.

const dirPath = (name: string): string =>
	fileURLToPath(new URL(`../${name}`, import.meta.url));

const SCANNED_DIRS = ["src", "client", "core", "resolvers", "hono"];

// A `.safeParse(` whose argument does not open with `underWirePolicy(`. The seam's own
// `parseWire` is inside gen/ts and is not scanned, so it needs no exemption here.
const BARE_SAFE_PARSE = /\.safeParse\(\s*(?!underWirePolicy\()/;

// Sites that may parse without the seam, each with the reason it does not apply.
// Keyed by path relative to sdk/ts.
const ALLOWED: Record<string, string> = {
	"src/verify.ts":
		"ParamsSchema is a LOCAL z.object for RFC 9421 signature parameters, not a generated " +
		"wire schema — there is no proto-JSON message here for the policy to apply to.",
	"src/errordetail.ts":
		"the Connect `debug` projection is lowerCamelCase and no server option changes it, so " +
		"this reader converts the names itself (protoNames) before parsing — the seam's naming " +
		"REFUSAL is the one rule that must not fire on this path. The null half still would; " +
		"closing that without breaking the rename is its own change.",
};

// tsFilesUnder walks `dir` recursively, so a nested module cannot become a blind spot.
function tsFilesUnder(dir: string): string[] {
	const out: string[] = [];
	for (const e of readdirSync(dirPath(dir), { withFileTypes: true })) {
		if (e.isDirectory()) {
			out.push(...tsFilesUnder(`${dir}/${e.name}`));
		} else if (e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts")) {
			out.push(`${dir}/${e.name}`);
		}
	}
	return out;
}

// parsesAroundTheSeam is the pure predicate, extracted so the meta-tests below can
// exercise it against synthetic source rather than against the tree.
function parsesAroundTheSeam(source: string): boolean {
	return BARE_SAFE_PARSE.test(source);
}

describe("wire-policy seam structural guard", () => {
	it("no module parses a generated schema around the seam", () => {
		const offenders: string[] = [];
		for (const dir of SCANNED_DIRS) {
			for (const rel of tsFilesUnder(dir)) {
				if (rel in ALLOWED) continue;
				if (parsesAroundTheSeam(readFileSync(dirPath(rel), "utf8"))) offenders.push(rel);
			}
		}
		expect(offenders).toEqual([]);
	});

	// Guard the guard. An allowlist that outlives its offender stops describing the
	// tree, and one whose entries carry no reason is just a way to make the gate green.
	it("every allowed site still parses, and says why it may", () => {
		for (const [rel, reason] of Object.entries(ALLOWED)) {
			expect(
				parsesAroundTheSeam(readFileSync(dirPath(rel), "utf8")),
				`${rel} no longer parses around the seam — drop it from ALLOWED`,
			).toBe(true);
			expect(reason.length, `${rel} carries no reason`).toBeGreaterThan(40);
		}
	});

	it("the scan reaches a real file set", () => {
		const scanned = SCANNED_DIRS.flatMap(tsFilesUnder);
		expect(scanned.length).toBeGreaterThan(20);
		expect(scanned).toContain("src/licenseterm.ts");
	});

	// --- meta-tests: exercise the detector against synthetic source ------------
	it("[meta positive] catches a bare parse of a generated schema", () => {
		expect(parsesAroundTheSeam("const p = ResourceEntrySchema.safeParse(entry);")).toBe(true);
	});

	it("[meta positive] catches one split across lines", () => {
		expect(parsesAroundTheSeam("const p = OfferSchema.safeParse(\n\traw,\n);")).toBe(true);
	});

	it("[meta negative] allows a parse routed through the seam", () => {
		expect(
			parsesAroundTheSeam('const p = S.safeParse(underWirePolicy(S, entry, ""));'),
		).toBe(false);
	});

	it("[meta negative] does not fire on a schema-shaped parameter type", () => {
		expect(
			parsesAroundTheSeam("schema: { safeParse: (v: unknown) => { success: boolean } },"),
		).toBe(false);
	});
});
