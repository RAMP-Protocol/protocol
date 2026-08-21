// What a consumer of this package can actually reach, and whether it is enough.
//
// This package is a deliverable in its own right: CLAUDE.md names it as how a TypeScript
// consumer pulls the wire types, and the README shows the import. `exports` carries no
// wildcard for `./wire/*`, so Node treats the map as an exhaustive allowlist — a subpath
// that is not listed fails with ERR_PACKAGE_PATH_NOT_EXPORTED and has no deep-path
// workaround.
//
// The seam was unreachable for exactly that reason while the changelog said a consumer
// could read a conformant answer. They could not: the schemas alone reject `"ext": null`,
// which is what a real Exchange sends for an unset message field.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { parseWire } from "../wire/base.ts";
import { snakeFromJsonName } from "../wire/names.ts";
import { ResourceResponseSchema } from "../wire/schemas.ts";

const manifest = JSON.parse(
	readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
) as { exports: Record<string, string> };

// Captured from connectserver.EmitUnpopulatedJSONCodec() — the codec a RAMP deployment
// registers on every JSON-serving listener.
const CODEC_BODY =
	'{"ver":"", "exchange":"exchange.test", "offers":[], "offer_groups":[], "ext":null, "ext_critical":[]}';

describe("the package exports what reading the wire requires", () => {
	it("every module the README tells a consumer to import is declared", () => {
		for (const subpath of ["./wire/schemas", "./wire/base", "./wire/names"]) {
			expect(manifest.exports[subpath], `${subpath} is not exported`).toBeDefined();
		}
	});

	it("every declared target exists", () => {
		for (const [subpath, target] of Object.entries(manifest.exports)) {
			if (target.includes("*")) continue; // the vocab wildcard
			const path = fileURLToPath(new URL(`../${target.slice(2)}`, import.meta.url));
			expect(() => readFileSync(path), `${subpath} -> ${target}`).not.toThrow();
		}
	});

	it("a consumer can parse what a real server sends", () => {
		const parsed = parseWire<{ exchange: string }>(
			ResourceResponseSchema,
			JSON.parse(CODEC_BODY),
		);
		expect(parsed.success).toBe(true);
		expect(parsed.success && parsed.data.exchange).toBe("exchange.test");
	});

	it("and the schema alone still does not — which is why the seam is exported", () => {
		expect(ResourceResponseSchema.safeParse(JSON.parse(CODEC_BODY)).success).toBe(false);
	});

	it("the shared name rule is reachable too", () => {
		expect(snakeFromJsonName("transactionId")).toBe("transaction_id");
	});
});
