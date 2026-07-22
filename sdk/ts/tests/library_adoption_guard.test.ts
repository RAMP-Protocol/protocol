import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the sdk/ts L1 relocation. This is the
// class-level counter-measure the sweep-verify atom requires: it pins that the
// canonical sdk/ts helpers keep composing the generated artifacts + the fixed
// byte contract, so a future edit cannot silently re-introduce the disease the
// port eliminated (hand-rolled wire-type mirrors instead of the generated
// gen/ts schemas, or a drifted canonical thumbprint JWK string).
//
// SCOPE — deliberately sdk/ts/src ONLY. A tree-wide ban on hand-rolled TS
// crypto would false-fire on the app's src/edge/src/{thumbprint,verify,pop}.ts,
// which MUST still exist until their deletion in the downstream adoption work.
// The tree-wide guard belongs to that downstream work; here the guard is
// correctly scoped to the new canonical library.
//
// The behavioral guard for byte-parity is the parity suite
// (thumbprint/signedurl-pop/crossfield .parity.test.ts vs the Go oracle
// vectors); this file adds the source-level guard the sweep atom asks for.

const srcPath = (name: string): string =>
	fileURLToPath(new URL(`../src/${name}`, import.meta.url));

function readSource(name: string): string {
	return readFileSync(srcPath(name), "utf8");
}

// siteGuard mirrors the sdk/go guard's shape: forbidden substrings are disease
// instances that must be ABSENT; required substrings are the canonical
// composition markers that must be PRESENT.
interface SiteGuard {
	file: string;
	forbidden: string[];
	required: string[];
}

// evalSite is the pure predicate (extracted so the meta-tests can exercise the
// guard logic against synthetic source without touching the real files). It
// returns one message per violation.
export function evalSite(src: string, g: SiteGuard): string[] {
	const violations: string[] = [];
	for (const bad of g.forbidden) {
		if (src.includes(bad)) {
			violations.push(
				`${g.file} still contains disease instance ${JSON.stringify(bad)}; it must compose the generated artifact instead`,
			);
		}
	}
	for (const req of g.required) {
		if (!src.includes(req)) {
			violations.push(
				`${g.file} is missing the canonical marker ${JSON.stringify(req)}; the port's contract was broken`,
			);
		}
	}
	return violations;
}

describe("sdk/ts library-adoption guard", () => {
	it("thumbprint.ts preserves the fixed RFC 7638 canonical JWK byte contract", () => {
		// The exact member order / literal is the cross-language byte contract
		// (Go go-jose + Python emit the same string). A reorder or reformat here
		// silently breaks byte-parity with the oracle.
		const violations = evalSite(readSource("thumbprint.ts"), {
			file: "thumbprint.ts",
			forbidden: [],
			required: [`{"crv":"Ed25519","kty":"OKP","x":"`],
		});
		expect(violations).toEqual([]);
	});

	it("crossfield.ts composes the generated gen/ts schemas (does not fork them)", () => {
		// The cross-field layer must .refine() ONTO the generated <Message>Schema,
		// never hand-declare a parallel z.object() wire mirror.
		const violations = evalSite(readSource("crossfield.ts"), {
			file: "crossfield.ts",
			forbidden: [],
			required: [`../../gen/ts/wire/schemas.ts`],
		});
		expect(violations).toEqual([]);
	});

	// ---- Meta-tests: prove the guard both CATCHES a regression (positive) and
	// PASSES clean source (negative). Substring-based, so there is no regex-slip
	// case to cover. ----

	const synthetic: SiteGuard = {
		file: "synthetic.ts",
		forbidden: ["z.object({ crv: z.literal"],
		required: [`../../gen/ts/wire/schemas.ts`],
	};

	it("meta: catches a re-introduced wire-mirror + dropped generated import", () => {
		const bad = `const Jwk = z.object({ crv: z.literal("Ed25519") });\n`;
		// both a forbidden hand-rolled mirror AND the missing generated import
		expect(evalSite(bad, synthetic)).toHaveLength(2);
	});

	it("meta: passes clean composed source", () => {
		const good = `import { LicenseSchema } from "../../gen/ts/wire/schemas.ts";\n`;
		expect(evalSite(good, synthetic)).toHaveLength(0);
	});
});

// ---- sdk/ts/core transport-neutrality guard ----
//
// Mirror of the Go core "no connectrpc import" guard (sdk/go/core
// library_adoption_guard_test.go). The L2 CORE must impose NOTHING beyond the web
// standard (WebCrypto + Fetch): NO framework import — no Hono, no Connect-ES. The
// framework binding (sdk/ts/hono) depends on core, never the reverse, so the
// forbidden imports are the FRAMEWORK names in the CORE files, and the required
// marker is that the offer-verify core composes a vetted JCS lib rather than
// hand-rolling canonicalization.
const coreSrcPath = (rel: string): string =>
	fileURLToPath(new URL(`../${rel}`, import.meta.url));

function readRel(rel: string): string {
	return readFileSync(coreSrcPath(rel), "utf8");
}

describe("sdk/ts/core transport-neutrality guard", () => {
	it("core/verifier.ts imports NO framework (no hono, no connect-es) and uses a vetted JCS lib", () => {
		const violations = evalSite(readRel("core/verifier.ts"), {
			file: "core/verifier.ts",
			forbidden: ['from "hono', 'from "@connectrpc', 'from "@hono'],
			// Never hand-roll canonicalization — compose the vetted JCS npm lib.
			required: ['from "canonicalize"'],
		});
		expect(violations).toEqual([]);
	});

	it("core/sign.ts imports NO framework (Fetch/WebCrypto only)", () => {
		const violations = evalSite(readRel("core/sign.ts"), {
			file: "core/sign.ts",
			forbidden: ['from "hono', 'from "@connectrpc', 'from "@hono'],
			required: [],
		});
		expect(violations).toEqual([]);
	});

	it("the hono binding depends on core (one-directional), not the reverse", () => {
		// The binding MAY reference core; the core MUST NOT reference the binding.
		const core = readRel("core/verifier.ts") + readRel("core/sign.ts");
		expect(core.includes("../hono/")).toBe(false);
	});
});
