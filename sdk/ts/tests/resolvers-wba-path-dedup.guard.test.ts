import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural dedup guard for the WBA directory-path constant (hp5o2.4).
//
// TS carries TWO copies of the "/.well-known/http-message-signatures-directory"
// path string: the module-private WBA_DIRECTORY_PATH in resolvers/wba.ts and the
// duplicate WBA_OFFER_DIRECTORY_PATH exported from resolvers/offer-key-cache.ts and
// re-exported through the public barrel resolvers/index.ts. The consolidation
// collapses these onto ONE public WBA_DIRECTORY_PATH exported from the barrel and
// DELETES the stale WBA_OFFER_DIRECTORY_PATH symbol + its barrel export.
//
// This is a non-behavioral (naming/dedup) disease with no runtime-observable
// change, so per the test-author structural-disease exception the red artifact is
// the source-level guard that sweep-verify later requires: it pins that the
// duplicate symbol is GONE and the single public constant is exported in its place.
//
// TDD-red: WBA_OFFER_DIRECTORY_PATH is still present in the barrel export today and
// WBA_DIRECTORY_PATH is not exported from it — so both assertions fail now.
//
// The detector is regex-based and whitespace-tolerant so a formatter reflow of the
// export block cannot let a revert slip; the meta-tests below exercise that.

const barrelPath = fileURLToPath(
	new URL("../resolvers/index.ts", import.meta.url),
);

function readBarrel(): string {
	return readFileSync(barrelPath, "utf8");
}

// The duplicate symbol that MUST disappear from the public surface.
const FORBIDDEN_DUP = /\bWBA_OFFER_DIRECTORY_PATH\b/;
// The single public constant that MUST be exported in its place.
const REQUIRED_CONST = /\bWBA_DIRECTORY_PATH\b/;

describe("WBA directory-path constant is deduplicated onto one public export", () => {
	it("no longer exports the duplicate WBA_OFFER_DIRECTORY_PATH from the barrel", () => {
		expect(FORBIDDEN_DUP.test(readBarrel())).toBe(false);
	});

	it("exports the single public WBA_DIRECTORY_PATH from the barrel", () => {
		expect(REQUIRED_CONST.test(readBarrel())).toBe(true);
	});

	// --- meta-tests: exercise the detector against synthetic barrel source ----
	it("[meta positive] catches a lingering WBA_OFFER_DIRECTORY_PATH export", () => {
		const bad = "export { WBA_OFFER_DIRECTORY_PATH } from './offer-key-cache.ts';";
		expect(FORBIDDEN_DUP.test(bad)).toBe(true);
	});

	it("[meta negative] passes the deduped single-constant export", () => {
		const good = "export { WBA_DIRECTORY_PATH } from './wba.ts';";
		expect(FORBIDDEN_DUP.test(good)).toBe(false);
		expect(REQUIRED_CONST.test(good)).toBe(true);
	});
});
