// Behavior suite for activeEd25519Key — the document-order active-key selector
// that complements the thumbprint-keyed WBAKeyResolver.resolve. Byte-parity with
// the Go ActiveEd25519Key / Python active_ed25519_key oracles: iterate the
// directory's keys in DOCUMENT ORDER, examine at most the first maxScan (default
// 10, a DoS cap), return the FIRST window-active well-formed OKP/Ed25519 key whose
// x base64url-decodes to exactly 32 bytes; skip-and-continue past any failing key;
// null when none qualifies. Pure logic over a parsed WBAFile — no HTTP origin.
import { describe, expect, it } from "vitest";

import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { encodeBase64Url } from "../src/base64url.ts";
import { activeEd25519Key, activeEd25519KeyWithExpiry } from "../resolvers/index.ts";
import { ANCHOR_MS, HOUR_MS, iso, makeKey, wbaJwk } from "./resolvers-harness.ts";

type WBAFile = ReturnType<typeof WBAFileSchema.parse>;

function activeJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + HOUR_MS));
}
function expiredJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - 2 * HOUR_MS), iso(ANCHOR_MS - HOUR_MS));
}
function futureJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS + HOUR_MS), iso(ANCHOR_MS + 2 * HOUR_MS));
}
// A long-window active key: active at ANCHOR with a FAR not_after, so a
// with-expiry test can assert a not_after distinct from activeJwk's bound.
function longJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + 1000 * HOUR_MS));
}
function directory(keys: Record<string, unknown>[]): WBAFile {
	return WBAFileSchema.parse({ keys });
}

describe("activeEd25519Key", () => {
	it("selects the first active key in document order", async () => {
		const k1 = await makeKey();
		const k2 = await makeKey();
		const dir = directory([activeJwk(k1.x), activeJwk(k2.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(k1.rawPub);
	});

	it("skips a retired key ahead of the active one", async () => {
		const retired = await makeKey();
		const active = await makeKey();
		const dir = directory([expiredJwk(retired.x), activeJwk(active.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(active.rawPub);
	});

	it("skips a not-yet-valid key ahead of the active one", async () => {
		const future = await makeKey();
		const active = await makeKey();
		const dir = directory([futureJwk(future.x), activeJwk(active.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(active.rawPub);
	});

	it("skips a non-OKP key and continues", async () => {
		const bad = await makeKey();
		const good = await makeKey();
		const dir = directory([{ ...activeJwk(bad.x), kty: "RSA" }, activeJwk(good.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(good.rawPub);
	});

	it("skips a wrong-crv key and continues", async () => {
		const bad = await makeKey();
		const good = await makeKey();
		const dir = directory([{ ...activeJwk(bad.x), crv: "P-256" }, activeJwk(good.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(good.rawPub);
	});

	it("skips an undecodable-x key and continues", async () => {
		const good = await makeKey();
		// "!!!!" is not valid base64url — atob throws, so the decode fails.
		const dir = directory([activeJwk("!!!!"), activeJwk(good.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(good.rawPub);
	});

	it("skips a wrong-length-x key (31 bytes) and continues", async () => {
		const good = await makeKey();
		const shortX = encodeBase64Url(new Uint8Array(31).fill(1));
		const dir = directory([activeJwk(shortX), activeJwk(good.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(good.rawPub);
	});

	it("selects a valid key at position 10 (0-indexed 9) within the default cap", async () => {
		const fillers = await Promise.all(
			Array.from({ length: 9 }, async () => expiredJwk((await makeKey()).x)),
		);
		const target = await makeKey();
		const dir = directory([...fillers, activeJwk(target.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toEqual(target.rawPub);
	});

	it("cannot reach a valid key at position 11 (0-indexed 10) under the default cap", async () => {
		const fillers = await Promise.all(
			Array.from({ length: 10 }, async () => expiredJwk((await makeKey()).x)),
		);
		const target = await makeKey();
		const dir = directory([...fillers, activeJwk(target.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toBeNull();
	});

	it("reaches position 11 when maxScan is raised past the padding", async () => {
		const fillers = await Promise.all(
			Array.from({ length: 10 }, async () => expiredJwk((await makeKey()).x)),
		);
		const target = await makeKey();
		const dir = directory([...fillers, activeJwk(target.x)]);
		expect(activeEd25519Key(dir, ANCHOR_MS, 11)).toEqual(target.rawPub);
	});

	it("returns null for an empty directory", () => {
		expect(activeEd25519Key(directory([]), ANCHOR_MS)).toBeNull();
	});

	it("returns null when no key is window-active", async () => {
		const dir = directory([
			expiredJwk((await makeKey()).x),
			futureJwk((await makeKey()).x),
		]);
		expect(activeEd25519Key(dir, ANCHOR_MS)).toBeNull();
	});
});

describe("activeEd25519KeyWithExpiry", () => {
	it("returns the selected key and its exact not_after", async () => {
		const k1 = await makeKey();
		const k2 = await makeKey();
		const dir = directory([activeJwk(k1.x), activeJwk(k2.x)]);
		const result = activeEd25519KeyWithExpiry(dir, ANCHOR_MS);
		expect(result).not.toBeNull();
		expect(result?.key).toEqual(k1.rawPub);
		expect(result?.notAfter).toBe(ANCHOR_MS + HOUR_MS); // activeJwk's not_after
	});

	it("skips inactive/malformed keys and returns the next active key's not_after", async () => {
		const future = await makeKey();
		const selected = await makeKey();
		const dir = directory([
			expiredJwk((await makeKey()).x),
			futureJwk(future.x),
			activeJwk("!!!!"), // active window but x is undecodable base64url
			longJwk(selected.x),
		]);
		const result = activeEd25519KeyWithExpiry(dir, ANCHOR_MS);
		expect(result?.key).toEqual(selected.rawPub);
		expect(result?.notAfter).toBe(ANCHOR_MS + 1000 * HOUR_MS); // longJwk's not_after
	});

	it("returns null when no key qualifies", async () => {
		const dir = directory([
			expiredJwk((await makeKey()).x),
			futureJwk((await makeKey()).x),
		]);
		expect(activeEd25519KeyWithExpiry(dir, ANCHOR_MS)).toBeNull();
	});

	it("agrees with activeEd25519Key on the selected key", async () => {
		const selected = await makeKey();
		const dir = directory([expiredJwk((await makeKey()).x), longJwk(selected.x)]);
		const plain = activeEd25519Key(dir, ANCHOR_MS);
		const withExpiry = activeEd25519KeyWithExpiry(dir, ANCHOR_MS);
		expect(withExpiry).not.toBeNull();
		expect(plain).toEqual(withExpiry?.key);
	});
});
