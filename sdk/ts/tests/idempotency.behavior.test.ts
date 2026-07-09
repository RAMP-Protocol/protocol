// Idempotency MINT behaviour (TypeScript side) — TDD red for djeue.
//
// NewIdempotencyKey carries entropy → NOT vector-gated. The Go oracle mints 16
// crypto-random bytes → base64.RawURLEncoding (22 chars, no padding). The TS
// face `newIdempotencyKey()` MUST match that SHAPE: a 22-char base64url string,
// charset [-A-Za-z0-9_], no padding, and distinct across N calls (entropy).
//
// RED now purely because sdk/ts/src/idempotency.ts does not exist yet.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/idempotency.ts does not exist yet (TDD red — missing face).
import { newIdempotencyKey } from "../src/idempotency.ts";

const BASE64URL_22 = /^[-A-Za-z0-9_]{22}$/;

describe("sdk/ts newIdempotencyKey shape + entropy", () => {
	it("mints a 22-char base64url key with no padding", () => {
		const key = newIdempotencyKey();
		expect(key).toMatch(BASE64URL_22);
		expect(key).not.toContain("=");
	});

	it("mints distinct keys across N calls (entropy)", () => {
		const n = 512;
		const seen = new Set<string>();
		for (let i = 0; i < n; i += 1) {
			const key = newIdempotencyKey();
			expect(key).toMatch(BASE64URL_22);
			seen.add(key);
		}
		expect(seen.size).toBe(n);
	});
});
