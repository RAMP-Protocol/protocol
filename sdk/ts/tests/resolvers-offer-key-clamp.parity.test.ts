// Cross-language offer-key EXPIRY-CLAMP parity (TypeScript side).
//
// sdk/ts clampOfferKeyExpiry MUST reproduce the sdk/go clampOfferKeyExpiry oracle's
// clamped expiry for EVERY vector in
// sdk/go/resolvers/testdata/offer-key-clamp-vectors.json. Each vector is
// {label, now, ttl_seconds, not_after, expected_expiry}: now/not_after/
// expected_expiry are RFC3339 strings (parsed natively to epoch-ms here),
// ttl_seconds is numeric.
//
// The clamped expiry (min(now+ttl, not_after)) is what keeps a cached offer-signing
// key from being served past its validity window. Replaying the corpus proves the
// TS clamp the CachedOfferKeyResolver CALLS agrees with the Go/Python clamp at the
// boundary the three languages must never disagree on: TTL-first, not_after-first,
// and the exact-equality now+ttl == not_after seam.
import { describe, expect, it } from "vitest";

import corpus from "../../go/resolvers/testdata/offer-key-clamp-vectors.json";
import { clampOfferKeyExpiry } from "../resolvers/offer-key-cache.ts";

interface ClampVector {
	label: string;
	now: string;
	ttl_seconds: number;
	not_after: string;
	expected_expiry: string;
}
interface ClampCorpus {
	note: string;
	vectors: ClampVector[];
}

const c = corpus as ClampCorpus;

describe("sdk/ts clampOfferKeyExpiry matches the sdk/go clamp oracle", () => {
	it("has a non-empty vector corpus", () => {
		expect(c.vectors.length).toBeGreaterThan(0);
	});

	for (const v of c.vectors) {
		it(v.label, () => {
			const nowMs = Date.parse(v.now);
			const ttlMs = v.ttl_seconds * 1000;
			const notAfterMs = Date.parse(v.not_after);
			expect(clampOfferKeyExpiry(nowMs, ttlMs, notAfterMs)).toBe(
				Date.parse(v.expected_expiry),
			);
		});
	}
});
