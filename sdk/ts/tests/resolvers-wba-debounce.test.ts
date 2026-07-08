// RAMP-24 anti-amplification parity (TS port of the Go
// wbakeyresolver_debounce_test.go). The unknown-thumbprint force-refresh is
// throttled to one directory fetch per debounce window per host, and a
// concurrent burst coalesces to one in-flight fetch. Because the resolver runs
// BEFORE the ed25519 check and the fetch host is the caller-supplied
// Signature-Agent, an unauthenticated caller must not drive N outbound GETs with
// N unknown-thumbprint requests.
//
// The SAME behavioral bound as go/python: a fetch-COUNTING origin + an injected
// clock assert a burst of N unknown lookups → 1 fetch (independent of N); the
// window resumes after syncDebounceMs; a concurrent burst → 1 fetch.
import { afterEach, describe, expect, it } from "vitest";
import { newWBAKeyResolver } from "../resolvers/index.ts";
import {
	ANCHOR_MS,
	HOUR_MS,
	iso,
	makeKey,
	type Origin,
	startOrigin,
	wbaFileJson,
	wbaJwk,
} from "./resolvers-harness.ts";

function longJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + 1000 * HOUR_MS));
}

describe("newWBAKeyResolver unknown-thumbprint debounce", () => {
	let origin: Origin | undefined;
	afterEach(async () => {
		await origin?.close();
		origin = undefined;
	});

	// A burst of N unknown lookups for one host forces exactly ONE directory
	// fetch (independent of N); a lookup after the debounce window fetches again.
	it("bounds a burst of unknown lookups to one fetch and resumes after the window", async () => {
		const known = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([longJwk(known.x)]));

		let now = ANCHOR_MS;
		const r = newWBAKeyResolver({
			scheme: "http",
			ttlMs: HOUR_MS,
			syncDebounceMs: 5_000,
			now: () => now,
		});

		// Prime the directory cache with the known key (no force-refresh), then
		// measure only the forced fetches the burst triggers.
		expect(await r.resolve(known.tp, origin.url)).toEqual(known.rawPub);
		const primed = origin.wbaHits();

		const burst = 50;
		for (let i = 0; i < burst; i++) {
			expect(
				await r.resolve(`unknown-thumbprint-${i}`, origin.url),
			).toBeUndefined();
		}
		expect(origin.wbaHits() - primed).toBe(1);

		// Advance past the debounce window (still within TTL): one more forced fetch.
		now = ANCHOR_MS + 6_000;
		expect(await r.resolve("unknown-after-window", origin.url)).toBeUndefined();
		expect(origin.wbaHits() - primed).toBe(2);
	});

	// A concurrent burst of cold resolves for one host coalesces to a single
	// outbound GET — the in-flight table (singleflight) shares one fetch.
	it("coalesces a concurrent cold burst to one fetch", async () => {
		const known = await makeKey();
		const o = await startOrigin();
		origin = o;
		o.setWBA(wbaFileJson([longJwk(known.x)]));

		const r = newWBAKeyResolver({
			scheme: "http",
			ttlMs: HOUR_MS,
			now: () => ANCHOR_MS,
		});

		const burst = 12;
		const results = await Promise.all(
			Array.from({ length: burst }, () => r.resolve(known.tp, o.url)),
		);
		for (const got of results) expect(got).toEqual(known.rawPub);
		expect(o.wbaHits()).toBe(1);
	});
});
