// Behavior suite for CachedOfferKeyResolver — the domain-keyed offer-signing-key
// cache that consolidates the Broker's offerkeys.Resolver and the MCP shim's
// ExchangeOfferKeyCache: per-domain TTL cache → WBA-directory fetch (injected
// seam) → revocation-aware active-key selection → not_after clamp. It IMPLEMENTS
// core/verifier.ts OfferKeyResolver (resolve(exchange) → Promise<key|undefined>),
// so newVerifier({ resolve }) injects it directly.
//
// The suite ports the REAL Go oracle cases (sdk/go/resolvers/
// cachedofferkeyresolver_test.go), reconciled to TS ABSENCE semantics: TS is
// fail-closed by `undefined`, NOT error-propagating like Go. Where Go asserts an
// error (PropagatesFetchError, RejectsWhenNoActiveKey, ClampsExpiryToNotAfter's
// ErrKeyExpired), the TS contract asserts `undefined` — this is the confirmed
// API-shape decision (OfferKeyResolver.resolve returns undefined for absence),
// matching Python's absence-from-map, not Go's error.
//
// Every leg drives the PUBLIC resolve() surface with an INJECTED counting fake
// fetch (no HTTP) and an INJECTED clock (opts.now) — no network, no real origin.
//
// RED: sdk/ts/resolvers/offer-key-cache.ts does not exist yet, so the import
// below fails to resolve and the whole suite is red until the module lands.
import { describe, expect, it } from "vitest";

import type { OfferKeyResolver } from "../core/verifier.ts";
import {
	type CachedOfferKeyResolverOptions,
	type OfferDirectoryFetch,
	createCachedOfferKeyResolver,
} from "../resolvers/offer-key-cache.ts";
import {
	activeJwk,
	ANCHOR_MS,
	directory,
	expiredJwk,
	HOUR_MS,
	makeKey,
	type WBAFile,
} from "./resolvers-harness.ts";

const EXCHANGE = "exchange.example";
const MINUTE_MS = 60_000;

/** An injected directory-fetch seam over a fixed per-domain table; counts calls.
 * Returns undefined for an absent domain (unresolvable) — the TS mapping of a
 * fetch that cannot produce a directory. */
function countingFetch(table: Record<string, WBAFile | undefined>): {
	fetch: OfferDirectoryFetch;
	calls: () => number;
} {
	let n = 0;
	const fetch: OfferDirectoryFetch = async (domain: string) => {
		n += 1;
		return table[domain];
	};
	return { fetch, calls: () => n };
}

describe("CachedOfferKeyResolver", () => {
	it("implements the OfferKeyResolver surface core.Verifier resolves through", () => {
		const { fetch } = countingFetch({});
		// A structural pin: the factory's return value must satisfy OfferKeyResolver
		// so newVerifier({ resolve }) accepts it. The TS analogue of Go's
		// `var _ helpers.KeyResolver = (*CachedOfferKeyResolver)(nil)` compile-assert.
		const resolver: OfferKeyResolver = createCachedOfferKeyResolver({
			fetch,
			now: () => ANCHOR_MS,
		});
		expect(typeof resolver.resolve).toBe("function");
	});

	it("caches within the TTL — a second resolve does not refetch", async () => {
		const key = await makeKey();
		const { fetch, calls } = countingFetch({
			[EXCHANGE]: directory([activeJwk(key.x)]),
		});
		const resolver = createCachedOfferKeyResolver({
			fetch,
			ttlMs: MINUTE_MS,
			now: () => ANCHOR_MS,
		});

		expect(await resolver.resolve(EXCHANGE)).toEqual(key.rawPub);
		// A second resolve within the TTL is a cache hit — no second fetch.
		expect(await resolver.resolve(EXCHANGE)).toEqual(key.rawPub);
		expect(calls()).toBe(1);
	});

	it("refetches after the TTL expires", async () => {
		const key = await makeKey();
		const { fetch, calls } = countingFetch({
			[EXCHANGE]: directory([activeJwk(key.x)]),
		});
		let now = ANCHOR_MS;
		const resolver = createCachedOfferKeyResolver({
			fetch,
			ttlMs: MINUTE_MS,
			now: () => now,
		});

		await resolver.resolve(EXCHANGE);
		// Advance past the TTL (still inside the key window): the entry is stale → refetch.
		now = ANCHOR_MS + 2 * MINUTE_MS;
		await resolver.resolve(EXCHANGE);
		expect(calls()).toBe(2);
	});

	it("clamps the cache-entry expiry to not_after, not now+TTL", async () => {
		// The TTL is far longer than the key's remaining window, so the entry MUST
		// expire at not_after (ANCHOR+1h), NOT at now+TTL — otherwise a key would keep
		// verifying up to a full TTL past its validity window.
		const key = await makeKey();
		const { fetch, calls } = countingFetch({
			[EXCHANGE]: directory([activeJwk(key.x)]), // not_after = ANCHOR+1h
		});
		let now = ANCHOR_MS;
		const resolver = createCachedOfferKeyResolver({
			fetch,
			ttlMs: 1000 * HOUR_MS,
			now: () => now,
		});

		expect(await resolver.resolve(EXCHANGE)).toEqual(key.rawPub);
		// Just before not_after: still a cache hit (no refetch).
		now = ANCHOR_MS + HOUR_MS - MINUTE_MS;
		await resolver.resolve(EXCHANGE);
		expect(calls()).toBe(1);
		// At not_after the clamped entry expires → refetch. The key is now also outside
		// its window, so selection fails closed → undefined — proving the clamp evicted
		// at not_after rather than at the far-future now+TTL.
		now = ANCHOR_MS + HOUR_MS;
		expect(await resolver.resolve(EXCHANGE)).toBeUndefined();
		expect(calls()).toBe(2);
	});

	it("skips a revoked active key and serves the next non-revoked key", async () => {
		// The first window-active key is revoked; the cache is on a verification path,
		// so it MUST screen revocation and serve the next active, non-revoked key.
		const revoked = await makeKey();
		const live = await makeKey();
		const { fetch } = countingFetch({
			[EXCHANGE]: directory([activeJwk(revoked.x), activeJwk(live.x)]),
		});
		const resolver = createCachedOfferKeyResolver({
			fetch,
			now: () => ANCHOR_MS,
			revoked: (tp) => tp === revoked.tp,
		});

		expect(await resolver.resolve(EXCHANGE)).toEqual(live.rawPub);
	});

	it("returns undefined when the fetch is unresolvable (returns undefined)", async () => {
		// TS mapping of Go's PropagatesFetchError: Go propagates the fetch error;
		// TS is fail-closed by ABSENCE — resolve() returns undefined, never throws.
		// This is the confirmed API-shape decision (OfferKeyResolver contract).
		const { fetch, calls } = countingFetch({}); // EXCHANGE absent → undefined
		const resolver = createCachedOfferKeyResolver({ fetch, now: () => ANCHOR_MS });

		await expect(resolver.resolve(EXCHANGE)).resolves.toBeUndefined();
		expect(calls()).toBe(1);
	});

	it("returns undefined when the directory has no active key", async () => {
		// Mirrors Go RejectsWhenNoActiveKey (ErrKeyExpired): an all-retired directory
		// yields no active key → absent (undefined), never a cached nil key.
		const key = await makeKey();
		const { fetch } = countingFetch({
			[EXCHANGE]: directory([expiredJwk(key.x)]),
		});
		const resolver = createCachedOfferKeyResolver({ fetch, now: () => ANCHOR_MS });

		await expect(resolver.resolve(EXCHANGE)).resolves.toBeUndefined();
	});

	it("throws at CONSTRUCTION when fetch is missing", () => {
		// Mirrors Go PanicsWithoutFetch: a missing seam is a programmer error surfaced
		// at construction, NOT a per-resolve fail-closed absence.
		expect(() =>
			createCachedOfferKeyResolver({} as CachedOfferKeyResolverOptions),
		).toThrow(TypeError);
	});

	it("coalesces concurrent resolves into a single fetch (TS-NATIVE single-flight)", async () => {
		// NOT present in the Go/Python oracle — Go fetches outside the mutex, Python
		// batches in prefetch. This mirrors EndpointResolverImpl's per-host single-flight
		// (wellknown.ts) and is asserted as a TS-native property, NOT oracle parity.
		const key = await makeKey();
		const dir = directory([activeJwk(key.x)]);
		let calls = 0;
		let release!: () => void;
		const gate = new Promise<void>((r) => {
			release = r;
		});
		const fetch: OfferDirectoryFetch = async (_domain) => {
			calls += 1;
			await gate; // hold the flight open so both resolves observe it in-flight
			return dir;
		};
		const resolver = createCachedOfferKeyResolver({ fetch, now: () => ANCHOR_MS });

		const p1 = resolver.resolve(EXCHANGE);
		const p2 = resolver.resolve(EXCHANGE);
		release();
		const [a, b] = await Promise.all([p1, p2]);
		expect(a).toEqual(key.rawPub);
		expect(b).toEqual(key.rawPub);
		expect(calls).toBe(1);
	});

	describe("structural fail-closed (invariant-critical)", () => {
		// Core Invariant guard: core.Verifier.sort()→check() awaits resolve() with NO
		// try/catch (verifier.ts:208). A throw would propagate out of sort() and
		// fail-CRASH the whole batch instead of fail-closed-REJECTING the offer. resolve()
		// MUST convert EVERY fallible step (fetch, async selection/screening, the
		// caller-supplied revoked() callback) into undefined — never rely on a
		// "fetcher never throws" contract.
		it("returns undefined when the fetch seam THROWS (never propagates)", async () => {
			const boom: OfferDirectoryFetch = async () => {
				throw new Error("directory unreachable");
			};
			const resolver = createCachedOfferKeyResolver({
				fetch: boom,
				now: () => ANCHOR_MS,
			});

			await expect(resolver.resolve(EXCHANGE)).resolves.toBeUndefined();
		});

		it("returns undefined when the revoked() callback THROWS (never propagates)", async () => {
			const key = await makeKey();
			const { fetch } = countingFetch({
				[EXCHANGE]: directory([activeJwk(key.x)]),
			});
			const resolver = createCachedOfferKeyResolver({
				fetch,
				now: () => ANCHOR_MS,
				revoked: () => {
					throw new Error("revocation channel exploded");
				},
			});

			await expect(resolver.resolve(EXCHANGE)).resolves.toBeUndefined();
		});
	});
});
