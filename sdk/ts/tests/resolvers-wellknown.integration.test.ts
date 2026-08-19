// Integration suite (TDD red) for the ported STATIC, WELL-KNOWN-KEY, and
// WELL-KNOWN-ENDPOINT resolver faces — mirroring sdk/go/helpers
// keyresolver_test.go + endpointresolver_test.go 1:1, plus the skip-not-fail
// JWKS matrix.
//
// These are IO-bound faces, so every case drives a REAL node:http origin (the
// shared harness) through the resolver's default global-fetch transport and
// asserts the resolved key/endpoint back out. Only the clock is injected.
//
// RED CONTRACT: the faces live in ../resolvers/ (kept OUT of the IO-free
// core/src tree per the transport-neutrality invariant) and DO NOT EXIST YET.
// The import below fails module resolution, so the whole file is RED until the
// next atom lands the faces — RED on the missing faces, not on a fixture error.
import { afterEach, describe, expect, it } from "vitest";

import {
	ANCHOR_MS,
	HOUR_MS,
	type Origin,
	jwksEntry,
	jwksKeyDocJson,
	makeKey,
	manifestJson,
	startOrigin,
	loopbackFetch,
} from "./resolvers-harness.ts";

// RED: ../resolvers/index.ts does not exist yet. The typed
// error classes and the four named constructors are the ported public surface.
import {
	DirectoryUnavailable,
	EndpointRefused,
	NoEndpoint,
	createStaticKeyResolver,
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
} from "../resolvers/index.ts";

describe("createStaticKeyResolver", () => {
	it("resolves a seeded key and returns undefined for an unknown keyid", async () => {
		const a = await makeKey();
		const b = await makeKey();
		const r = createStaticKeyResolver({ "a.v1": a.rawPub });

		expect(await r.resolve("a.v1")).toEqual(a.rawPub);
		// A plain unknown key is undefined (NOT a thrown typed error).
		expect(await r.resolve("missing")).toBeUndefined();

		r.put("b.v1", b.rawPub);
		expect(await r.resolve("b.v1")).toEqual(b.rawPub);
	});
});

describe("createWellKnownKeyResolver", () => {
	let origin: Origin | undefined;
	afterEach(async () => {
		await origin?.close();
	});

	it("fetches on a cache miss, then serves the second resolve from cache", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setJwks(jwksKeyDocJson([jwksEntry("ex.v1", k.x)]));

		const r = createWellKnownKeyResolver(`${origin.url}/keys.json`, { ttlMs: HOUR_MS, fetch: loopbackFetch });
		expect(await r.resolve("ex.v1")).toEqual(k.rawPub);
		// Cached: no second fetch.
		expect(await r.resolve("ex.v1")).toEqual(k.rawPub);
		expect(origin.jwksHits()).toBe(1);
		// Unknown kid within the cache is undefined and does not refetch.
		expect(await r.resolve("nope")).toBeUndefined();
		expect(origin.jwksHits()).toBe(1);
	});

	it("refetches after the TTL expires", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setJwks(jwksKeyDocJson([jwksEntry("ex.v1", k.x)]));

		let now = ANCHOR_MS;
		const r = createWellKnownKeyResolver(`${origin.url}/keys.json`, {
			ttlMs: 60_000,
			now: () => now,
			fetch: loopbackFetch,
		});
		expect(await r.resolve("ex.v1")).toEqual(k.rawPub);
		now = ANCHOR_MS + 2 * 60_000; // expire the cache
		expect(await r.resolve("ex.v1")).toEqual(k.rawPub);
		expect(origin.jwksHits()).toBe(2);
	});

	it("throws DirectoryUnavailable on a non-200 fetch, DISTINCT from an unknown key", async () => {
		origin = await startOrigin();
		origin.setJwksStatus(500);

		const r = createWellKnownKeyResolver(`${origin.url}/keys.json`, { ttlMs: HOUR_MS, fetch: loopbackFetch });
		// The taxonomy the composite depends on: an outage is a thrown
		// DirectoryUnavailable (fail-closed halt), never a silent undefined that
		// a composite would treat as "unknown key, fall through".
		await expect(r.resolve("ex.v1")).rejects.toBeInstanceOf(DirectoryUnavailable);
	});

	it("coalesces a concurrent burst of cold resolves into a single JWKS fetch", async () => {
		// Single-flight parity (Core Invariant: same shape in Go/Python/TS). The
		// resolver's `inflight` guard collapses a concurrent burst of cold resolves
		// into ONE upstream fetch. Every resolve is started before any is awaited, so
		// each observes the leader's in-flight refresh and coalesces onto it — mirrors
		// the WBA + offer-cache single-flight assertions. RED if single-flight
		// regresses: a burst of N cold resolves would drive N JWKS fetches.
		const k = await makeKey();
		origin = await startOrigin();
		origin.setJwks(jwksKeyDocJson([jwksEntry("ex.v1", k.x)]));

		const r = createWellKnownKeyResolver(`${origin.url}/keys.json`, {
			ttlMs: HOUR_MS,
			now: () => ANCHOR_MS,
			fetch: loopbackFetch,
		});

		const burst = 12;
		const results = await Promise.all(
			Array.from({ length: burst }, () => r.resolve("ex.v1")),
		);
		for (const got of results) expect(got).toEqual(k.rawPub);
		expect(origin.jwksHits()).toBe(1);
	});

	// JWKS extraction is skip-not-fail — one malformed key must not kill the
	// whole publisher key set; survivors still resolve, bad entries become
	// unknown (undefined).
	it("skips malformed JWKS entries (missing kid / non-Ed25519 / bad-length x) and resolves survivors", async () => {
		const good = await makeKey();
		const nonEd = await makeKey();
		origin = await startOrigin();
		origin.setJwks(
			jwksKeyDocJson([
				// missing kid → skipped
				{ kty: "OKP", crv: "Ed25519", x: (await makeKey()).x },
				// non-Ed25519 kty → skipped
				{ kid: "rsa.v1", kty: "RSA", crv: "Ed25519", x: nonEd.x },
				// wrong-length x (not 32 bytes) → skipped
				{ kid: "short.v1", kty: "OKP", crv: "Ed25519", x: "AAAA" },
				// valid survivor
				jwksEntry("good.v1", good.x),
			]),
		);

		const r = createWellKnownKeyResolver(`${origin.url}/keys.json`, { ttlMs: HOUR_MS, fetch: loopbackFetch });
		expect(await r.resolve("good.v1")).toEqual(good.rawPub);
		// The skipped entries are unknown (undefined), NOT a thrown parse failure.
		expect(await r.resolve("rsa.v1")).toBeUndefined();
		expect(await r.resolve("short.v1")).toBeUndefined();
	});
});

describe("createWellKnownEndpointResolver", () => {
	// Every endpoint in this file is LATE-BOUND to the origin that serves it: an
	// Exchange advertises ITSELF, so the value is not known until its server has an
	// address. That is not test bookkeeping — it is the endpoint rule. An endpoint
	// on any other host is one the resolver refuses to hand back, so a fixed
	// exchange.example string served from a loopback port would exercise the
	// refusal path rather than the behaviour each of these tests is about.
	it("resolves each host to its OWN endpoint (per-host cache isolation)", async () => {
		const a = await startOrigin();
		const b = await startOrigin();
		const epA = `http://${a.host}/ramp.v1.ExchangeService`;
		const epB = `http://${b.host}/ramp.v1.ExchangeService`;
		a.setManifest(manifestJson(epA));
		b.setManifest(manifestJson(epB));
		try {
			const r = createWellKnownEndpointResolver({ ttlMs: HOUR_MS, scheme: "http", fetch: loopbackFetch });
			expect(await r.resolveEndpoint(a.host)).toBe(epA);
			expect(await r.resolveEndpoint(b.host)).toBe(epB);
			// Re-resolving A must never return B's endpoint — the cache is keyed
			// per host and B did not clobber A.
			expect(await r.resolveEndpoint(a.host)).toBe(epA);
		} finally {
			await a.close();
			await b.close();
		}
	});

	it("serves the second resolve for the same host from cache", async () => {
		const origin = await startOrigin();
		const ep = `http://${origin.host}/ramp.v1.ExchangeService`;
		origin.setManifest(manifestJson(ep));
		try {
			const r = createWellKnownEndpointResolver({ ttlMs: HOUR_MS, scheme: "http", fetch: loopbackFetch });
			expect(await r.resolveEndpoint(origin.host)).toBe(ep);
			expect(await r.resolveEndpoint(origin.host)).toBe(ep);
			expect(origin.manifestHits()).toBe(1);
		} finally {
			await origin.close();
		}
	});

	it("refetches after the TTL expires", async () => {
		const origin = await startOrigin();
		const ep = `http://${origin.host}/ramp.v1.ExchangeService`;
		origin.setManifest(manifestJson(ep));
		try {
			let now = ANCHOR_MS;
			const r = createWellKnownEndpointResolver({
				ttlMs: 60_000,
				scheme: "http", fetch: loopbackFetch,
				now: () => now,
			});
			expect(await r.resolveEndpoint(origin.host)).toBe(ep);
			now = ANCHOR_MS + 2 * 60_000;
			expect(await r.resolveEndpoint(origin.host)).toBe(ep);
			expect(origin.manifestHits()).toBe(2);
		} finally {
			await origin.close();
		}
	});

	it("throws DirectoryUnavailable on a non-200 manifest response", async () => {
		const origin = await startOrigin();
		origin.setManifestStatus(503);
		try {
			const r = createWellKnownEndpointResolver({ scheme: "http", fetch: loopbackFetch });
			await expect(r.resolveEndpoint(origin.host)).rejects.toBeInstanceOf(DirectoryUnavailable);
		} finally {
			await origin.close();
		}
	});

	it("throws DirectoryUnavailable on a malformed manifest body", async () => {
		const origin = await startOrigin();
		origin.setManifest("{not json");
		try {
			const r = createWellKnownEndpointResolver({ scheme: "http", fetch: loopbackFetch });
			await expect(r.resolveEndpoint(origin.host)).rejects.toBeInstanceOf(DirectoryUnavailable);
		} finally {
			await origin.close();
		}
	});

	it("throws NoEndpoint when a valid manifest omits the endpoint field", async () => {
		const origin = await startOrigin();
		origin.setManifest(manifestJson(undefined)); // valid manifest, no endpoint
		try {
			const r = createWellKnownEndpointResolver({ scheme: "http", fetch: loopbackFetch });
			// NoEndpoint must be DISTINCT from DirectoryUnavailable: the manifest
			// was reachable and decoded, it simply advertises no endpoint.
			await expect(r.resolveEndpoint(origin.host)).rejects.toBeInstanceOf(NoEndpoint);
			expect(origin.manifestHits()).toBe(1);
		} finally {
			await origin.close();
		}
	});

	// The WIRING half of the endpoint rule. Which endpoints the rule refuses is
	// settled by the shared vectors (host-rule.parity.test.ts and
	// endpoint-vet.parity.test.ts); what these cases pin is that the resolver
	// actually asks — before it hands anything back, and before it caches.
	it("refuses an endpoint on a host unrelated to the one that served the manifest", async () => {
		const origin = await startOrigin();
		origin.setManifest(manifestJson("https://cdn.other.example/ramp.v1.ExchangeService"));
		try {
			const r = createWellKnownEndpointResolver({ ttlMs: HOUR_MS, scheme: "http", fetch: loopbackFetch });
			// A VERDICT, not a transport failure: the Exchange answered and the answer
			// is unusable, so a caller classifying retryability reads this as final.
			await expect(r.resolveEndpoint(origin.host)).rejects.toBeInstanceOf(EndpointRefused);
		} finally {
			await origin.close();
		}
	});

	it("refuses an endpoint carrying credentials, with or without a scheme", async () => {
		const origin = await startOrigin();
		try {
			const r = createWellKnownEndpointResolver({ scheme: "http", fetch: loopbackFetch });
			for (const ep of [
				`http://user:pass@${origin.host}/ramp.v1.ExchangeService`,
				// Schemeless. A plain URL parse reads "user" as the scheme and finds no
				// userinfo at all, while the anchor check recovers the host and matches
				// it — so this is the shape a rule that reads the reference twice lets
				// through.
				`user:pass@${origin.host}/ramp.v1.ExchangeService`,
			]) {
				origin.setManifest(manifestJson(ep));
				await expect(r.resolveEndpoint(origin.host)).rejects.toBeInstanceOf(EndpointRefused);
			}
		} finally {
			await origin.close();
		}
	});

	it("does not cache a refused endpoint", async () => {
		const origin = await startOrigin();
		origin.setManifest(manifestJson("https://cdn.other.example/ramp.v1.ExchangeService"));
		try {
			const r = createWellKnownEndpointResolver({ ttlMs: HOUR_MS, scheme: "http", fetch: loopbackFetch });
			await expect(r.resolveEndpoint(origin.host)).rejects.toBeInstanceOf(EndpointRefused);
			// The Exchange fixes its manifest. A resolver that had cached the refused
			// value would keep refusing for the whole TTL.
			const ep = `http://${origin.host}/ramp.v1.ExchangeService`;
			origin.setManifest(manifestJson(ep));
			expect(await r.resolveEndpoint(origin.host)).toBe(ep);
		} finally {
			await origin.close();
		}
	});

	it("refuses to resolve a host that is not a bare host", async () => {
		const origin = await startOrigin();
		origin.setManifest(manifestJson(`http://${origin.host}/ramp.v1.ExchangeService`));
		try {
			const r = createWellKnownEndpointResolver({ scheme: "http", fetch: loopbackFetch });
			// The fetch URL is built by concatenation, so a smuggled path would choose
			// WHAT gets fetched. Refused before the network, so the origin is never hit.
			//
			// The refusal is the invalid-host fault, NOT EndpointRefused: the bad value
			// is the caller's argument, and no manifest was read to have a verdict on.
			for (const bad of [`${origin.host}/.well-known/evil.json`, `http://${origin.host}`, ""]) {
				await expect(r.resolveEndpoint(bad)).rejects.toThrow(/not a usable host/);
			}
			expect(origin.manifestHits()).toBe(0);
		} finally {
			await origin.close();
		}
	});
});
