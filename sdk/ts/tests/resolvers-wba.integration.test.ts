// Integration suite (TDD red) for the ported WBA key resolver — mirroring
// sdk/go/helpers/wbakeyresolver_test.go 1:1 (all 14 tests) plus a malformed
// Signature-Agent case (→ unknown). The WBA directory host that Go threads
// through ctx (Signature-Agent) is passed EXPLICITLY as the second resolve arg
// in the port: resolve(thumbprint, directory).
//
// Every case drives a REAL node:http origin (the shared harness) through the
// resolver's default global-fetch transport; the clock and the poll-timer seam
// are injected so no test sleeps. The monotonic guard / as_of clamp /
// forward-progress cases run via Resolve + TTL-expiry (NO poller), so a
// poller-only guard would fail them — only Run_PollerAppliesRevocation exercises
// the background poller, via the OnPollArmed/OnPollCycle determinism seams.
//
// RED CONTRACT: ../resolvers/index.ts does not exist yet — the file is RED on the
// missing faces, not on a fixture error.
import { afterEach, describe, expect, it } from "vitest";

import {
	ANCHOR_MS,
	HOUR_MS,
	iso,
	makeKey,
	type Origin,
	revocationJson,
	startOrigin,
	wbaFileJson,
	wbaJwk,
	loopbackFetch,
} from "./resolvers-harness.ts";

// RED: the WBA face and its typed sentinels do not exist yet.
import {
	DirectoryUnavailable,
	KeyExpired,
	KeyRevoked,
	createWBAKeyResolver,
	RevocationUnevaluated,
	WBA_DIRECTORY_PATH,
} from "../resolvers/index.ts";
import type { FetchLike } from "../resolvers/http.ts";

// activeJwk / expiredJwk / longJwk build a directory JWK member whose validity
// window straddles (or excludes) the shared anchor.
function activeJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + HOUR_MS));
}
function expiredJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - 2 * HOUR_MS), iso(ANCHOR_MS - HOUR_MS));
}
function longJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + 1000 * HOUR_MS));
}

// A deterministic clock: now() is a mutable instant; after(ms) resolves when
// advance() moves the clock to or past the scheduled instant. It is the port of
// the Go pollClock (func() time.Time / func(Duration) <-chan time.Time), letting
// the poller test cross a poll boundary without sleeping.
class TestClock {
	private cur: number;
	private pending: Array<{ at: number; resolve: () => void }> = [];
	constructor(startMs: number) {
		this.cur = startMs;
	}
	now = (): number => this.cur;
	after = (ms: number): Promise<void> =>
		new Promise<void>((resolve) => {
			if (ms <= 0) {
				resolve();
				return;
			}
			this.pending.push({ at: this.cur + ms, resolve });
		});
	advance(ms: number): void {
		this.cur += ms;
		const due = this.pending.filter((t) => t.at <= this.cur);
		this.pending = this.pending.filter((t) => t.at > this.cur);
		for (const t of due) t.resolve();
	}
}

// A buffered (cap-1-ish) signal bridging the resolver's OnPollArmed/OnPollCycle
// seams to the test, so it can wait for the poller to arm its timer, advance the
// clock, then wait for the refresh to complete — the port of the Go pollSignals.
function makeSignal(): { fire: () => void; wait: () => Promise<void> } {
	const buffer: true[] = [];
	const waiters: Array<() => void> = [];
	return {
		fire() {
			const w = waiters.shift();
			if (w) w();
			else buffer.push(true);
		},
		wait() {
			if (buffer.shift()) return Promise.resolve();
			return new Promise<void>((resolve) => waiters.push(resolve));
		},
	};
}

describe("createWBAKeyResolver.resolve", () => {
	let origin: Origin | undefined;
	let extra: Origin | undefined;
	afterEach(async () => {
		await origin?.close();
		await extra?.close();
		extra = undefined;
	});

	// Test 1 — Active happy path.
	it("resolves an active key by thumbprint", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([activeJwk(k.x)]));

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub);
	});

	// Test 2 — key outside its validity window → KeyExpired.
	it("throws KeyExpired for a key outside its validity window", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([expiredJwk(k.x)]));

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyExpired);
	});

	// Test 3 — thumbprint absent from the directory → unknown (undefined).
	it("returns undefined for a thumbprint absent from the directory", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([activeJwk(k.x)]));

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		expect(await r.resolve("absent-thumbprint", origin.url)).toBeUndefined();
	});

	// Test 4 — thumbprint in the revocation snapshot → KeyRevoked.
	it("throws KeyRevoked for a revoked thumbprint", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([activeJwk(k.x)], origin.revocationURL()));
		origin.setRevocation(revocationJson(iso(ANCHOR_MS), [k.tp]));

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyRevoked);
	});

	// Test 5 — a key rotated in after the prime is found by a single sync refresh.
	it("self-heals: a key added after the cache prime is found on refresh", async () => {
		const k1 = await makeKey();
		const k2 = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([activeJwk(k1.x)])); // prime: only k1

		const now = ANCHOR_MS;
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, ttlMs: HOUR_MS, now: () => now });
		expect(await r.resolve(k1.tp, origin.url)).toEqual(k1.rawPub);

		origin.setWBA(wbaFileJson([activeJwk(k1.x), activeJwk(k2.x)])); // rotate k2 in
		// Cache still holds k1-only, so the k2 lookup must trigger a self-heal
		// re-fetch even before the TTL expires.
		expect(await r.resolve(k2.tp, origin.url)).toEqual(k2.rawPub);
	});

	// Test 6 — monotonic guard: an older-as_of snapshot must NOT un-revoke.
	// Runs via Resolve + TTL-expiry (no poller).
	it("ignores a rolled-back (older as_of) revocation snapshot", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([longJwk(k.x)], origin.revocationURL()));
		origin.setRevocation(revocationJson(iso(ANCHOR_MS), [k.tp]));

		let now = ANCHOR_MS;
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, ttlMs: HOUR_MS, now: () => now });
		await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyRevoked);

		// Publish a rolled-back (older as_of) snapshot that drops the revocation.
		origin.setRevocation(revocationJson(iso(ANCHOR_MS - HOUR_MS), []));
		now = ANCHOR_MS + 2 * HOUR_MS; // expire TTL → re-fetch + revocation refresh
		await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyRevoked);
	});

	// Test 7 — forward progress: a strictly-newer empty snapshot DOES un-revoke.
	it("applies a strictly-newer empty snapshot and un-revokes the key", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([longJwk(k.x)], origin.revocationURL()));
		origin.setRevocation(revocationJson(iso(ANCHOR_MS), [k.tp]));

		let now = ANCHOR_MS;
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, ttlMs: HOUR_MS, now: () => now });
		await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyRevoked);

		origin.setRevocation(revocationJson(iso(ANCHOR_MS + HOUR_MS), []));
		now = ANCHOR_MS + 2 * HOUR_MS; // expire TTL
		expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub);
	});

	// Test 8 — a far-future first as_of is clamped to now+skew so a later honest
	// snapshot still applies (first-poll integrity).
	it("clamps a far-future first as_of so later revocations still apply", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([longJwk(k.x)], origin.revocationURL()));
		origin.setRevocation(revocationJson(iso(ANCHOR_MS + 10000 * HOUR_MS), []));

		let now = ANCHOR_MS;
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, ttlMs: HOUR_MS, now: () => now });
		expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub); // prime

		now = ANCHOR_MS + 2 * HOUR_MS;
		origin.setRevocation(revocationJson(iso(ANCHOR_MS + 2 * HOUR_MS), [k.tp]));
		await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyRevoked);
	});

	// Test 9 — a key dropped from the directory is unknown (undefined), NOT revoked.
	it("treats directory removal as unknown, not revocation", async () => {
		const k1 = await makeKey();
		const k2 = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([longJwk(k1.x)]));

		let now = ANCHOR_MS;
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, ttlMs: HOUR_MS, now: () => now });
		expect(await r.resolve(k1.tp, origin.url)).toEqual(k1.rawPub);

		origin.setWBA(wbaFileJson([longJwk(k2.x)])); // drop k1
		now = ANCHOR_MS + 2 * HOUR_MS; // expire TTL → re-fetch k1-less directory
		// Removal is fall-through (undefined), never a thrown KeyRevoked.
		expect(await r.resolve(k1.tp, origin.url)).toBeUndefined();
	});

	// Test 10 — a cross-host revocation_url is skipped; the key stays valid.
	it("skips a revocation_url whose host is not anchored to the directory", async () => {
		const k = await makeKey();
		extra = await startOrigin(); // evil origin that would revoke if polled
		extra.setRevocation(revocationJson(iso(ANCHOR_MS), [k.tp]));

		origin = await startOrigin();
		origin.setWBA(wbaFileJson([activeJwk(k.x)], extra.revocationURL())); // cross-host

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		// Not anchored → not polled → key resolves.
		expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub);
	});

	// M-6 — a directory that declares a revocation_url whose snapshot never lands
	// (here: cross-host, so the poll is refused) leaves revocation UNEVALUATED. The
	// default best-effort mode still resolves the key; requireRevocation makes
	// resolve fail closed with RevocationUnevaluated — DISTINCT from KeyRevoked
	// ("evaluated, revoked").
	it("fails closed with RevocationUnevaluated when requireRevocation and the snapshot never landed", async () => {
		const k = await makeKey();
		extra = await startOrigin(); // a revocation host the resolver must not follow
		extra.setRevocation(revocationJson(iso(ANCHOR_MS), [k.tp]));

		origin = await startOrigin();
		// Declares a revocation_url, but cross-host → never anchored → no snapshot.
		origin.setWBA(wbaFileJson([activeJwk(k.x)], extra.revocationURL()));

		// Default (best-effort): resolves despite the unevaluated revocation channel.
		const best = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		expect(await best.resolve(k.tp, origin.url)).toEqual(k.rawPub);

		// requireRevocation: fail closed — revocation_url declared, no snapshot.
		const strict = createWBAKeyResolver({
			scheme: "http", fetch: loopbackFetch,
			requireRevocation: true,
			now: () => ANCHOR_MS,
		});
		const rejects = expect(strict.resolve(k.tp, origin.url)).rejects;
		await rejects.toBeInstanceOf(RevocationUnevaluated);
		// Unevaluated must be distinct from revoked.
		await rejects.not.toBeInstanceOf(KeyRevoked);
	});

	// Test 12 — no directory (empty Signature-Agent) → unknown (undefined).
	it("returns undefined when no directory is supplied", async () => {
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		expect(await r.resolve("any-thumbprint", "")).toBeUndefined();
	});

	// A malformed (non-empty, unparseable) directory ref → unknown
	// (undefined), DISTINCT from a fetch failure. Malformed cannot name a
	// directory, so it is fall-through, not a fail-closed halt.
	it("returns undefined for a malformed directory reference", async () => {
		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		expect(await r.resolve("any-thumbprint", "http://")).toBeUndefined();
	});

	// Test 13 — a cache hit resolves within TTL even after the origin starts 500ing.
	it("serves a cached directory within TTL even when the origin fails", async () => {
		const k = await makeKey();
		origin = await startOrigin();
		origin.setWBA(wbaFileJson([wbaJwk(k.x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + 10 * HOUR_MS))]));

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, ttlMs: HOUR_MS, now: () => ANCHOR_MS });
		expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub);

		origin.setWBAStatus(500); // origin now fails; cached hit must still succeed
		expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub);
	});

	// Test 14 — a fetch/500 failure throws DirectoryUnavailable, which MUST be
	// distinct from an unknown key (undefined) so a composite fails closed.
	it("throws DirectoryUnavailable on a fetch failure, distinct from an unknown key", async () => {
		origin = await startOrigin();
		origin.setWBAStatus(500);

		const r = createWBAKeyResolver({ scheme: "http", fetch: loopbackFetch, now: () => ANCHOR_MS });
		// Directory outage is a thrown halt, never an undefined fall-through.
		await expect(r.resolve("any-thumbprint", origin.url)).rejects.toBeInstanceOf(
			DirectoryUnavailable,
		);
	});
});

// Test 11 — the background Run poller applies a newly-published revocation
// without a directory re-fetch, driven by the deterministic clock + armed/cycle
// seams (no sleeps).
describe("createWBAKeyResolver.run poller", () => {
	it("applies a revocation published after priming, on the next poll boundary", async () => {
		const k = await makeKey();
		const origin = await startOrigin();
		origin.setWBA(wbaFileJson([longJwk(k.x)], origin.revocationURL()));
		origin.setRevocation(revocationJson(iso(ANCHOR_MS - HOUR_MS), [])); // nothing revoked yet

		const pollIntervalMs = 10_000;
		const clk = new TestClock(ANCHOR_MS);
		const armed = makeSignal();
		const cycled = makeSignal();

		const r = createWBAKeyResolver({
			scheme: "http", fetch: loopbackFetch,
			ttlMs: 100 * HOUR_MS, // never expires during the test → isolate the poller
			pollIntervalMs,
			now: clk.now,
			after: clk.after,
			onPollArmed: armed.fire,
			onPollCycle: cycled.fire,
		});

		const ac = new AbortController();
		void r.run(ac.signal);
		try {
			// Prime the directory + empty revocation snapshot.
			expect(await r.resolve(k.tp, origin.url)).toEqual(k.rawPub);

			// Publish a newer snapshot revoking the key, then cross one poll
			// boundary: wait armed → advance past interval → wait cycle.
			origin.setRevocation(revocationJson(iso(ANCHOR_MS), [k.tp]));
			await armed.wait();
			clk.advance(2 * pollIntervalMs);
			await cycled.wait();

			await expect(r.resolve(k.tp, origin.url)).rejects.toBeInstanceOf(KeyRevoked);
		} finally {
			ac.abort();
			await origin.close();
		}
	});
});

// The WBA anchor wrapper, at the two things that are local to it and that no
// resolver-level case reaches. Both are what its docstring claims and neither was
// covered: the wrapper is module-private, so it is driven here through the poll it
// guards, with a stub transport recording which URLs were actually requested.
describe("the WBA revocation anchor wrapper", () => {
	async function polled(directory: string, revocationURL: string): Promise<string[]> {
		const seen: string[] = [];
		const fetch: FetchLike = async (url) => {
			seen.push(url);
			if (url.includes(WBA_DIRECTORY_PATH)) {
				return {
					status: 200,
					text: async () => JSON.stringify({ keys: [], revocation_url: revocationURL }),
				};
			}
			return {
				status: 200,
				text: async () => JSON.stringify({ as_of: "2026-01-01T00:00:00Z", revoked: [] }),
			};
		};
		const r = createWBAKeyResolver({ scheme: "http", fetch });
		await r.resolve("unknown-thumbprint", directory).catch(() => undefined);
		// De-duplicated: the unknown-thumbprint force-refresh re-reads the directory,
		// so a polled URL legitimately appears more than once. What is under test is
		// WHICH URLs were reached, not how many times.
		return [...new Set(seen.filter((u) => !u.includes(WBA_DIRECTORY_PATH)))];
	}

	// The shared predicate reads a schemeless value as https, which is right for an
	// exchange domain and wrong for a URL a directory published. The wrapper requires
	// an absolute reference so the scheme cannot be invented on the directory's behalf.
	it("does not poll a revocation_url that names no scheme", async () => {
		expect(await polled("a.example", "a.example/rev.json")).toEqual([]);
	});

	// The regression the wrapper was introduced for: an explicit non-default port on
	// both sides must still anchor. A predicate that folded the port away on one side
	// only stopped a directory anchoring its own revocation URL, and a skipped poll
	// leaves a revoked key resolving.
	it("polls a revocation_url that spells the directory's own port out", async () => {
		expect(await polled("a.example:8443", "http://a.example:8443/rev.json")).toEqual([
			"http://a.example:8443/rev.json",
		]);
	});

	// And the guard still holds where it matters.
	it("does not poll a revocation_url on another port of the same name", async () => {
		expect(await polled("a.example:8443", "http://a.example:9443/rev.json")).toEqual([]);
	});
});
