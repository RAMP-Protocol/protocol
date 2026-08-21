// A refusal above the read must still release the socket behind the body it refused.
//
// Every guard in the client tier that rejects an answer before reading it — the coding
// check, the redirect class — throws while the response is mid-stream. undici cannot
// return a connection whose body nobody consumed, so without an explicit release the
// socket stays open until the peer hangs up, and the peer is the party the guard exists to
// contain. On the delivery leg the dispatcher is shared process-wide, so they accumulate.
//
// WHY THESE BODIES ARE BIG AND RANDOM. A small answer is already buffered whole by the
// time the refusal runs, so no socket can be stranded and the test would pass against the
// unfixed code — a probe built that way is what made an earlier review round conclude,
// wrongly, that there was nothing here. Compressible bytes fail the same way on the coding
// leg: two mebibytes of one repeated byte is about two kilobytes on the wire. So the body
// has to be large enough to still be in flight AND incompressible.
//
// WHAT IS ASSERTED, AND WHY NOT THE OBVIOUS THING. Counting how many connections the
// server accepted cannot tell the two states apart: a stranded socket is never reused, so
// the next request opens a fresh one and the totals match either way. What separates them
// is whether those sockets were CLOSED. Six refusals close six sockets once the release
// lands and none before it, so that count is the property. A live socket survives either
// way — undici holds one idle connection in the pool — and the point is that it does not
// grow with the refusals, so it is bounded rather than required to be zero.
//
// The last case asserts what a caller actually feels instead: with the pool bounded to one
// connection, a single unreleased socket means nothing afterwards can dial at all.

import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { Agent } from "undici";
import { describe, expect, it } from "vitest";

import { fetchContent } from "../client/content.ts";
import { createUnarySend } from "../client/send.ts";
import type { UnaryRequest } from "../client/transport.ts";

/** Incompressible, and past any read buffer: see the header. */
const BIG = randomBytes(2 << 20);
const BIG_GZIP = gzipSync(BIG);

/** What the server saw happen to its connections. */
interface Sockets {
	/** How many were closed — one per released response body. */
	closed: () => number;
	/** How many are still open. Bounded, not zero: undici keeps one idle. */
	live: () => number;
}

/** Idle pool connections that survive a run and do not grow with the refusal count. */
const IDLE_POOL_SLACK = 2;

/**
 * serving stands up a loopback server and reports what its sockets are doing.
 *
 * The counter is on the SERVER side deliberately: it is the one vantage point available
 * for every leg, including the RPC send, which builds its dispatcher internally and
 * exposes no seam a test could bound.
 */
async function serving(
	handler: (path: string) => { status: number; headers: Record<string, string>; body: Buffer },
): Promise<[Server, string, Sockets]> {
	let opened = 0;
	let closed = 0;
	const server = createServer((req, res) => {
		const answer = handler(String(req.url ?? "/"));
		res.writeHead(answer.status, {
			...answer.headers,
			"content-length": String(answer.body.length),
		});
		res.end(answer.body);
	});
	server.on("connection", (socket) => {
		opened++;
		socket.on("close", () => closed++);
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
	const port = (server.address() as { port: number }).port;
	return [
		server,
		`http://127.0.0.1:${port}`,
		{ closed: () => closed, live: () => opened - closed },
	];
}

/**
 * withPlaintext runs against a loopback origin.
 *
 * ALLOW_INSECURE only — never SKIP_SSRF, whose value the delivery leg's shared dispatcher
 * caches at first use and would then impose on every later test in this file. Each case
 * passes its own dispatcher instead. Restored in a finally, so a failing assertion does not
 * leave the flag set for whatever runs next.
 */
async function withPlaintext<T>(run: () => Promise<T>): Promise<T> {
	const saved = process.env["ALLOW_INSECURE"];
	process.env["ALLOW_INSECURE"] = "true";
	try {
		return await run();
	} finally {
		if (saved === undefined) delete process.env["ALLOW_INSECURE"];
		else process.env["ALLOW_INSECURE"] = saved;
	}
}

async function agentKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

/** Sockets close on a later tick than the refusal, so give the event loop one turn. */
async function settle(): Promise<void> {
	await new Promise((done) => setTimeout(done, 250));
}

/** A sentinel that beats a call which never settles, so a wedge fails rather than hangs. */
const WEDGED = Symbol("wedged");
async function within<T>(ms: number, call: Promise<T>): Promise<T | typeof WEDGED> {
	return await Promise.race([
		call,
		new Promise<typeof WEDGED>((done) => setTimeout(() => done(WEDGED), ms)),
	]);
}

const REFUSALS = 6;

describe("a refusal above the read", () => {
	it("does not strand the socket behind a refused redirect", async () => {
		const [server, base, sockets] = await serving(() => ({
			status: 302,
			headers: { location: "https://elsewhere.test/x" },
			body: BIG,
		}));
		try {
			await withPlaintext(async () => {
				const keyPair = await agentKeys();
				const dispatcher = new Agent();
				for (let i = 0; i < REFUSALS; i++) {
					const failure = await fetchContent(`${base}/a${i}`, {
						keyPair,
						dispatcher,
						timeoutMs: 5000,
					}).catch((e: unknown) => e);
					expect(failure).toBeInstanceOf(Error);
				}
				await settle();
				expect(
					sockets.closed(),
					"a refused redirect never released its socket",
				).toBeGreaterThanOrEqual(REFUSALS);
				expect(sockets.live()).toBeLessThanOrEqual(IDLE_POOL_SLACK);
				dispatcher.destroy();
			});
		} finally {
			server.closeAllConnections();
			await new Promise<void>((done) => server.close(() => done()));
		}
	}, 30000);

	it("does not strand the socket behind a refused content coding", async () => {
		const [server, base, sockets] = await serving(() => ({
			status: 200,
			headers: { "content-encoding": "gzip" },
			body: BIG_GZIP,
		}));
		try {
			await withPlaintext(async () => {
				const keyPair = await agentKeys();
				const dispatcher = new Agent();
				for (let i = 0; i < REFUSALS; i++) {
					const failure = await fetchContent(`${base}/a${i}`, {
						keyPair,
						dispatcher,
						timeoutMs: 5000,
					}).catch((e: unknown) => e);
					expect(failure).toBeInstanceOf(Error);
				}
				await settle();
				expect(
					sockets.closed(),
					"a refused coding never released its socket",
				).toBeGreaterThanOrEqual(REFUSALS);
				expect(sockets.live()).toBeLessThanOrEqual(IDLE_POOL_SLACK);
				dispatcher.destroy();
			});
		} finally {
			server.closeAllConnections();
			await new Promise<void>((done) => server.close(() => done()));
		}
	}, 30000);

	// The RPC leg builds its own dispatcher and takes no seam for one, so this case cannot
	// bound the pool the way the delivery cases do. Liveness is the whole signal here.
	it("does not strand the socket behind a refused coding on the RPC leg", async () => {
		const [server, base, sockets] = await serving(() => ({
			status: 200,
			headers: { "content-encoding": "gzip" },
			body: BIG_GZIP,
		}));
		try {
			const send = createUnarySend({ guarded: false });
			for (let i = 0; i < REFUSALS; i++) {
				const req: UnaryRequest = {
					url: `${base}/ramp.v1.ExchangeService/DiscoverResources`,
					headers: { "content-type": "application/json" },
					body: new TextEncoder().encode("{}"),
					signal: new AbortController().signal,
					maxBytes: 1 << 20,
					op: "discover",
				};
				const failure = await send(req).catch((e: unknown) => e);
				expect(failure).toBeInstanceOf(Error);
			}
			await settle();
			expect(
				sockets.closed(),
				"a refused coding never released its socket",
			).toBeGreaterThanOrEqual(REFUSALS);
			expect(sockets.live()).toBeLessThanOrEqual(IDLE_POOL_SLACK);
		} finally {
			server.closeAllConnections();
			await new Promise<void>((done) => server.close(() => done()));
		}
	}, 30000);

	// What a caller actually feels. One refusal is enough: the stranded socket is the only
	// one the pool is allowed, so everything after it queues behind a request that will
	// never complete — and the client's own timeout does not break it, because the call
	// waiting on the pool was never dispatched.
	it("leaves the connection pool usable, so an ordinary fetch still goes through", async () => {
		const [server, base, sockets] = await serving((path) =>
			path.startsWith("/ok")
				? { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("hi") }
				: { status: 302, headers: { location: "https://elsewhere.test/x" }, body: BIG },
		);
		try {
			await withPlaintext(async () => {
				const keyPair = await agentKeys();
				const dispatcher = new Agent({ connections: 1 });
				const refused = await fetchContent(`${base}/refuse`, {
					keyPair,
					dispatcher,
					timeoutMs: 5000,
				}).catch((e: unknown) => e);
				expect(refused).toBeInstanceOf(Error);

				const answer = await within(
					6000,
					fetchContent(`${base}/ok`, { keyPair, dispatcher, timeoutMs: 5000 }),
				);
				expect(answer, "the refusal wedged the pool: nothing after it can dial").not.toBe(
					WEDGED,
				);
				expect(sockets.closed()).toBeGreaterThanOrEqual(1);
				dispatcher.destroy();
			});
		} finally {
			server.closeAllConnections();
			await new Promise<void>((done) => server.close(() => done()));
		}
	}, 30000);
});
