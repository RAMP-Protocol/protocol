// The client negotiates identity encoding, and refuses a coding it did not ask for.
//
// Mirrors sdk/python/tests/test_client_bounds.py's encoding cases.
//
// Streaming under a running total is not by itself a bound. A decoder expands a whole raw
// read at once, so one decoded chunk can be far past the cap before the total can refuse
// it — measured in Python at 70 MiB of growth against a 1 MiB cap. Refusing a coding the
// client never negotiated is the check that holds at any chunk size.
//
// TypeScript has the same exposure from the other direction: undici does NOT decode a
// content coding, and per RFC 9110 §12.5.3 an absent Accept-Encoding means any coding is
// acceptable — so a client that sent nothing would be handed gzip octets, fail to parse
// them, and report the peer's fault for something the peer was entitled to do.
import { gzipSync } from "node:zlib";
import { createServer, type Server } from "node:http";
import { describe, expect, it } from "vitest";

import { RampCallError } from "../client/errors.ts";
import { fetchContent } from "../client/content.ts";
import { createUnarySend } from "../client/send.ts";
import { unaryCall, type UnaryRequest } from "../client/transport.ts";

/** Serves what the test asks for, and records what the client negotiated. */
async function serving(
	body: Buffer,
	headers: Record<string, string>,
): Promise<[Server, number, () => string | undefined]> {
	let negotiated: string | undefined;
	const server = createServer((req, res) => {
		negotiated = req.headers["accept-encoding"] as string | undefined;
		res.writeHead(200, { "content-type": "application/json", ...headers });
		res.end(body);
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
	return [server, (server.address() as { port: number }).port, () => negotiated];
}

function unaryRequest(url: string): UnaryRequest {
	return {
		url,
		op: "discover",
		headers: { "content-type": "application/json" },
		body: new TextEncoder().encode("{}"),
		signal: new AbortController().signal,
		maxBytes: 1 << 20,
	};
}

async function withLoopback<T>(run: () => Promise<T>): Promise<T> {
	const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
	process.env["SKIP_SSRF"] = "true";
	process.env["ALLOW_INSECURE"] = "true";
	try {
		return await run();
	} finally {
		if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
		else process.env["SKIP_SSRF"] = saved[0];
		if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
		else process.env["ALLOW_INSECURE"] = saved[1];
	}
}

describe("content coding", () => {
	// Driven through unaryCall, which owns the header set: an injected send is handed the
	// headers this tier built, so the negotiation reaches the wire either way.
	it("the client asks for identity rather than sending nothing", async () => {
		const [server, port, negotiated] = await serving(Buffer.from("{}"), {});
		await withLoopback(() =>
			unaryCall({
				op: "discover",
				target: {
					baseURL: `http://127.0.0.1:${port}`,
					service: "ramp.v1.ExchangeService",
					method: "DiscoverResources",
				},
				message: {},
				send: createUnarySend({ guarded: true }),
			}),
		);
		expect(negotiated()).toBe("identity");
		server.close();
	});

	// The delivery leg builds its own header set, so it is asserted separately.
	it("the delivery leg asks for identity too", async () => {
		const [server, port, negotiated] = await serving(Buffer.from("body"), {});
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
		await withLoopback(() =>
			fetchContent(`http://127.0.0.1:${port}/x`, { keyPair: keys }).catch(() => undefined),
		);
		expect(negotiated()).toBe("identity");
		server.close();
	});

	it("a coding the client did not negotiate is refused", async () => {
		// 200 MiB of gzip: undici would hand this back as raw octets, and no running total
		// over them would say anything useful about the answer.
		const bomb = gzipSync(Buffer.alloc(200 * 1024 * 1024, 0x41));
		const [server, port] = await serving(bomb, { "content-encoding": "gzip" });
		const failure = await withLoopback(() =>
			createUnarySend({ guarded: true })(
				unaryRequest(`http://127.0.0.1:${port}/x`),
			).catch((e: unknown) => e),
		);
		expect(failure).toBeInstanceOf(RampCallError);
		expect((failure as RampCallError).kind).toBe("malformed");
		expect(String((failure as RampCallError).cause ?? "")).toContain("content-encoding");
		server.close();
	});

	it("an identity coding, and no coding at all, are both fine", async () => {
		for (const headers of [{ "content-encoding": "identity" }, {}]) {
			const [server, port] = await serving(Buffer.from('{"ver":"1.0"}'), headers);
			const response = await withLoopback(() =>
				createUnarySend({ guarded: true })(unaryRequest(`http://127.0.0.1:${port}/x`)),
			);
			expect(response.status).toBe(200);
			server.close();
		}
	});
});
