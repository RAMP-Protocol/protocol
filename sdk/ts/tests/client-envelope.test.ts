// Envelope details the three clients have to agree on, and one URL join.
//
// Each of these was a place TypeScript answered differently from Go and Python for a
// reason no one had chosen.
import { describe, expect, it } from "vitest";

import { rpcURL } from "../client/transport.ts";

describe("the RPC path is joined onto the base, not concatenated", () => {
	const target = { service: "ramp.v1.ExchangeService", method: "DiscoverResources" };
	const path = "/ramp.v1.ExchangeService/DiscoverResources";

	it("a plain base", () => {
		expect(rpcURL({ ...target, baseURL: "https://x.test" })).toBe(`https://x.test${path}`);
	});

	it("a trailing slash is not doubled", () => {
		expect(rpcURL({ ...target, baseURL: "https://x.test/" })).toBe(`https://x.test${path}`);
	});

	it("a base with a path keeps it", () => {
		expect(rpcURL({ ...target, baseURL: "https://x.test/v1" })).toBe(
			`https://x.test/v1${path}`,
		);
	});

	// Concatenated, this left the RPC path inside the query string and the call reached
	// the origin's root — a signed request at an address nobody chose.
	it("a base carrying a query does not swallow the path", () => {
		const url = new URL(rpcURL({ ...target, baseURL: "https://x.test?a=1" }));
		expect(url.pathname).toBe(path);
		expect(url.search).toBe("");
	});

	it("a base carrying a fragment does not either", () => {
		const url = new URL(rpcURL({ ...target, baseURL: "https://x.test#frag" }));
		expect(url.pathname).toBe(path);
		expect(url.hash).toBe("");
	});
});

describe("an empty pinned idempotency key is no key", () => {
	// `??` treated "" as a value and sent it, which fails the message's own min(1). Go
	// (`!= ""`) and Python (`or`) both fall through to the next source.
	it("falls through to a minted one", async () => {
		const { createClient } = await import("../client/index.ts");
		const seen: Array<Record<string, unknown>> = [];
		// report usage is the offer-derived leg, so it dials through guardedSend.
		const send = async (req: { body: Uint8Array }) => {
			seen.push(JSON.parse(new TextDecoder().decode(req.body)) as Record<string, unknown>);
			return { status: 200, body: JSON.stringify({ ver: "1.0", report_id: "r" }) };
		};
		const client = createClient("https://exchange.test", {
			requester: { id: "a", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" },
			send,
			guardedSend: send,
			endpointResolver: { resolveEndpoint: async (h: string) => `https://${h}` },
		});
		await client.reportUsage(
			{ exchange: "exchange.test", transaction_id: "t-1" },
			{ idempotencyKey: "" },
		);
		const key = seen[0]?.["idempotency_key"];
		expect(typeof key).toBe("string");
		expect(key).not.toBe("");
	});
});
