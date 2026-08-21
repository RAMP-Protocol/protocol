// The client tier refuses a scheme it will not dial — the gate the SSRF connector cannot
// make, because by the time a connector runs the URL is already a host and a port.
//
// Go states the same rule in resolvers.NewGuardedTransport's schemeGuardRoundTripper and
// Python in resolvers._http._SchemeGuardTransport, both wrapping the transport so it holds
// for whatever base a caller injected. TypeScript dials undici directly on these two legs,
// so it needs the gate stated at the dial.
//
// The RPC leg is gated only when guarded. That mirrors Go: the configured home Exchange
// gets a plain transport, the offer-derived leg gets NewGuardedTransport. The delivery leg
// is always guarded — its host is always named by another party.
import { createServer, type Server } from "node:http";
import { describe, expect, it } from "vitest";

import { fetchContent } from "../client/content.ts";
import { RampCallError } from "../client/errors.ts";
import { createClient } from "../client/index.ts";
import { createUnarySend } from "../client/send.ts";
import { unaryCall, type UnaryRequest } from "../client/transport.ts";

const RPC_PATH = "/ramp.v1.ExchangeService/DiscoverResources";

function unaryRequest(url: string): UnaryRequest {
	return {
		url,
		op: "discover",
		signal: new AbortController().signal,
		// The header a plaintext dial would put on the wire.
		headers: { "content-type": "application/json", signature: "sig1=:AAAA:" },
		body: new TextEncoder().encode("{}"),
		maxBytes: 1 << 20,
	};
}

async function listening(): Promise<[Server, number]> {
	const server = createServer((_req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end("{}");
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
	return [server, (server.address() as { port: number }).port];
}

describe("the guarded RPC leg refuses plaintext", () => {
	// Driven through unaryCall, which is where the gate lives. It sits ABOVE the send on
	// purpose: `send` is an injectable option, so a gate inside the default dial would
	// leave with it — see the injected-send case below.
	const target = (baseURL: string) => ({
		baseURL,
		service: "ramp.v1.ExchangeService",
		method: "DiscoverResources",
	});

	it("does not dial http, and nothing reaches the listener", async () => {
		const [server, port] = await listening();
		let hits = 0;
		server.on("request", () => {
			hits += 1;
		});
		await expect(
			unaryCall({
				op: "discover",
				target: target(`http://127.0.0.1:${port}`),
				message: {},
				send: createUnarySend({ guarded: true }),
				guarded: true,
			}),
		).rejects.toThrow(/scheme/i);
		expect(hits, "a signed request reached the listener over plaintext").toBe(0);
		server.close();
	});

	it("refuses a scheme that is not http at all", async () => {
		await expect(
			unaryCall({
				op: "discover",
				target: target("ftp://example.test"),
				message: {},
				send: createUnarySend({ guarded: true }),
				guarded: true,
			}),
		).rejects.toThrow(/scheme/i);
	});

	// The finding this arrangement closes: guardedSend is a documented option, and while
	// the gate lived inside createUnarySend, supplying one removed it. A signed usage
	// report reached http://issuer.test.
	it("and an injected send cannot reach a plaintext endpoint either", async () => {
		let dialed = "";
		const client = createClient("https://exchange.test", {
			requester: { id: "a", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" },
			endpointResolver: { resolveEndpoint: async (h: string) => `http://${h}` },
			guardedSend: async (req) => {
				dialed = req.url;
				return { status: 200, body: JSON.stringify({ ver: "1.0", report_id: "r" }) };
			},
		});
		await expect(
			client.reportUsage({ exchange: "issuer.test", transaction_id: "t-1" }),
		).rejects.toThrow(/scheme/i);
		expect(dialed, "the injected send was reached over plaintext").toBe("");
	});

	it("but the configured home Exchange keeps its plain transport, as in Go", async () => {
		const [server, port] = await listening();
		const response = await createUnarySend({ guarded: false })(
			unaryRequest(`http://127.0.0.1:${port}${RPC_PATH}`),
		);
		expect(response.status).toBe(200);
		server.close();
	});
});

describe("the delivery leg refuses plaintext", () => {
	const keyPair = crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);

	it("refuses before a proof is minted, so custody is never called", async () => {
		let minted = 0;
		const watched = {
			// A key pair whose use would be observable: reaching it means the URL was
			// accepted as dialable first, which is the order the code documents.
			get privateKey() {
				minted += 1;
				return undefined as never;
			},
		};
		const err = await fetchContent("http://edge.test/a?token=live-credential", {
			keyPair: watched as never,
		}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(RampCallError);
		expect((err as RampCallError).kind).toBe("unreachable");
		expect(minted, "a proof was minted for a URL that was never dialable").toBe(0);
	});

	it("and does not echo the credential in its message", async () => {
		const err = (await fetchContent("http://edge.test/a?token=live-credential", {
			keyPair: (await keyPair) as CryptoKeyPair,
		}).catch((e: unknown) => e)) as RampCallError;
		expect(String(err.cause ?? "")).not.toContain("live-credential");
	});
});
