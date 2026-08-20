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
import { createUnarySend } from "../client/send.ts";
import type { UnaryRequest } from "../client/transport.ts";

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
	it("does not dial http, and nothing reaches the listener", async () => {
		const [server, port] = await listening();
		let hits = 0;
		server.on("request", () => {
			hits += 1;
		});
		const send = createUnarySend({ guarded: true });
		await expect(
			send(unaryRequest(`http://127.0.0.1:${port}${RPC_PATH}`)),
		).rejects.toThrow(/scheme/i);
		expect(hits, "a signed request reached the listener over plaintext").toBe(0);
		server.close();
	});

	it("refuses a scheme that is not http at all", async () => {
		const send = createUnarySend({ guarded: true });
		await expect(send(unaryRequest("ftp://example.test/x"))).rejects.toThrow(/scheme/i);
	});

	it("but the configured home Exchange keeps its plain transport, as in Go", async () => {
		const [server, port] = await listening();
		const send = createUnarySend({ guarded: false });
		const response = await send(unaryRequest(`http://127.0.0.1:${port}${RPC_PATH}`));
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
