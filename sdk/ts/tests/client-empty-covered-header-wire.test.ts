// An empty covered header has to reach the WIRE, not just the header map.
//
// The whole point of binding `authorization` and `signature-agent` unconditionally is
// that a verifier rebuilds the signature base from the request it RECEIVED. A value
// bound but never transmitted is not bound at all — the verifier reads the covered
// names off Signature-Input, finds nothing on the wire under one of them, and refuses.
//
// Every other assertion about the emitted set reads a captured object literal from an
// injected send, which proves what the SDK BUILT and says nothing about what left the
// socket. An empty header value is exactly the kind of thing a runtime may decide to
// drop, and if it does, every signed call becomes a rejection while the suite stays
// green. So this one goes through the real dialing seam into a real server and reads
// `req.rawHeaders` — the unparsed name/value pairs as received.
//
// Node only. The edge runtimes named in the docs (Workers, Fastly) host the signed-URL
// edge function, a different surface from the signing client, and cannot be exercised
// from here.
import { createServer, type Server } from "node:http";
import { describe, expect, it } from "vitest";

import { createUnarySend } from "../client/send.ts";
import { unaryCall } from "../client/transport.ts";
import { SignatureAgentHeader } from "../src/wire.ts";

const SIGNATURE_AGENT_LOWER = SignatureAgentHeader.toLowerCase();

/** Answers `{}` and records the raw name/value pairs exactly as received. */
async function recordingServer(): Promise<[Server, number, () => string[]]> {
	let raw: string[] = [];
	const server = createServer((req, res) => {
		raw = req.rawHeaders;
		res.writeHead(200, { "content-type": "application/json" });
		res.end("{}");
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (address === null || typeof address === "string") throw new Error("no port");
	return [server, address.port, () => raw];
}

/** The loopback target is private space; the dial guard is off for this test only. */
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

/** rawHeaders is a flat [name, value, name, value, …] list; collect every line under one name. */
function linesFor(raw: string[], name: string): string[] {
	const out: string[] = [];
	for (let i = 0; i + 1 < raw.length; i += 2) {
		if ((raw[i] as string).toLowerCase() === name) out.push(raw[i + 1] as string);
	}
	return out;
}

describe("an empty covered header survives the transport", () => {
	it("both covered names arrive present-and-empty, exactly once each", async () => {
		const [server, port, raw] = await recordingServer();
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;

		try {
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
					// The static-bootstrap signer: no bearer token and no key directory, so
					// BOTH covered values are empty. This is the shape that never left the
					// socket before, and the shape a request from an agent without a WBA
					// directory takes.
					signer: { privKey: keys.privateKey, keyid: "agent.test.v1" },
				}),
			);

			const received = raw();
			// PRESENT, and empty — not absent. An adapter that drops an empty value would
			// leave zero lines here and every signed call would be refused downstream.
			expect(linesFor(received, "authorization")).toEqual([""]);
			expect(linesFor(received, SIGNATURE_AGENT_LOWER)).toEqual([""]);
			// And exactly ONE line per covered name: two lines under one name join with
			// ", " before the base is rebuilt, which breaks an otherwise valid signature.
			for (const name of [
				"authorization",
				SIGNATURE_AGENT_LOWER,
				"content-digest",
				"signature-input",
				"signature",
			]) {
				expect(linesFor(received, name), `field lines for ${name}`).toHaveLength(1);
			}
		} finally {
			server.close();
		}
	});
});
