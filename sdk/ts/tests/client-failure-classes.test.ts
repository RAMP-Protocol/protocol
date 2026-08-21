// Two classifications the three languages have to agree on, and one value shape.
//
// Each was a place one language answered differently for a reason nobody chose, and each
// changes what a caller does next: a verdict is final and a transport failure is worth
// retrying, so collapsing them either strands a usage report or retries a refusal forever.
import { describe, expect, it } from "vitest";

import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

import { Agent } from "undici";

import { RampCallError } from "../client/errors.ts";
import { fetchContent } from "../client/content.ts";
import { decodeResponse } from "../client/transport.ts";

describe("a redirect this client refused to follow", () => {
	// Every leg refuses redirects, so a 3xx reaching the decode means the server did not
	// answer the call rather than declining it — which is what all three failure
	// taxonomies already document a redirect as. connect-go maps these to CodeUnknown but
	// never sees one, because its transport follows them.
	for (const status of [301, 302, 303, 307, 308]) {
		it(`${status} is unreachable, not refused`, () => {
			let thrown: unknown;
			try {
				decodeResponse("discover", { status, body: "" });
			} catch (e) {
				thrown = e;
			}
			expect(thrown).toBeInstanceOf(RampCallError);
			expect((thrown as RampCallError).kind).toBe("unreachable");
		});
	}
});

describe("the DELIVERY leg's own failures", () => {
	// The answer arrives and then goes wrong under the read — the deadline fires mid-body,
	// or the connection resets. Both raise the dialing library's own error, and this leg
	// used to have no catch, so it escaped past every caller branching on the contract this
	// package states. Measured before the fix: a bare DOMException.
	it("classify a mid-body deadline instead of raising the dialer's own error", async () => {
		const body = randomBytes(8 << 20);
		const server = createServer((_req, res) => {
			res.writeHead(200, {
				"content-type": "text/plain",
				"content-length": String(body.length),
			});
			// Headers and a first chunk, then nothing: the read is still open when the
			// client's own deadline fires.
			res.write(body.subarray(0, 1024));
		});
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
		const port = (server.address() as { port: number }).port;
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;

		const saved = process.env["ALLOW_INSECURE"];
		process.env["ALLOW_INSECURE"] = "true";
		let failure: unknown;
		try {
			failure = await fetchContent(`http://127.0.0.1:${port}/x`, {
				keyPair: keys,
				dispatcher: new Agent(),
				timeoutMs: 400,
				maxBytes: 64 << 20,
			}).catch((e: unknown) => e);
		} finally {
			if (saved === undefined) delete process.env["ALLOW_INSECURE"];
			else process.env["ALLOW_INSECURE"] = saved;
			server.closeAllConnections();
			await new Promise<void>((done) => server.close(() => done()));
		}

		expect(
			failure,
			"the dialer's own error escaped a verb that promises RampCallError and nothing else",
		).toBeInstanceOf(RampCallError);
		expect((failure as RampCallError).kind).toBe("unreachable");
		// The refusal reaches a log, and a delivery URL's query is the credential.
		expect(String((failure as RampCallError).cause ?? "")).not.toContain("127.0.0.1");
	}, 20000);
});

describe("a redirect on the DELIVERY leg", () => {
	// The RPC leg was fixed and this one was not, in both ports. Worse than a wrong class:
	// the refusal reader ran first and promoted a token out of the redirect body, so a 302
	// carrying {"reason":"moved"} surfaced as though the edge had named a typed refusal.
	it("is unreachable, and no token is promoted out of its body", async () => {
		const server = createServer((_req, res) => {
			res.writeHead(302, {
				location: "https://elsewhere.test/x",
				"content-type": "application/json",
			});
			res.end('{"reason":"moved"}');
		});
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
		const port = (server.address() as { port: number }).port;
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;

		// An explicit dispatcher rather than SKIP_SSRF: the shared one is built once per
		// process and caches whatever the flag said at first use, so setting it here would
		// leave every later test in this file dialing unguarded. ALLOW_INSECURE is still
		// needed — the scheme pre-flight above the dial reads it, not the dispatcher.
		const saved = process.env["ALLOW_INSECURE"];
		process.env["ALLOW_INSECURE"] = "true";
		const failure = (await fetchContent(`http://127.0.0.1:${port}/x`, {
			keyPair: keys,
			dispatcher: new Agent(),
		}).catch((e: unknown) => e)) as RampCallError;
		if (saved === undefined) delete process.env["ALLOW_INSECURE"];
		else process.env["ALLOW_INSECURE"] = saved;
		server.close();

		expect(failure).toBeInstanceOf(RampCallError);
		expect(failure.kind).toBe("unreachable");
		expect(failure.reason, "a token was promoted out of a redirect body").toBeUndefined();
	}, 20000);
});

describe("a dial the guard refused", () => {
	// The class is read off the original cause BEFORE redaction. Redacting first replaced
	// it with a fresh Error, so an address-pin refusal — a verdict about where this URL
	// points, which will refuse identically forever — was indistinguishable from a
	// momentary blip.
	it("is named, and still does not echo the credential", async () => {
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
		// Loopback is what the address pin refuses; the scheme gate is satisfied by https.
		const failure = (await fetchContent(
			"https://localhost/a?token=live-credential-value",
			{ keyPair: keys },
		).catch((e: unknown) => e)) as RampCallError;

		expect(failure).toBeInstanceOf(RampCallError);
		expect(failure.reason, "the guard's verdict was flattened into a plain failure").toBe(
			"ssrf_guard",
		);
		expect(String(failure.cause ?? "")).not.toContain("live-credential-value");
	});
});
