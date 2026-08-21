// Two classifications the three languages have to agree on, and one value shape.
//
// Each was a place one language answered differently for a reason nobody chose, and each
// changes what a caller does next: a verdict is final and a transport failure is worth
// retrying, so collapsing them either strands a usage report or retries a refusal forever.
import { describe, expect, it } from "vitest";

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
