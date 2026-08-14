// The GET-PoP sign face refuses control bytes in the target URI.
//
// The signature base is line-delimited and the target is written into it verbatim,
// so a newline would add or split a component line and the signed bytes would stop
// describing the request a verifier reconstructs. Refused rather than escaped,
// mirroring the Go signer (helpers.SignAgentBinding / ErrInvalidPoPInput). TS
// throws rather than exporting a sentinel, which is the mapped-correct shape per
// the parity map.
//
// Go refuses the same bytes in BOTH the method and the URL; only the URL arm is
// mirrored here because this face always signs GET.

import { describe, expect, it } from "vitest";

import { signInbound } from "../core/sign.ts";

const now = () => 1_700_000_000_000;

async function keypair(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

describe("signInbound refuses control bytes in the target URI", () => {
	const cases: Record<string, string> = {
		newline: 'https://cdn.test/a\n"@authority": evil.test',
		"carriage return": "https://cdn.test/a\r",
		nul: "https://cdn.test/a\x00",
		delete: "https://cdn.test/a\x7f",
	};

	for (const [name, url] of Object.entries(cases)) {
		it(`refuses a ${name}`, async () => {
			const kp = await keypair();
			await expect(
				signInbound(kp, url, { now, ttlSec: 300 }),
			).rejects.toThrow(/control byte/);
		});
	}

	// The refusal is narrow: percent-encoded bytes are not control bytes and must
	// still sign, since the target URI is carried verbatim.
	it("still signs an ordinary and a percent-encoded URL", async () => {
		const kp = await keypair();
		for (const url of [
			"https://cdn.test/a?agent_id=x",
			"https://cdn.test/a%20b%2Fc",
		]) {
			const req = await signInbound(kp, url, { now, ttlSec: 300 });
			expect(req.headers.get("signature-input")).toMatch(/^sig1=/);
		}
	});
});
