// A member named `__proto__` is data, not an instruction.
//
// `out[key] = value` invokes the prototype SETTER for that one key: the member is never
// created, and the object silently inherits whatever the peer put there. Both walkers did
// it, and the consequences differed by which one.
//
// In the from-wire inversion it was a fail-open at the offer trust boundary. The member
// vanished from the canonical form, so the JCS bytes were unchanged and the signature still
// verified — `__proto__` was the one name that could be appended to a signed offer for
// free — while the VerifiedOffer handed to the caller answered attacker-chosen values for
// any property the real offer did not own. That is the opposite of what this module's
// header promises: an unknown member is kept verbatim so verification fails CLOSED.
import { describe, expect, it } from "vitest";

import { createVerifier } from "../core/verifier.ts";
import { fromWireOffer } from "../core/wire-canon.ts";
import { signOffer } from "../src/offer-sign.ts";

async function signedOffer(): Promise<[string, Uint8Array<ArrayBuffer>]> {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const pub = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	) as Uint8Array<ArrayBuffer>;
	const offer: Record<string, unknown> = {
		offer_id: "o",
		exchange: "e.test",
		expires_at: "2099-01-01T00:00:00Z",
	};
	const signature = await signOffer(offer, kp.privateKey);
	const body =
		`"offer_id":"o","exchange":"e.test","expires_at":"2099-01-01T00:00:00Z",` +
		`"signature":${JSON.stringify(signature)},"signature_algorithm":"EdDSA"`;
	return [body, pub];
}

const verifierFor = (pub: Uint8Array<ArrayBuffer>) =>
	createVerifier("strict", {
		resolve: async () => pub,
		now: () => Date.parse("2024-01-01T00:00:00Z"),
	});

describe("an appended member cannot ride a signed offer", () => {
	it("the untouched offer still verifies", async () => {
		const [body, pub] = await signedOffer();
		const sorted = await verifierFor(pub).sort([fromWireOffer(JSON.parse(`{${body}}`))]);
		expect(sorted.verified).toHaveLength(1);
	});

	for (const key of ["__proto__", "constructor", "future_field"]) {
		it(`an appended ${key} makes it fail verification`, async () => {
			const [body, pub] = await signedOffer();
			const wire = JSON.parse(`{${body},"${key}":{"pricing":{"model":"PRICING_MODEL_FREE"}}}`);
			const sorted = await verifierFor(pub).sort([fromWireOffer(wire)]);
			expect(sorted.verified, `${key} rode along for free`).toHaveLength(0);
			expect(sorted.rejected).toHaveLength(1);
		});
	}

	it("and nothing the signature did not cover is readable off the result", async () => {
		const [body] = await signedOffer();
		const wire = JSON.parse(
			`{${body},"__proto__":{"pricing":{"model":"PRICING_MODEL_FREE"},"isPaid":false}}`,
		);
		const canonical = fromWireOffer(wire) as Record<string, unknown>;
		// A real own member, so JCS sees it and the signature check does too.
		expect(Object.hasOwn(canonical, "__proto__")).toBe(true);
		// And not a prototype, so nothing is answered that was never sent.
		expect(canonical["pricing"]).toBeUndefined();
		expect(canonical["isPaid"]).toBeUndefined();
		expect(({} as Record<string, unknown>)["isPaid"]).toBeUndefined();
	});
});
