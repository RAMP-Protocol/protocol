// Wire-name and hex parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors sdk/python/tests/test_wire_names_parity.py and the Go leg
// sdk/go/helpers/wire_names_corpus_test.go.
//
// Two textual rules every SDK applies to bytes a PEER chose, and that had drifted into one
// transcription per language.
//
// snakeFromJsonName inverts protojson's lowerCamelCase spelling. Three copies existed and
// they did not agree: two tested an ASCII-uppercase predicate and this one tested "not
// equal to its own lowercase", which answer differently for a titlecase character. The
// rule is ASCII A-Z and nothing else, which is exactly what protojson can produce.
//
// Hex is how Offer.signature and the acceptance signature arrive. Go's hex.DecodeString
// and Python's bytes.fromhex refuse a sign, whitespace and an odd length; parseInt
// accepted all three, so this language read a signature where the other two read garbage.
import { describe, expect, it } from "vitest";

import { signOfferAcceptance, verifyOfferAcceptance } from "../src/acceptance.ts";
import { createVerifier } from "../core/verifier.ts";
import { snakeFromJsonName } from "../src/wire-names.ts";
import vectorsFile from "../../go/helpers/testdata/wire-names-vectors.json";

type SnakeVector = { name: string; json_name: string; snake: string };
type HexVector = { name: string; hex: string; ok: boolean; bytes: string };

const doc = vectorsFile as {
	snake_from_json_name: SnakeVector[];
	hex_decode: HexVector[];
};

describe("snake_from_json_name", () => {
	it("the vector set is non-empty", () => {
		expect(doc.snake_from_json_name.length).toBeGreaterThan(0);
	});

	for (const v of doc.snake_from_json_name) {
		it(v.name, () => {
			expect(snakeFromJsonName(v.json_name)).toBe(v.snake);
		});
	}
});

describe("hex decoding refuses what the oracle refuses", () => {
	it("the vector set asserts both outcomes", () => {
		expect(doc.hex_decode.some((v) => v.ok)).toBe(true);
		expect(doc.hex_decode.some((v) => !v.ok)).toBe(true);
	});

	// Driven through the Verifier, whose REJECTION REASON distinguishes the two outcomes:
	// "offer signature is not valid hex" means the decode refused the value, and "offer
	// signature invalid" means it decoded and did not match. Both languages already word it
	// that way, so the corpus is asserted through a public face and nothing new is exported.
	//
	// The earlier version of this replay asserted only that verification returned false,
	// which is true for every vector either way — reverting both hexToBytes copies to the
	// lenient parseInt form left the whole suite green.
	// The ACCEPTANCE decoder is a second copy of the same rule, on a face that answers a
	// plain boolean. A refused decode and a signature that merely does not match both read
	// false, so no vector spliced into a signature can separate them — which is how this
	// half stayed ungated while the offer half was pinned.
	//
	// What separates them is a value a LENIENT decoder reads as the RIGHT bytes. parseInt
	// reads " a" as 0x0a, exactly like "0a", so a genuine signature with one "0a" pair
	// rewritten as " a" verifies under the lenient decoder and is refused by the strict
	// one. That is the mutation this test exists to fail.
	it("a value only a lenient decoder would accept does not verify", async () => {
		const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
		const base = {
			offerSig: "abcd",
			requesterId: "agent-1",
			requesterDomain: "agent.test",
		};

		// Sign until the signature carries an "0a" pair at an even offset.
		let genuine = "";
		let input = { ...base, idempotencyKey: "idem-0" };
		for (let i = 0; i < 200 && genuine === ""; i += 1) {
			input = { ...base, idempotencyKey: `idem-${i}` };
			const hex = await signOfferAcceptance(input, kp.privateKey);
			for (let j = 0; j + 2 <= hex.length; j += 2) {
				if (hex.slice(j, j + 2) === "0a") {
					genuine = hex;
					break;
				}
			}
		}
		expect(genuine, "no signature carried an 0a pair in 200 attempts").not.toBe("");

		// The control: it verifies as issued.
		expect(await verifyOfferAcceptance(input, genuine, kp.publicKey)).toBe(true);

		const at = genuine.indexOf("0a") - (genuine.indexOf("0a") % 2);
		const lenientOnly = `${genuine.slice(0, at)} a${genuine.slice(at + 2)}`;
		expect(lenientOnly).not.toBe(genuine);
		// parseInt(" a", 16) === 0x0a, so a lenient decoder rebuilds the exact signature.
		expect(await verifyOfferAcceptance(input, lenientOnly, kp.publicKey)).toBe(false);
	});

	for (const v of doc.hex_decode) {
		it(`${v.name}: decodes = ${v.ok}`, async () => {
			const verifier = createVerifier("strict", {
				resolve: async () => new Uint8Array(32) as Uint8Array<ArrayBuffer>,
				now: () => 0,
			});
			const sorted = await verifier.sort([
				{ exchange: "e.test", signature: v.hex, expires_at: "2099-01-01T00:00:00Z" },
			]);
			expect(sorted.verified).toHaveLength(0);
			const reason = sorted.rejected[0]?.reason ?? "";
			const refusedTheDecode = reason.includes("not valid hex");
			expect(
				refusedTheDecode,
				`${v.name}: oracle says decodes=${v.ok}, this reader says decodes=${!refusedTheDecode} (${reason})`,
			).toBe(!v.ok);
		});
	}
});
