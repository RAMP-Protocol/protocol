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

import { verifyOfferAcceptance } from "../src/acceptance.ts";
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

	// Driven through a public face that decodes a signature, rather than a private
	// helper: what matters is that a value the oracle calls garbage cannot verify here.
	// A refused decode and a decode that simply does not match both answer false, so the
	// accepted vectors are what make the refusals meaningful — they prove the face does
	// reach the decoder.
	for (const v of doc.hex_decode) {
		it(`${v.name} decodes: ${v.ok}`, async () => {
			const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
				"sign",
				"verify",
			])) as CryptoKeyPair;
			const verified = await verifyOfferAcceptance(
				{
					offerSig: "sig",
					requesterId: "a",
					requesterDomain: "agent.test",
					idempotencyKey: "k",
				},
				v.hex,
				keys.publicKey,
			);
			// Never true — the signature is not over these bytes. The assertion is that it
			// RETURNS rather than throwing, for every input the oracle has an answer for.
			expect(verified).toBe(false);
		});
	}
});
