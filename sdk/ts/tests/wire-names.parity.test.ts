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
