// HashURL parity (TypeScript side) (parity guard, djeue).
//
// sdk/ts `hashUrl(signed)` MUST reproduce the sdk/go oracle: SHA-256 over the
// VERBATIM URL bytes (opaque bytes, no WHATWG renormalization), returning the
// raw 32-byte digest (the transaction_log.signed_url_hash). The shared vectors
// at sdk/go/helpers/testdata/hashurl-vectors.json carry {url, sha256_hex}. The
// TS face is async (crypto.subtle.digest); the vector encodes the digest as hex.
//
// These faces now exist; the suite is green and guards cross-language parity.
import { describe, it, expect } from "vitest";
import { hashUrl } from "../src/hashurl.ts";
import vectorsFile from "../../go/helpers/testdata/hashurl-vectors.json";

type HashURLVector = { name: string; url: string; sha256_hex: string };
type HashURLVectorsFile = { vectors: HashURLVector[] };

const vectors = (vectorsFile as HashURLVectorsFile).vectors;

function toHex(bytes: Uint8Array): string {
	let out = "";
	for (let i = 0; i < bytes.length; i += 1)
		out += (bytes[i] as number).toString(16).padStart(2, "0");
	return out;
}

describe("sdk/ts hashUrl matches the sdk/go oracle vectors", () => {
	it("hashurl vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`hex(hashUrl(${v.name})) === ${v.sha256_hex}`, async () => {
			const digest = await hashUrl(v.url);
			expect(digest.length).toBe(32);
			expect(toHex(digest)).toBe(v.sha256_hex);
		});
	}
});
