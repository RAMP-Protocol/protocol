// Cross-language active-Ed25519-key selection parity (TypeScript side).
//
// sdk/ts activeEd25519Key / activeEd25519KeyWithExpiry MUST reproduce the sdk/go
// oracle's document-order selection for EVERY vector in
// sdk/go/resolvers/testdata/active-ed25519-key-vectors.json. Each vector is a WBA
// directory (keys[] with validity windows + JWK `x`), an optional max_scan, and
// the oracle's verdict: the selected key's document-order index (-1 = none), its
// raw public key (base64url), and its not_after.
//
// The corpus is the shared parity lock for the H2 base64 edges (standard-alphabet
// `x`, `=`-padded `x`, valid unpadded `x`) and the C1 timestamp edges (offset-less,
// date-only, empty bounds, the not_before==now / not_after==now half-open
// boundaries), plus the max_scan DoS cap. Replaying it here proves the TS selector
// picks the SAME key the Go oracle did — the divergence the byte-parity contract
// exists to forbid.
import { describe, expect, it } from "vitest";

import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import corpus from "../../go/resolvers/testdata/active-ed25519-key-vectors.json";
import { decodeBase64UrlStrict } from "../src/base64url.ts";
import { activeEd25519Key, activeEd25519KeyWithExpiry } from "../resolvers/index.ts";

interface ActiveKeyJwk {
	kty: string;
	crv: string;
	x: string;
	not_before: string;
	not_after: string;
}
interface ActiveKeyVector {
	label: string;
	note: string;
	max_scan: number | null;
	keys: ActiveKeyJwk[];
	expected_index: number;
	expected_pub: string;
	expected_not_after: string;
}
interface ActiveKeyCorpus {
	now: string;
	vectors: ActiveKeyVector[];
}

const c = corpus as ActiveKeyCorpus;
const NOW = Date.parse(c.now);

function directory(keys: ActiveKeyJwk[]): ReturnType<typeof WBAFileSchema.parse> {
	return WBAFileSchema.parse({ keys });
}

// Call the selector with the vector's max_scan when set, else the default cap.
function select(dir: ReturnType<typeof WBAFileSchema.parse>, v: ActiveKeyVector) {
	return v.max_scan === null
		? activeEd25519Key(dir, NOW)
		: activeEd25519Key(dir, NOW, v.max_scan);
}
function selectWithExpiry(dir: ReturnType<typeof WBAFileSchema.parse>, v: ActiveKeyVector) {
	return v.max_scan === null
		? activeEd25519KeyWithExpiry(dir, NOW)
		: activeEd25519KeyWithExpiry(dir, NOW, v.max_scan);
}

describe("sdk/ts activeEd25519Key matches the sdk/go active-key oracle", () => {
	it("has a non-empty vector corpus", () => {
		expect(c.vectors.length).toBeGreaterThan(0);
	});

	for (const v of c.vectors) {
		it(v.label, () => {
			const dir = directory(v.keys);
			const result = select(dir, v);
			const withExpiry = selectWithExpiry(dir, v);

			if (v.expected_index === -1) {
				expect(result).toBeNull();
				expect(withExpiry).toBeNull();
				return;
			}

			const expectedPub = decodeBase64UrlStrict(v.expected_pub);
			expect(expectedPub).toBeDefined();
			expect(result).toEqual(expectedPub);
			// Document order: the selected bytes are exactly keys[expected_index].x.
			expect(decodeBase64UrlStrict(v.keys[v.expected_index]?.x ?? "")).toEqual(expectedPub);

			expect(withExpiry).not.toBeNull();
			expect(withExpiry?.key).toEqual(expectedPub);
			expect(withExpiry?.notAfter).toBe(Date.parse(v.expected_not_after));
		});
	}
});
