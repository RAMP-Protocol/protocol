// Idempotency-validate parity (TypeScript side): validateIdempotencyKey mirrors
// the Go oracle — the only rule is non-empty (protocol min_len=1).
//
// sdk/ts `validateIdempotencyKey` MUST reproduce the sdk/go oracle: the ONLY
// rule is non-empty (protocol min_len=1). The shared vectors at
// sdk/go/helpers/testdata/idempotency-validate-vectors.json carry {key, valid}.
// A valid key returns (does not throw); an invalid (empty) key throws.
//
// NOTE: NewIdempotencyKey MINT is random → NOT vector-gated (it is behaviour-
// tested in idempotency.behavior.test.ts). This suite covers only the pure
// deterministic VALIDATE face.
//
// RED now purely because sdk/ts/src/idempotency.ts does not exist yet.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/idempotency.ts does not exist yet (TDD red — missing face).
import { validateIdempotencyKey } from "../src/idempotency.ts";
import vectorsFile from "../../go/helpers/testdata/idempotency-validate-vectors.json";

type IdemVector = { name: string; key: string; valid: boolean };
type IdemVectorsFile = { vectors: IdemVector[] };

const vectors = (vectorsFile as IdemVectorsFile).vectors;

describe("sdk/ts validateIdempotencyKey matches the sdk/go oracle vectors", () => {
	it("idempotency-validate vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		if (v.valid) {
			it(`validateIdempotencyKey(${JSON.stringify(v.key)}) accepts`, () => {
				expect(() => validateIdempotencyKey(v.key)).not.toThrow();
			});
		} else {
			it(`validateIdempotencyKey(${JSON.stringify(v.key)}) rejects (empty)`, () => {
				expect(() => validateIdempotencyKey(v.key)).toThrow();
			});
		}
	}
});
