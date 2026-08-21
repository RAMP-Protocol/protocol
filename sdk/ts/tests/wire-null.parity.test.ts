// A null is how the wire spells "no value", and every SDK has to read one.
//
// Replays the Go-emitted null wire-policy corpus (wire-null-vectors.json). This is the
// language the rule was wrong in: the policy seam dropped a null only where the schema
// looked like a message or a map, and the type generator flattens google.protobuf.Timestamp
// to a plain string schema — so an unset timestamp arrived as a null that no longer looked
// like a message, and the whole answer was refused. Go and Python read the same bytes.
//
// The corpus is what makes that one rule rather than three implementations of it. Every
// case here failed before the seam started asking about presence instead of type.
//
// Mirrors sdk/python/tests/test_wire_null_parity.py.

import { describe, expect, it } from "vitest";

import { parseWire } from "../../../gen/ts/wire/base.ts";
import {
	RateLimitInfoSchema,
	ResourceAttestationSchema,
	ResourceResponseSchema,
} from "../../../gen/ts/wire/schemas.ts";
import vectorsFile from "../../go/helpers/testdata/wire-null-vectors.json";

interface WireNullVector {
	name: string;
	message: string;
	wire_json: Record<string, unknown>;
	accepted: boolean;
	note: string;
}

const vectors = (vectorsFile as { vectors: WireNullVector[] }).vectors;

/** The generated schema each case is parsed against, keyed by the corpus's own name for
 * the message. A case naming a schema this suite has not wired up fails rather than being
 * skipped into silence. */
const schemaFor: Record<string, { safeParse: (v: unknown) => { success: boolean } }> = {
	ResourceAttestation: ResourceAttestationSchema,
	RateLimitInfo: RateLimitInfoSchema,
	ResourceResponse: ResourceResponseSchema,
};

describe("the TypeScript wire policy reads what the wire may carry", () => {
	it("vector set is not empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(v.name, () => {
			const schema = schemaFor[v.message];
			expect(schema, `no schema wired for ${v.message}`).toBeDefined();
			const parsed = parseWire<Record<string, unknown>>(
				schema as NonNullable<typeof schema>,
				v.wire_json,
			);
			expect(parsed.success, v.note).toBe(v.accepted);
		});
	}

	// The half a boolean verdict cannot carry. ACCEPTED alone would be satisfied by a parse
	// that took the null and left the field holding anything at all; Go reads it as the
	// field's default, and dropping the null is what lets the schema's own default supply
	// exactly that.
	it("a null on a defaulted field reads as that default, as it does in Go", () => {
		const parsed = parseWire<{ keyid?: unknown }>(ResourceAttestationSchema, {
			keyid: null,
			verifier: "v.test",
		});
		expect(parsed.success).toBe(true);
		expect(parsed.success && parsed.data.keyid).toBe("");
	});

	// The rule is about presence, not about permissiveness: a field the schema requires
	// still refuses a null, which is what keeps this from being "accept anything".
	it("but a null on a field the schema requires is still refused", () => {
		expect(
			parseWire(ResourceResponseSchema, { ver: "1.0", exchange: null }).success,
		).toBe(false);
	});
});
