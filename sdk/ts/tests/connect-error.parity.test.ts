// Connect error-envelope parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors the sdk/python sibling test_connect_error_parity.py and the Go leg
// sdk/go/connect/connect_error_corpus_test.go.
//
// error-detail-vectors.json pins the DETAIL's own proto-JSON. This corpus pins the
// ENVELOPE the detail arrives in, which is the form this SDK actually reads: with no
// protobuf binary codec it cannot open a detail's `value` (a base64 Any), so Connect's
// `debug` projection is the only decodable copy.
//
// That projection is lowerCamelCase and no server option changes it — connect-go builds
// it with its own protojson codec at default options — while the response bodies the
// same server emits are snake_case. Reading `debug` with a snake-only schema therefore
// used to return a detail carrying `domain` and `message` (single words spell the same
// either way) and NO typed reason, for a refusal the Exchange had named precisely. The
// failure was silent: the parse succeeded, and the unknown reason block was removed by
// the .strip() forward-compatibility policy that exists for a newer protocol version.
//
// Every vector here was CAPTURED from a real connect-go handler, so the fix is asserted
// against what the wire does rather than against a description of it.
import { describe, it, expect } from "vitest";
import { errorDetailFrom, reason } from "../src/errordetail.ts";
import vectorsFile from "../../go/connect/testdata/connect-error-vectors.json";

type ConnectErrorVector = {
	name: string;
	code: string;
	http_status: number;
	envelope: unknown;
	expect: {
		has_detail: boolean;
		domain: string;
		message: string;
		metadata: Record<string, string> | null;
		reason_field: string;
		reason_enum: string;
	};
};
type VectorsFile = { note: string; vectors: ConnectErrorVector[] };

const vectors = (vectorsFile as VectorsFile).vectors;

describe("sdk/ts reads a Connect error envelope the way the sdk/go oracle does", () => {
	it("connect-error vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`extracts the Go projection: ${v.name}`, () => {
			const detail = errorDetailFrom(v.envelope);

			if (!v.expect.has_detail) {
				expect(detail).toBeNull();
				return;
			}
			expect(detail).not.toBeNull();
			const got = detail as NonNullable<typeof detail>;
			expect(got.domain).toBe(v.expect.domain);
			expect(got.message).toBe(v.expect.message);

			// Metadata keys are the EMITTER's, not the proto's. The corpus carries a
			// deliberately lowerCamelCase key so a normalizer that walked into the map
			// would rewrite it and fail here.
			expect(got.metadata ?? {}).toEqual(v.expect.metadata ?? {});

			const typed = reason(got);
			if (v.expect.reason_field === "") {
				expect(typed).toBeNull();
				return;
			}
			expect(typed).not.toBeNull();
			expect(typed?.field).toBe(v.expect.reason_field);
			expect(typed?.value).toBe(v.expect.reason_enum);
		});
	}

	// The regression itself, stated once in the open rather than only via the corpus. A
	// snake-only read of this envelope parses successfully and reports no reason — which
	// is why nothing caught it before the corpus existed.
	it("decodes the lowerCamelCase debug projection", () => {
		const detail = errorDetailFrom({
			code: "permission_denied",
			message: "balance too low",
			details: [
				{
					type: "ramp.v1.ErrorDetail",
					value: "aWdub3JlZA",
					debug: {
						domain: "ramp.v1.ExchangeService",
						message: "balance too low",
						transactionDenial: { reason: "DENIAL_REASON_INSUFFICIENT_BALANCE" },
					},
				},
			],
		});
		expect(detail).not.toBeNull();
		expect(reason(detail as NonNullable<typeof detail>)).toEqual({
			field: "transaction_denial",
			value: "DENIAL_REASON_INSUFFICIENT_BALANCE",
		});
	});
});
