// ErrorDetail parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors the sdk/python sibling test_errordetail_parity.py and the Go leg
// sdk/go/helpers/errordetail_corpus_test.go.
//
// The ADR-019 failure envelope — ErrorDetail{domain, message, metadata, typed
// reason oneof} — was, until the shared corpus, built AND read only in sdk/go. The
// edge worker is the READ side of that contract. error-detail-vectors.json carries,
// per vector, the canonical proto-JSON wire form (wire_json) plus the field
// projection a reader MUST extract (domain, message, metadata, reason_field,
// reason_enum), all DERIVED from the real Go faces.
//
// This suite parses each vector's wire_json through the TS reader
// (parseErrorDetail → the generated ErrorDetailSchema) and asserts the extracted
// projection matches the Go oracle: same domain/message, same metadata map
// (order-independent — metadata is an unordered map, which is why the multi-key
// vector exists), and the same typed reason (oneof field + enum NAME) via `reason`.
// A divergence in TS's ErrorDetail decoding fails here, at the replay boundary.
import { describe, it, expect } from "vitest";
import {
	REASON_FIELDS,
	errorDetailFrom,
	parseErrorDetail,
	reason,
} from "../src/errordetail.ts";
import vectorsFile from "../../go/helpers/testdata/error-detail-vectors.json";

type ErrorDetailVector = {
	name: string;
	domain: string;
	message: string;
	metadata: Record<string, string> | null;
	reason_field: string;
	reason_enum: string;
	field_errors: { path: string; error: string }[] | null;
	wire_json: unknown;
};
type VectorsFile = { canonicalization: string; vectors: ErrorDetailVector[] };

const vectors = (vectorsFile as VectorsFile).vectors;

describe("sdk/ts ErrorDetail reader matches the sdk/go oracle vectors", () => {
	it("error-detail vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`reader extracts the Go projection for ${v.name}`, () => {
			const detail = parseErrorDetail(v.wire_json);

			expect(detail.domain ?? "").toBe(v.domain);
			expect(detail.message ?? "").toBe(v.message);
			// metadata is an unordered map; an absent map and an empty map are equal.
			expect(detail.metadata ?? {}).toEqual(v.metadata ?? {});

			const record = detail as Record<string, unknown>;
			const populated = REASON_FIELDS.filter((f) => record[f] != null);
			const got = reason(detail);

			if (v.reason_field === "") {
				expect(populated).toEqual([]);
				expect(got).toBeNull();
			} else {
				// Exactly the recorded oneof member is populated, and only it.
				expect(populated).toEqual([v.reason_field]);
				expect(got).not.toBeNull();
				expect(got?.field).toBe(v.reason_field);
				expect(got?.value).toBe(v.reason_enum);
			}

			// The RegistrationFailure per-member detail, positionally. The empty path
			// is the boundary a decoder most plausibly gets wrong: proto3 omits an
			// empty string, so wire_json carries an entry with no "path" key at all
			// and a reader must still extract "" rather than dropping the entry.
			const rf = detail.registration_failure as
				| { field_errors?: { path?: string; error: string }[] }
				| undefined;
			const gotFieldErrors = (rf?.field_errors ?? []).map((fe) => ({
				path: fe.path ?? "",
				error: fe.error,
			}));
			expect(gotFieldErrors).toEqual(v.field_errors ?? []);
		});
	}

	it("errorDetailFrom locates the ramp.v1.ErrorDetail among a Connect error's details", () => {
		const v = vectors.find((x) => x.reason_field === "transaction_denial");
		expect(v).toBeDefined();
		const connectError = {
			code: "failed_precondition",
			message: v?.message,
			details: [
				{ type: "google.rpc.RetryInfo", debug: { retry_delay: "1s" } },
				{ type: "ramp.v1.ErrorDetail", debug: v?.wire_json },
			],
		};
		const detail = errorDetailFrom(connectError);
		expect(detail).not.toBeNull();
		expect(detail?.domain).toBe(v?.domain);
		expect(reason(detail as NonNullable<typeof detail>)?.value).toBe(v?.reason_enum);
	});

	it("errorDetailFrom returns null when no RAMP detail is present", () => {
		expect(errorDetailFrom({ code: "internal", details: [] })).toBeNull();
		expect(errorDetailFrom([{ type: "google.rpc.RetryInfo", debug: {} }])).toBeNull();
	});
});
