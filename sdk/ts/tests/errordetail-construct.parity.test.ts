// ErrorDetail CONSTRUCT-side parity (TypeScript) — write-half replay of the Go corpus.
//
// Sibling of the read-side errordetail.parity.test.ts and the Python construct leg
// sdk/python/tests/test_errordetail_construct_parity.py. Where the read-side suite
// proves TS can PARSE the shared Go-oracle ErrorDetail wire, this suite proves TS can
// CONSTRUCT it: the 7 typed domain error-detail builders — the TS peers of the Go
// sdk/go/helpers.*Detail constructors (errordetail.go:24-75) — must, from
// (domain, message, reason), emit byte-for-byte the same canonical proto-JSON the Go
// emitter recorded in error-detail-vectors.json.
//
// RED until the builders exist: the 7 builder symbols are not yet exported from
// ../src/errordetail.ts (only the READ half parseErrorDetail/reason/errorDetailFrom
// lives there today), so the dispatched builders are `undefined` and calling one
// throws — the TDD-red anchor of this task. A guard test asserts each is a function,
// making the missing-symbol red explicit.
//
// The replay honors the binding recipe on agentic-content-access:
//   1. detail = <builder for vector.reason family>(domain, message, reason_enum)
//      — arity is exactly (domain, message, reason); the builder sets ONLY the oneof
//      reason block, mirroring Go which omits sub-fields (offer_id, rejected_paths…).
//   2. IF the vector carries metadata, apply it POST-construction (detail.metadata =
//      vector metadata), mirroring the Go emitter. The builder OMITS metadata by
//      design; this is why multi_key_metadata_with_reason does not fail.
//   3. Assert FULL-object equality DIRECT to the Go oracle wire_json.
//
// The corpus today vectors only 2 of the 7 reason families (transaction_denial,
// retrieval_auth_failure); the implement step adds the other 5 vectors + builders.
// This suite iterates over ALL reason-carrying vectors present, so it is red now and
// goes green covering every family the corpus exercises.
import { describe, expect, it } from "vitest";
import vectorsFile from "../../go/helpers/testdata/error-detail-vectors.json";
import {
	catalogRejectionDetail,
	disputeFailureDetail,
	domainVerificationFailureDetail,
	type ErrorDetail,
	registrationFailureDetail,
	retrievalAuthFailureDetail,
	transactionDenialDetail,
	usageReportRejectionDetail,
} from "../src/errordetail.ts";

type ErrorDetailVector = {
	name: string;
	domain: string;
	message: string;
	metadata: Record<string, string> | null;
	reason_field: string;
	reason_enum: string;
	wire_json: unknown;
};
type VectorsFile = { canonicalization: string; vectors: ErrorDetailVector[] };

type Builder = (domain: string, message: string, reason: string) => ErrorDetail;

// reason-oneof family (the vector's reason_field) -> the typed builder that owns it.
// Covers all 7 families even though the corpus vectors only some of them today. The
// cast loosens each builder's narrow reason-enum param to `string` so a vector's
// reason NAME string dispatches without a per-family cast.
const builders = {
	transaction_denial: transactionDenialDetail,
	catalog_rejection: catalogRejectionDetail,
	retrieval_auth_failure: retrievalAuthFailureDetail,
	dispute_failure: disputeFailureDetail,
	registration_failure: registrationFailureDetail,
	domain_verification_failure: domainVerificationFailureDetail,
	usage_report_rejection: usageReportRejectionDetail,
} as Record<string, Builder>;

const vectors = (vectorsFile as VectorsFile).vectors;
const reasonVectors = vectors.filter((v) => v.reason_field !== "");

describe("sdk/ts ErrorDetail builders emit the sdk/go oracle wire", () => {
	it("has at least one reason-carrying vector to replay", () => {
		expect(reasonVectors.length).toBeGreaterThan(0);
	});

	it("exports a builder for every reason family", () => {
		// Pins the 5 families whose corpus vectors the implement step still adds;
		// each must be a real function (missing export -> undefined -> fails here).
		for (const build of Object.values(builders)) {
			expect(typeof build).toBe("function");
		}
	});

	for (const v of reasonVectors) {
		it(`builder emits the Go oracle wire for ${v.name}`, () => {
			const build = builders[v.reason_field];
			// A vector's reason_field MUST have a registered builder; a missing one is
			// a real gap, not a silent skip (also narrows `build` off `| undefined`
			// under noUncheckedIndexedAccess).
			expect(build, `no builder for ${v.reason_field}`).toBeTypeOf("function");
			if (build === undefined)
				throw new Error(`no builder for ${v.reason_field}`);
			// arity is exactly (domain, message, reason); the reason NAME string is
			// validated by the generated schema at construction.
			const detail = build(v.domain, v.message, v.reason_enum) as Record<
				string,
				unknown
			>;
			// metadata is set POST-construction, mirroring the Go emitter; the builder
			// omits it by design.
			if (v.metadata) detail.metadata = v.metadata;

			expect(detail).toEqual(v.wire_json);
		});
	}
});
