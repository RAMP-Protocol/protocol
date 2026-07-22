import type { z } from "zod";
import type {
	CatalogRejectionReasonSchema,
	DenialReasonSchema,
	DisputeFailureReasonSchema,
	DomainVerificationFailureReasonSchema,
	RegistrationFailureReasonSchema,
	RetrievalAuthFailureReasonSchema,
	UsageReportRejectionReasonSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { ErrorDetailSchema } from "../../../gen/ts/wire/schemas.ts";

// ADR-019 ErrorDetail reader + typed detail builders (both halves of the contract).
//
// RAMP's failure envelope is a typed ErrorDetail attached to the transport error:
// the Connect/gRPC Code is the coarse class, the ErrorDetail oneof carries the
// precise machine-readable reason. Clients branch on the typed reason, never on the
// human `message` string.
//
// READ half — the edge worker is a CONSUMER of Connect error envelopes emitted by
// the Broker / Exchange, so it extracts the ErrorDetail (domain, message, metadata,
// and the typed reason if present) and branches on the reason enum. This is the TS
// peer of the Go client binding's ErrorDetailFrom plus the transport-neutral
// helpers.Reason accessor (sdk/go/connect + sdk/go/helpers).
//
// WRITE half — the seven typed *Detail builders below are the TS peers of the Go
// helpers.*Detail constructors (sdk/go/helpers/errordetail.go). Each builds an
// ErrorDetail carrying exactly one typed reason oneof block from
// (domain, message, reason), mirroring Go one-for-one: the builder sets ONLY the
// reason block and omits the reason message's extra sub-fields (offer_id,
// rejected_paths, …) — a caller that needs them, or metadata, mutates the returned
// object post-construction, exactly as the Go emitter does. A TS service
// now emits the same typed envelope a Go service does; byte-parity of both halves is
// gated by error-detail-vectors.json, replayed in Go + Python + TS.
//
// Construction goes through ErrorDetailSchema.parse (the same generated-schema
// surface parseErrorDetail uses), so the generated schema owns field names, enum
// NAME strings, and the proto3 omit-unpopulated shape — the builders never hand-roll
// canonicalization.
//
// The ErrorDetail wire form is canonical proto-JSON (snake_case field names, enums
// as NAME strings) — the exact shape the generated ErrorDetailSchema parses. Binary
// protobuf is deliberately NOT used: it is not a cross-language primitive
// (protobuf's own caveat), so the shared wire the three SDKs agree on is proto-JSON.

export type ErrorDetail = z.infer<typeof ErrorDetailSchema>;

/** The fully-qualified proto name Connect stamps on an ErrorDetail transport detail. */
export const ERROR_DETAIL_TYPE = "ramp.v1.ErrorDetail";

/**
 * The ErrorDetail `reason` oneof members, in proto field-number order (the same
 * order the Go helpers.Reason accessor walks). Exactly one is populated when a
 * typed reason is present; all are absent for a generic transport-class failure.
 */
export const REASON_FIELDS = [
	"transaction_denial",
	"catalog_rejection",
	"registration_failure",
	"dispute_failure",
	"domain_verification_failure",
	"retrieval_auth_failure",
	"usage_report_rejection",
] as const;

export type ReasonField = (typeof REASON_FIELDS)[number];

/** The extracted typed reason: which oneof family fired, and its enum NAME. */
export interface TypedReason {
	field: ReasonField;
	value: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Parse a canonical proto-JSON ErrorDetail object into the generated model. The
 * payload is the proto-JSON object (snake_case keys, enums as NAME strings). This
 * is the low-level decode the corpus replay exercises and the building block of
 * {@link errorDetailFrom}.
 */
export function parseErrorDetail(payload: unknown): ErrorDetail {
	return ErrorDetailSchema.parse(payload);
}

/**
 * Return the active typed reason (oneof family + enum NAME), or null when no reason
 * is set. Mirrors the Go helpers.Reason accessor so callers branch on the family +
 * value, never on the human message string.
 */
export function reason(detail: ErrorDetail): TypedReason | null {
	const record = detail as Record<string, { reason?: string } | undefined>;
	for (const field of REASON_FIELDS) {
		const block = record[field];
		if (block != null && block.reason != null) {
			return { field, value: block.reason };
		}
	}
	return null;
}

function detailsOf(err: unknown): unknown[] {
	if (Array.isArray(err)) return err;
	if (isRecord(err) && Array.isArray(err["details"])) return err["details"];
	return [];
}

/**
 * Extract the first RAMP ErrorDetail from a Connect error (or its details array).
 * `err` is either a Connect error object (carrying a `details` array) or the
 * details iterable itself. Each detail entry is the Connect wire form
 * `{ "type": "ramp.v1.ErrorDetail", ... }`; the ErrorDetail proto-JSON is read from
 * the entry's `debug` projection (Connect includes it for JSON clients) or from a
 * `value` already decoded to an object. Returns null when `err` carries no
 * ErrorDetail — the TS analog of the Go `(detail, false)`.
 *
 * The opaque binary `value` of a detail is intentionally NOT decoded here: the JSON
 * SDKs have no protobuf binary codec, so they consume the proto-JSON form.
 */
export function errorDetailFrom(err: unknown): ErrorDetail | null {
	for (const entry of detailsOf(err)) {
		if (!isRecord(entry) || entry["type"] !== ERROR_DETAIL_TYPE) continue;
		const debug = entry["debug"];
		const value = entry["value"];
		const payload = isRecord(debug) ? debug : isRecord(value) ? value : null;
		if (payload === null) continue;
		const parsed = ErrorDetailSchema.safeParse(payload);
		if (parsed.success) return parsed.data;
	}
	return null;
}

/** ExecuteTransaction denial reason (the DenialReason enum NAME set). */
export type DenialReason = z.infer<typeof DenialReasonSchema>;
/** Signed-URL / proof-of-possession failure reason. */
export type RetrievalAuthFailureReason = z.infer<
	typeof RetrievalAuthFailureReasonSchema
>;
/** CatalogService rejection reason. */
export type CatalogRejectionReason = z.infer<
	typeof CatalogRejectionReasonSchema
>;
/** Agent/provider registration failure reason. */
export type RegistrationFailureReason = z.infer<
	typeof RegistrationFailureReasonSchema
>;
/** DisputeTransaction filing failure reason. */
export type DisputeFailureReason = z.infer<typeof DisputeFailureReasonSchema>;
/** Domain-verification failure reason. */
export type DomainVerificationFailureReason = z.infer<
	typeof DomainVerificationFailureReasonSchema
>;
/** ReportUsage rejection reason. */
export type UsageReportRejectionReason = z.infer<
	typeof UsageReportRejectionReasonSchema
>;

/**
 * Build an ErrorDetail carrying a typed DenialReason (ExecuteTransaction denial).
 * TS peer of Go `helpers.TransactionDenialDetail`. Sets only the `transaction_denial`
 * reason block; the message's extra sub-fields (offer_id, restriction_mismatches) and
 * metadata are omitted — mutate the returned object post-construction if needed.
 */
export function transactionDenialDetail(
	domain: string,
	message: string,
	reason: DenialReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		transaction_denial: { reason },
	});
}

/**
 * Build an ErrorDetail carrying a typed RetrievalAuthFailureReason.
 * TS peer of Go `helpers.RetrievalAuthFailureDetail` (signed-URL / proof-of-possession
 * check failed).
 */
export function retrievalAuthFailureDetail(
	domain: string,
	message: string,
	reason: RetrievalAuthFailureReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		retrieval_auth_failure: { reason },
	});
}

/**
 * Build an ErrorDetail carrying a typed CatalogRejectionReason.
 * TS peer of Go `helpers.CatalogRejectionDetail`. Sets only the `catalog_rejection`
 * reason block; `rejected_paths` is omitted.
 */
export function catalogRejectionDetail(
	domain: string,
	message: string,
	reason: CatalogRejectionReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		catalog_rejection: { reason },
	});
}

/**
 * Build an ErrorDetail carrying a typed RegistrationFailureReason.
 * TS peer of Go `helpers.RegistrationFailureDetail` (agent/provider registration
 * refused).
 */
export function registrationFailureDetail(
	domain: string,
	message: string,
	reason: RegistrationFailureReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		registration_failure: { reason },
	});
}

/**
 * Build an ErrorDetail carrying a typed DisputeFailureReason.
 * TS peer of Go `helpers.DisputeFailureDetail` (DisputeTransaction filing refused).
 */
export function disputeFailureDetail(
	domain: string,
	message: string,
	reason: DisputeFailureReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		dispute_failure: { reason },
	});
}

/**
 * Build an ErrorDetail carrying a typed DomainVerificationFailureReason.
 * TS peer of Go `helpers.DomainVerificationFailureDetail` (domain verification failed).
 */
export function domainVerificationFailureDetail(
	domain: string,
	message: string,
	reason: DomainVerificationFailureReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		domain_verification_failure: { reason },
	});
}

/**
 * Build an ErrorDetail carrying a typed UsageReportRejectionReason.
 * TS peer of Go `helpers.UsageReportRejectionDetail` (ReportUsage filing rejected).
 */
export function usageReportRejectionDetail(
	domain: string,
	message: string,
	reason: UsageReportRejectionReason,
): ErrorDetail {
	return ErrorDetailSchema.parse({
		domain,
		message,
		usage_report_rejection: { reason },
	});
}
