import type { z } from "zod";
import { ErrorDetailSchema } from "../../../gen/ts/wire/schemas.ts";

// ADR-019 ErrorDetail reader (the READ half of the error contract).
//
// RAMP's failure envelope is a typed ErrorDetail attached to the transport error:
// the Connect/gRPC Code is the coarse class, the ErrorDetail oneof carries the
// precise machine-readable reason. Clients branch on the typed reason, never on the
// human `message` string.
//
// The edge worker is a CONSUMER of Connect error envelopes emitted by the
// Broker / Exchange, so it needs the READ direction: extract the ErrorDetail
// (domain, message, metadata, and the typed reason if present) and branch on the
// reason enum. This is the TS peer of the Go client binding's ErrorDetailFrom plus
// the transport-neutral helpers.Reason accessor (sdk/go/connect + sdk/go/helpers).
//
// Reader-only by design: the EMIT/attach half (build an ErrorDetail and stamp it
// onto a *connect.Error) lives server-side in the Go connectserver binding, which
// is where RAMP services classify and emit errors. No TS service currently emits
// ErrorDetail, so a TS builder would have no consumer; the byte-parity that matters
// here is the decode, gated by error-detail-vectors.json.
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
