// The client's typed failure — TS port of sdk/go/connect/callerror.go.
//
// A refusal and a failure are different things, and a caller handles the situations
// differently. It cannot tell them apart from a message, so the class is carried as a
// value.
//
// The one worth naming is: WE refused to send. The routing checks that precede a call to
// an offer-derived address can decline before anything leaves the process, and folding
// that into "unreachable" — as a network timeout — hides the difference between "the
// network is bad" and "the address failed a security check". They call for opposite
// responses.

import type { ErrorDetail } from "../src/errordetail.ts";

/**
 * CallErrorKind classifies why a client call did not produce an answer.
 *
 * - `refused` — a server that answered and said no, with a status and, usually, a typed
 *   reason.
 * - `unreachable` — a server that did not answer: dial failure, timeout, or a redirect
 *   this SDK refused to follow.
 * - `not_sent` — THIS SDK declining to send. The address failed the plain-hostname,
 *   same-host or dial-time guard, so nothing left the process and no signature was
 *   exposed.
 * - `malformed` — a request that could not be built, or an answer that could not be read
 *   as the protocol defines it. Nothing was acted on.
 * - `too_large` — a response body past the configured cap.
 * - `not_signable` — a signature or proof that could not be produced, typically custody
 *   declining or timing out. Nothing left the process.
 * - `unknown` — no classification.
 */
export type CallErrorKind =
	| "refused"
	| "unreachable"
	| "not_sent"
	| "malformed"
	| "too_large"
	| "not_signable"
	| "unknown";

/** What a RampCallError carries beyond its message. */
export interface CallErrorInit {
	kind: CallErrorKind;
	/** The verb that failed, in the SDK's own words ("discover", "fetch content"). */
	op: string;
	/** HTTP status when the peer answered; absent otherwise. */
	status?: number;
	/** The peer's own refusal token when it sent one (a Connect code, an edge reason). */
	reason?: string;
	/** The typed protocol reason when there is one. */
	detail?: ErrorDetail;
	/** The underlying failure, kept so a caller can still reach a custody or resolver
	 * sentinel after the failure has been classified here. */
	cause?: unknown;
}

/**
 * RampCallError is the client's typed failure. Every verb throws this and nothing else,
 * so `instanceof RampCallError` is not a coin flip on the very type callers are told to
 * branch on — which is what happens when a method yields a typed error where it declines
 * to send and a bare transport error where the peer refuses.
 */
export class RampCallError extends Error {
	readonly kind: CallErrorKind;
	readonly op: string;
	readonly status: number | undefined;
	readonly reason: string | undefined;
	readonly detail: ErrorDetail | undefined;

	constructor(init: CallErrorInit) {
		super(renderCallError(init), init.cause !== undefined ? { cause: init.cause } : undefined);
		this.name = "RampCallError";
		this.kind = init.kind;
		this.op = init.op;
		this.status = init.status;
		this.reason = init.reason;
		this.detail = init.detail;
	}

	/**
	 * The most specific machine-readable reason available: the peer's own token when it
	 * sent one, otherwise the failure class.
	 */
	reasonOf(): string {
		return this.reason !== undefined && this.reason !== ""
			? this.reason
			: this.kind;
	}
}

// renderCallError mirrors the Go failure renderer's shape (package, op, class, status,
// reason, cause) so a log line reads the same whichever SDK produced it.
function renderCallError(init: CallErrorInit): string {
	const parts = [`ramp/client: ${init.op}: ${init.kind}`];
	if (init.status !== undefined && init.status !== 0) {
		parts.push(`status ${init.status}`);
	}
	if (init.reason !== undefined && init.reason !== "") {
		parts.push(`reason ${init.reason}`);
	}
	if (init.cause !== undefined) {
		parts.push(String(init.cause instanceof Error ? init.cause.message : init.cause));
	}
	return parts.join(": ");
}

/** The refusal for an address that failed a routing check. Its own constructor because
 * every such refusal must state which check declined and must never carry a status:
 * nothing was sent, so there is nothing to report a status for. */
export function notSent(op: string, cause: unknown): RampCallError {
	return new RampCallError({ kind: "not_sent", op, cause });
}

/** The refusal for a request that could not be assembled, or an answer that could not be
 * read as the protocol defines it. */
export function malformed(op: string, cause: unknown): RampCallError {
	return new RampCallError({ kind: "malformed", op, cause });
}

/**
 * The Connect code a peer answered with, mapped onto the failure class.
 *
 * A peer that answered is a refusal, whatever it said: the distinction a caller needs is
 * "it said no" versus "it never answered", and only the first is worth surfacing a reason
 * for. Three codes land on the second side. `unavailable` is the transport failure
 * proper; `deadline_exceeded` and `canceled` are LOCAL outcomes wearing a Connect code,
 * so neither means the peer reached a verdict — classifying a caller's own cancellation
 * as a refusal would tell it the Exchange declined a call the Exchange may never have
 * seen. `resource_exhausted` is the read cap seen from this side: the peer's answer was
 * larger than the client agreed to read.
 */
/**
 * The Connect code a status implies when the body is not an envelope that names one.
 *
 * connect-go derives the code from the HTTP STATUS in exactly two cases: a body it cannot
 * read as an envelope, and an envelope carrying no code. Both are what a deployment's own
 * infrastructure produces — a gateway draining, a proxy answering with its own HTML page —
 * and the difference between "the Exchange declined this" and "nothing answered" is the
 * whole reason the failure classes exist. Anything not listed is `unknown`, which reads as
 * a refusal.
 *
 * Not a rule invented here: it is connect-go's own table (protocol.go, httpToCode), and
 * the transport-failure corpus is captured from a real client so a future change to it is
 * reported rather than mirrored by hand.
 */
const STATUS_CODES: Readonly<Record<number, string>> = {
	// A 3xx reached this client only because the send refused to follow it, and every leg
	// refuses. That is a server that did not answer the call, not one that declined it —
	// which is what all three failure taxonomies say a redirect is. connect-go maps these
	// to CodeUnknown, but it never sees one: its transport follows redirects, so the row is
	// unreachable there rather than decided.
	301: "unavailable",
	302: "unavailable",
	303: "unavailable",
	307: "unavailable",
	308: "unavailable",
	400: "internal",
	401: "unauthenticated",
	403: "permission_denied",
	404: "unimplemented",
	429: "unavailable",
	502: "unavailable",
	503: "unavailable",
	504: "unavailable",
};

/** The Connect code a non-envelope answer carries, derived from its status. */
export function connectCodeFromStatus(status: number): string {
	return STATUS_CODES[status] ?? "unknown";
}

export function kindOfConnectCode(code: string): CallErrorKind {
	switch (code) {
		case "unavailable":
		case "deadline_exceeded":
		case "canceled":
			return "unreachable";
		case "resource_exhausted":
			return "too_large";
		default:
			return "refused";
	}
}
