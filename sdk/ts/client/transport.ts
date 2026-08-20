// The Connect-unary JSON transport: POST /ramp.v1.<Service>/<Method>, JSON body.
//
// Every RAMP RPC is unary, so this is the whole protocol rather than a subset of it.
// Full Connect framing exists for streaming, which RAMP has none of and would never use,
// and it would drag in a protobuf binary codec this SDK deliberately does not have — the
// Zod/Pydantic decision makes these clients JSON-only by design, not by omission.
//
// What this module owns: the URL, the header set, composing the signing face over the
// body bytes, the response-size bound, the deadline, refusing redirects, and turning a
// non-2xx into the client's typed failure. What it does NOT own: message shapes. Bodies
// are produced and parsed by the generated Zod schemas, which is the same path the
// canonical proto-JSON round-trip gate already proves loss-free against Go protojson.

import { signOutbound } from "../core/signing-transport.ts";
import type { Window } from "../core/window.ts";
import { errorDetailFrom } from "../src/errordetail.ts";
import { parseWire, WireNamingError } from "../../../gen/ts/wire/base.ts";
import {
	ConnectProtocolVersion,
	ConnectProtocolVersionHeader,
	ContentTypeJSON,
	RequestIDHeader,
} from "../src/wire.ts";
import { kindOfConnectCode, malformed, RampCallError } from "./errors.ts";

/**
 * DEFAULT_MAX_RPC_READ_BYTES caps the response body a single RAMP call will read.
 *
 * A RAMP response for a realistic batch is small; the bound is what stops a peer —
 * including one an offer named — spending the caller's memory on its behalf. Mirrors the
 * Go client's DefaultMaxRPCReadBytes.
 */
export const DEFAULT_MAX_RPC_READ_BYTES = 1 << 20; // 1 MiB

/**
 * DEFAULT_CALL_TIMEOUT_MS bounds one call. A RAMP RPC is interactive — something is
 * waiting on the other end — so a request that has not answered by now is more useful as
 * an error than as a hang. Mirrors the Go client's DefaultCallTimeout.
 */
export const DEFAULT_CALL_TIMEOUT_MS = 30_000;

/** One outbound unary request, after the SDK has assembled and signed it. */
export interface UnaryRequest {
	url: string;
	headers: Record<string, string>;
	body: Uint8Array<ArrayBuffer>;
	/** Aborts the send when the call's deadline elapses. */
	signal: AbortSignal;
	/** The body bound the send must not read past. */
	maxBytes: number;
}

/** What a send returns. The body is already read, bounded, as text. */
export interface UnaryResponse {
	status: number;
	body: string;
}

/**
 * The seam the transport dials through. Injected, so an edge runtime supplies its own and
 * a test drives the whole client without a socket.
 *
 * An implementation MUST NOT follow redirects. Following one would re-sign the caller's
 * request for a target the peer chose, after the endpoint check had already passed — a
 * 3xx is an answer to be reported, never a hop to take. It MUST also refuse to read past
 * `maxBytes`, and signal that by throwing a RampCallError of kind `too_large`.
 */
export type UnarySend = (req: UnaryRequest) => Promise<UnaryResponse>;

/** Where a call is addressed: the origin, the fully-qualified service, and the method. */
export interface UnaryTarget {
	baseURL: string;
	service: string;
	method: string;
}

/** The identity a signed call carries. Absent means the call goes out unsigned. */
export interface CallSigner {
	privKey: CryptoKey;
	keyid: string;
	/** The WBA directory origin this client signs as. Covered by the signature even when
	 * empty, so it is passed through verbatim rather than defaulted here. */
	signatureAgent?: string;
	/** The RFC 9421 freshness window. Defaults to the signing transport's own. */
	window?: Window;
}

/** Everything one unary call needs beyond its message. */
export interface UnaryCallOptions {
	target: UnaryTarget;
	op: string;
	/** The request message, already validated by its generated schema. */
	message: unknown;
	send: UnarySend;
	signer?: CallSigner;
	requestId?: () => string;
	maxBytes?: number;
	timeoutMs?: number;
}

/**
 * rpcURL joins an origin to the Connect unary path. The trailing slash is trimmed so a
 * base URL written either way addresses the same method — a doubled slash is a different
 * path to some servers and a 404 from them.
 */
export function rpcURL(target: UnaryTarget): string {
	return `${target.baseURL.replace(/\/+$/, "")}/${target.service}/${target.method}`;
}

/**
 * unaryCall sends one RAMP RPC and returns the peer's answer as parsed JSON.
 *
 * The body is serialized ONCE and the same bytes are signed and sent: RFC 9530
 * Content-Digest covers the exact octets, so re-serializing between signing and sending
 * would produce a digest for a body the peer never received.
 */
export async function unaryCall(opts: UnaryCallOptions): Promise<unknown> {
	const url = rpcURL(opts.target);
	const body = encodeBody(opts.op, opts.message);
	const headers: Record<string, string> = {
		"content-type": ContentTypeJSON,
		[ConnectProtocolVersionHeader]: ConnectProtocolVersion,
	};
	// Stamped BEFORE the signature so the covered headers are written last and nothing
	// here can be mistaken for part of the proof. The correlation id is not covered and is
	// not meant to be: it identifies the request in two sets of logs, it authorises
	// nothing.
	if (opts.requestId !== undefined) headers[RequestIDHeader] = opts.requestId();

	if (opts.signer !== undefined) {
		Object.assign(headers, await signCall(opts.op, url, body, opts.signer));
	}

	const controller = new AbortController();
	const timer = setTimeout(
		() => controller.abort(),
		opts.timeoutMs ?? DEFAULT_CALL_TIMEOUT_MS,
	);
	let response: UnaryResponse;
	try {
		response = await opts.send({
			url,
			headers,
			body,
			signal: controller.signal,
			maxBytes: opts.maxBytes ?? DEFAULT_MAX_RPC_READ_BYTES,
		});
	} catch (cause) {
		throw asCallError(opts.op, cause);
	} finally {
		clearTimeout(timer);
	}
	return decodeResponse(opts.op, response);
}

// encodeBody renders the message as the canonical proto-JSON bytes that get both signed
// and sent. The message is already a parsed generated-schema value, so JSON.stringify is
// the emission — no field names or enum spellings are decided here.
function encodeBody(op: string, message: unknown): Uint8Array<ArrayBuffer> {
	let text: string;
	try {
		text = JSON.stringify(message ?? {});
	} catch (cause) {
		throw malformed(op, cause);
	}
	return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
}

// signCall produces the RFC 9421 headers for this request. A custody failure is
// `not_signable`, matching what the content leg answers for the same missing holder: a
// caller branching on the kind sees one condition under one class, whichever verb met it
// first.
async function signCall(
	op: string,
	url: string,
	body: Uint8Array<ArrayBuffer>,
	signer: CallSigner,
): Promise<Record<string, string>> {
	try {
		const signed = await signOutbound({
			privKey: signer.privKey,
			keyid: signer.keyid,
			method: "POST",
			url,
			body,
			authorization: "",
			signatureAgent: signer.signatureAgent ?? "",
			...(signer.window !== undefined ? { window: signer.window } : {}),
		});
		return signed.headers;
	} catch (cause) {
		throw new RampCallError({ kind: "not_signable", op, cause });
	}
}

// asCallError classifies a failure the send raised. A RampCallError from the send (the
// size cap, most often) is already classified and passes through; anything else is a peer
// that did not answer.
function asCallError(op: string, cause: unknown): RampCallError {
	if (cause instanceof RampCallError) return cause;
	return new RampCallError({ kind: "unreachable", op, cause });
}

/**
 * decodeResponse turns one answer into a parsed message, or throws the typed failure.
 *
 * A non-2xx is the Connect error envelope: `{code, message, details}`. The typed reason
 * rides in `details`, which errorDetailFrom reads — including the lowerCamelCase `debug`
 * projection connect-go emits there and no server codec replaces.
 */
export function decodeResponse(op: string, response: UnaryResponse): unknown {
	const payload = parseJSON(op, response);
	if (response.status < 200 || response.status >= 300) {
		throw connectEnvelopeError(op, response.status, payload);
	}
	return payload;
}

function parseJSON(op: string, response: UnaryResponse): unknown {
	try {
		return JSON.parse(response.body === "" ? "{}" : response.body);
	} catch (cause) {
		// A body that is not JSON is not an answer this protocol defines, whatever the
		// status said. Reported as malformed rather than as the status's own class,
		// because the status is the peer's claim about a body that turned out not to
		// exist.
		throw new RampCallError({
			kind: "malformed",
			op,
			status: response.status,
			cause,
		});
	}
}

function connectEnvelopeError(
	op: string,
	status: number,
	payload: unknown,
): RampCallError {
	const envelope = isRecord(payload) ? payload : {};
	const code = typeof envelope["code"] === "string" ? envelope["code"] : "";
	const detail = errorDetailFrom(envelope);
	return new RampCallError({
		kind: code === "" ? "refused" : kindOfConnectCode(code),
		op,
		status,
		// The peer's own token, which is the Connect code here. A caller that wants more
		// than the class reads the typed detail.
		...(code !== "" ? { reason: code } : {}),
		...(detail !== null ? { detail } : {}),
		cause:
			typeof envelope["message"] === "string" ? envelope["message"] : undefined,
	});
}

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * NOT_CANONICAL_WIRE_NAMING is the reason a peer's answer is refused for spelling its
 * field names the wrong way.
 *
 * It is the SDK's own verdict rather than a token the peer sent, which is the one place
 * that happens: the peer's failure IS that it did not speak the contract, so there is no
 * refusal of its own to carry. Go never produces it — it speaks binary proto, and
 * protojson accepts both spellings on the way in — so this is a value only the JSON
 * clients can observe, not a divergence in the shared failure taxonomy.
 */
export const NOT_CANONICAL_WIRE_NAMING = "not_canonical_wire_naming";

/**
 * Whether a request is checked against its generated schema before it is signed and sent.
 * "strict" is the default, mirroring the Go client. A caller that means to probe a server
 * with a deliberately invalid message turns it off.
 */
export type Validation = "strict" | "off";

/**
 * validateRequest refuses a request the protocol would reject anyway, before it costs a
 * signature and a round trip.
 *
 * The check is FIELD-level, which is what the generated schema carries: the cross-field
 * CEL rules stay server-authoritative, so this is a smaller check than the Go client's
 * protovalidate interceptor, not an equal one. What it does catch is the common case — a
 * required recipient or idempotency key left unset — where the server's only possible
 * answer is a refusal.
 *
 * The validated value is DISCARDED and the caller's own object is what gets sent: a parse
 * fills declared defaults, and sending those would put fields on the wire the caller never
 * set.
 */
export function validateRequest(
	op: string,
	message: unknown,
	schema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
	validation: Validation,
): void {
	if (validation === "off") return;
	if (!parseUnderWirePolicy(op, message, schema).success) {
		throw malformed(
			op,
			new Error("request failed its generated schema; the server could only refuse it"),
		);
	}
}

/**
 * parseMessage validates one answer against its generated schema, after refusing a
 * non-canonical spelling. The schema owns the field names, the enum NAME strings and the
 * proto3 omit-unpopulated shape; nothing about the message is decided here.
 */
export function parseMessage<T>(
	op: string,
	raw: unknown,
	schema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
): T {
	const parsed = parseUnderWirePolicy<T>(op, raw, schema);
	if (!parsed.success) {
		throw malformed(op, new Error("peer answer failed its generated schema"));
	}
	return parsed.data;
}

/**
 * parseUnderWirePolicy runs the generated schema seam and turns its one refusal into this
 * tier's typed failure.
 *
 * The wire policy — an unset message field arrives as null, and the lowerCamelCase
 * json_name alias is refused at every depth — belongs to the schemas, so it lives with
 * them in gen/ts/wire/base.ts and this tier only names what a refusal MEANS to a caller.
 * Every parse of a generated schema in this SDK goes through here; a bare `safeParse`
 * would skip the policy, which the no-direct-parse guard is there to catch.
 */
function parseUnderWirePolicy<T>(
	op: string,
	raw: unknown,
	schema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
): { success: true; data: T } | { success: false } {
	try {
		return parseWire<T>(schema, raw);
	} catch (cause) {
		if (cause instanceof WireNamingError) {
			throw new RampCallError({
				kind: "malformed",
				op,
				reason: NOT_CANONICAL_WIRE_NAMING,
				cause,
			});
		}
		throw cause;
	}
}
