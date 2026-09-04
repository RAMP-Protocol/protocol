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
import { MAX_BODY_DEPTH, rawNestingDepth } from "../src/jsondepth.ts";
import { parseWire, WireNamingError } from "../../../gen/ts/wire/base.ts";
import { requireScheme } from "../resolvers/http.ts";
import {
	ConnectProtocolVersion,
	ConnectProtocolVersionHeader,
	ContentTypeJSON,
	RequestIDHeader,
} from "../src/wire.ts";
import {
	connectCodeFromStatus,
	kindOfConnectCode,
	malformed,
	RampCallError,
} from "./errors.ts";

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
	/** The verb, so a failure raised inside the send names the call rather than the
	 * mechanism — Go and Python both report it. */
	op: string;
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
 * An implementation MUST honour `signal`: the tier above sets the call deadline on it and
 * has no other way to stop a send that never returns. The shipped send passes it to undici.
 *
 * What an implementation is NOT responsible for is the scheme: `unaryCall` refuses a URL it
 * will not dial before this is ever called, so a send cannot admit one by omission. What it
 * DOES take on by replacing the shipped send is the dial-time address pin — the check that
 * a hostname resolves somewhere public — which the default composes and an injected send
 * must compose for itself if it needs one.
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
	/** Whether this leg dials a host another party named — an offer-derived Exchange. The
	 * scheme is gated here rather than inside the send, so replacing the send cannot
	 * remove it. */
	guarded?: boolean;
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
	// Joined through URL, not concatenated: a base carrying a query or a fragment would
	// otherwise swallow the RPC path — "https://x.test?a=1" + "/ramp.v1.…" leaves the path
	// inside the query string, and the call reaches the origin's root.
	const base = target.baseURL.replace(/\/+$/, "");
	const path = `/${target.service}/${target.method}`;
	try {
		const url = new URL(base);
		url.pathname = `${url.pathname.replace(/\/+$/, "")}${path}`;
		url.search = "";
		url.hash = "";
		return url.toString();
	} catch {
		// Not a URL this runtime can parse. Left to the send to refuse, which names the
		// value; failing here would report it as something the caller could fix by
		// changing the RPC instead of the address.
		return `${base}${path}`;
	}
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
	// The scheme, before anything is built for this call. It sits ABOVE the send because
	// `send` is an injectable option: a caller that supplies one replaces the dial, and a
	// gate living inside the default send would leave with it. Go states the same rule the
	// other way round — a caller hands over what sits UNDER the guard, never what replaces
	// it — and the delivery leg already gates here rather than at its dispatcher.
	//
	// Converted HERE rather than left to the catch below, because it runs before the try:
	// refusing early is the point — a URL this client will not dial should cost no body
	// encoding, no timer and no signature. requireScheme raises the resolvers' own
	// SsrfBlockedError, which is deliberate, and this tier is what gives it a class. Every
	// verb throws RampCallError and nothing else; an untyped throw here is one a caller
	// branching on that contract drops silently.
	if (opts.guarded === true) {
		try {
			requireScheme(url);
		} catch (cause) {
			// Unreachable, matching what the delivery leg answers for the identical refusal
			// and what Go answers when the same check fires inside its RoundTripper.
			throw new RampCallError({ kind: "unreachable", op: opts.op, cause });
		}
	}
	const body = encodeBody(opts.op, opts.message);
	const headers: Record<string, string> = {
		"content-type": ContentTypeJSON,
		[ConnectProtocolVersionHeader]: ConnectProtocolVersion,
		...IDENTITY_ENCODING,
	};
	// Stamped BEFORE the signature so the covered headers are written last and nothing
	// here can be mistaken for part of the proof. The correlation id is not covered and is
	// not meant to be: it identifies the request in two sets of logs, it authorises
	// nothing.
	if (opts.requestId !== undefined) headers[RequestIDHeader] = opts.requestId();

	// The deadline COVERS the signature rather than starting after it. Signing may reach a
	// custody backend, and a timer started afterwards would give the send a fresh full
	// budget on top of whatever signing already spent — so "bounds one call" would mean
	// something different depending on how slow custody was. It does not INTERRUPT signing:
	// WebCrypto takes no signal, so what this bounds is the total, which is the property Go
	// gets from passing one context through both. The content leg covers proof minting the
	// same way, and Go pins that with a test of its own.
	const controller = new AbortController();
	const timer = setTimeout(
		() => controller.abort(),
		opts.timeoutMs ?? DEFAULT_CALL_TIMEOUT_MS,
	);
	let response: UnaryResponse;
	try {
		if (opts.signer !== undefined) {
			Object.assign(headers, await signCall(opts.op, url, body, opts.signer));
		}
		response = await opts.send({
			url,
			headers,
			body,
			signal: controller.signal,
			maxBytes: opts.maxBytes ?? DEFAULT_MAX_RPC_READ_BYTES,
			op: opts.op,
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
 * IDENTITY_ENCODING asks the peer for no content coding.
 *
 * Sending nothing is not the same thing: per RFC 9110 §12.5.3 an absent Accept-Encoding
 * means ANY coding is acceptable, and undici does not decode one — so a gzipped answer
 * would arrive as raw octets, fail to parse, and be reported as the peer's fault for
 * something the peer was entitled to do.
 */
export const IDENTITY_ENCODING = { "accept-encoding": "identity" } as const;

/**
 * refuseUnrequestedEncoding refuses a response carrying a content coding we did not ask for.
 *
 * Every leg negotiates identity, so a coding here is the peer answering that negotiation
 * and then ignoring it. It is refused BEFORE the body is read, which is the only bound
 * that holds at any chunk size — a decoder expands a whole raw read at once, so a running
 * total over decoded chunks can be overshot by however much one chunk inflates to. The
 * same check, for the same reason, is what bounds the Python client.
 *
 * `identity` itself is not a coding, and neither is an absent header.
 */
export function refuseUnrequestedEncoding(
	op: string,
	status: number,
	headers: Record<string, string | string[] | undefined>,
): void {
	const raw = headers["content-encoding"];
	const coding = (Array.isArray(raw) ? raw.join(",") : (raw ?? "")).trim().toLowerCase();
	if (coding === "" || coding === "identity") return;
	throw new RampCallError({
		kind: "malformed",
		op,
		status,
		cause: new Error(
			`peer answered with content-encoding "${coding}" after being asked for identity; ` +
				"a coding this client did not negotiate cannot be read under a bound",
		),
	});
}

/**
 * decodeResponse turns one answer into a parsed message, or throws the typed failure.
 *
 * A non-2xx is the Connect error envelope: `{code, message, details}`. The typed reason
 * rides in `details`, which errorDetailFrom reads — including the lowerCamelCase `debug`
 * projection connect-go emits there and no server codec replaces.
 */
export function decodeResponse(op: string, response: UnaryResponse): unknown {
	// A 3xx before anything is read out of the body. Every leg refuses to follow a
	// redirect, so one reaching here is a server that did not answer rather than one that
	// declined — and there is nothing in a redirect body to interpret. Unconditional on
	// purpose: a 302 carrying a Connect envelope would otherwise be read as the peer's own
	// verdict, and connect-go has no answer to mirror here because its transport follows
	// redirects and never surfaces one.
	if (response.status >= 300 && response.status < 400) {
		throw new RampCallError({
			kind: "unreachable",
			op,
			status: response.status,
			cause: new Error("peer answered with a redirect, which this client does not follow"),
		});
	}
	const payload = parseJSON(op, response);
	if (response.status < 200 || response.status >= 300) {
		throw connectEnvelopeError(op, response.status, payload);
	}
	return payload;
}

function parseJSON(op: string, response: UnaryResponse): unknown {
	// Depth BEFORE the parse, and the bound is a CONTRACT rather than a property of this
	// runtime. V8's JSON parser is iterative, so nothing here overflows a stack the way
	// Python's reader does — but "how deep may a document this client did not write be" has
	// to be one answer for both JSON clients, or a peer's answer is readable in one and
	// refused in the other, and nothing says which is right. Go is not bounded here and
	// deliberately so; docs/design-history.md records the difference.
	//
	// The scan is lexical and shared with the registration-schema compiler, which reaches
	// for it against a runtime that does overflow. Counting needs no recursion.
	if (rawNestingDepth(response.body) > MAX_BODY_DEPTH) {
		throw new RampCallError({
			kind: "malformed",
			op,
			status: response.status,
			cause: new Error(`answer nests deeper than ${MAX_BODY_DEPTH} containers`),
		});
	}
	try {
		return JSON.parse(response.body === "" ? "{}" : response.body);
	} catch (cause) {
		// A non-2xx body that is not JSON did not come from the service: it is a gateway, a
		// proxy or a load balancer answering for it. The STATUS is then the only thing that
		// classifies it, which is what connect-go does with the same answer — and calling a
		// momentary 502 malformed would put a retryable outage in the "this peer is broken"
		// class. A 2xx that is not JSON is a different thing: the service claimed to answer
		// and did not, which IS malformed.
		if (response.status < 200 || response.status >= 300) {
			const code = connectCodeFromStatus(response.status);
			throw new RampCallError({
				kind: kindOfConnectCode(code),
				op,
				status: response.status,
				reason: code,
				cause,
			});
		}
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
	// An envelope carrying no code is not a verdict the peer reached, so the STATUS decides
	// the class — which is what connect-go does with the same answer. Reporting a draining
	// gateway's 503 as a refusal tells a caller not to retry a usage report that would
	// succeed a moment later.
	const named = typeof envelope["code"] === "string" ? envelope["code"] : "";
	const code = named === "" ? connectCodeFromStatus(status) : named;
	const detail = errorDetailFrom(envelope);
	return new RampCallError({
		kind: kindOfConnectCode(code),
		op,
		status,
		// The peer's own token, which is the Connect code here. A caller that wants more
		// than the class reads the typed detail.
		reason: code,
		...(detail !== null ? { detail } : {}),
		// The one site that fills peerMessage, because this is the one site holding a
		// detail the PEER emitted. Every other CallError leaves it empty — including
		// the content leg, whose detail this SDK writes itself.
		...(detail?.message !== undefined && detail.message !== ""
			? { peerMessage: detail.message }
			: {}),
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
 * "strict" is the default; a caller that means to probe a server with a deliberately
 * invalid message turns it off.
 *
 * DELIBERATELY STRICTER THAN GO, which defaults to ValidationOff. These two SDKs are the
 * ones handed to external partners, so catching a missing recipient or idempotency key
 * before anything is signed is worth more here than matching the oracle's default. It
 * costs nothing in safety: the Exchange enforces the same rules whatever this says, and
 * the answer coming back is validated either way.
 *
 * And it is a SMALLER check than the Go client's, not an equal one: the generated schema
 * carries field-level rules, while the cross-field CEL rules stay server-authoritative.
 * "Strict" does not mean the same thing in the two places.
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
 * The wire policy — a null means the field has no value, and the lowerCamelCase
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
