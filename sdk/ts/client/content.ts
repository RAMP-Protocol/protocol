// The content leg: fetching the bytes a signed delivery URL names, presenting the agent
// key that URL is bound to. TS port of sdk/go/resolvers/contentfetch.go.
//
// It lives in this tier because it DIALS, and a retrieval endpoint is chosen by a party
// on the network rather than by configuration — the exact threat shape the guard exists
// to contain. The transport-neutral tiers above stay free of any dialing surface.

import { Agent, type Dispatcher, request as undiciRequest } from "undici";

import { signInbound } from "../core/sign.ts";
import type { Window } from "../core/window.ts";
import { AGENT_KEY_HEADER } from "../src/pop.ts";
import { retrievalAuthFailureDetail } from "../src/errordetail.ts";
import { RequestIDHeader } from "../src/wire.ts";
import { ssrfGuard } from "../resolvers/http.ts";
import { RampCallError } from "./errors.ts";
import { concat } from "./send.ts";

/**
 * DEFAULT_CONTENT_TIMEOUT_MS bounds one content fetch. An agent is blocked on the call
 * that triggered it, so a fetch that has not answered by now is more useful as a reported
 * failure than as a hang.
 */
export const DEFAULT_CONTENT_TIMEOUT_MS = 30_000;

/**
 * DEFAULT_MAX_CONTENT_BYTES caps one fetched body at 8 MiB. A memory bound on the
 * fetching process, not a judgement about how large licensed content may be: the body is
 * buffered whole and held for the life of the call, and a batch fetches one per item.
 */
export const DEFAULT_MAX_CONTENT_BYTES = 8 << 20;

/** How much of a refusal body is read before the edge's reason is parsed out of it. The
 * payload is a small JSON object; anything past this is not a refusal that can be
 * interpreted. */
const MAX_ERROR_BODY_BYTES = 4 << 10;

/** What a body with no usable Content-Type is labelled. Guessing from the bytes would be
 * worse: the caller is told what the publisher said, and "unknown" is a true answer where
 * a sniffed guess might not be. */
const DEFAULT_CONTENT_MIME_TYPE = "application/octet-stream";

/**
 * The shape a refusal token may have.
 *
 * The body this is read from is written by the host just fetched from, and the value is
 * promoted over this SDK's own classification. Unchecked, a publisher could answer any
 * 4 KiB of text and have it render as though the SDK had said it. Anything that is not
 * token-shaped falls back to the failure class, which the SDK does own.
 */
const EDGE_REASON_TOKEN = /^[a-z][a-z0-9_]{0,63}$/;

/** The ErrorDetail domain for a refusal by a delivery edge. It is the failing surface,
 * not the fetched resource: the field is a stable grouping key for tooling, so it names
 * the tier that refused. */
const EDGE_ERROR_DOMAIN = "ramp.v1.Edge";

/** One fetched resource. */
export interface Content {
	/** The signed delivery URL that was fetched, echoed back so a caller correlating a
	 * batch does not have to keep its own map. */
	url: string;
	/** The media type the edge served, parameters stripped. */
	mimeType: string;
	/** The fetched bytes. */
	body: Uint8Array;
}

/** What the content leg needs to mint one proof and dial once. */
export interface ContentFetchOptions {
	/** The agent keypair the delivery URL is bound to. Both halves are required and
	 * neither can be derived from the other: the private half signs, the public half is
	 * presented alongside. */
	keyPair: CryptoKeyPair;
	/** The freshness window stamped on the proof. Short on purpose, and deliberately NOT
	 * the signed URL's own expiry, which can be hours: the proof covers only the method
	 * and the URL, so for as long as the window is open anyone who observes the request
	 * can repeat it. */
	window?: Window;
	timeoutMs?: number;
	maxBytes?: number;
	requestId?: () => string;
	/** The dialing seam, guarded by default. An edge runtime with no undici injects its
	 * own; the same obligations come with it — no redirects, and the address pin. */
	dispatcher?: Dispatcher;
}

/**
 * fetchContent retrieves the content at signedURL, presenting the proof of possession
 * minted for it.
 *
 * Redirects are REFUSED. Following one would either replay a proof bound to the old URL,
 * which the edge's own check rejects, or hand a fresh proof of possession of the agent's
 * key to whatever host the first hop named.
 *
 * The URL is taken as given. Whether it is one this agent bought, and whether its
 * agent_id matches this agent's key, are the CALLER's checks to make — the SDK exports
 * verifyEd25519SignedUrl and the proof-of-possession verifier for exactly that, and
 * running them first turns an edge 403 into a local answer. Worth doing when the URL
 * reached the caller from anywhere but its own execute response: a proof is minted for
 * whatever URL is passed in.
 */
export async function fetchContent(
	signedURL: string,
	opts: ContentFetchOptions,
): Promise<Content> {
	const op = "fetch content";
	const maxBytes = opts.maxBytes ?? DEFAULT_MAX_CONTENT_BYTES;
	const controller = new AbortController();
	// The deadline covers proof minting, not just the round trip: minting may call out to
	// a custody backend bounded only by that backend's own client, and a timeout covering
	// the round trip alone would leave "bounds one content fetch" untrue against a
	// degraded custody service. A batch pays that cost once per item.
	const timer = setTimeout(
		() => controller.abort(),
		opts.timeoutMs ?? DEFAULT_CONTENT_TIMEOUT_MS,
	);
	try {
		const proof = await mintProof(op, signedURL, opts);
		const headers: Record<string, string> = {
			[AGENT_KEY_HEADER]: proof.agentKey,
			"signature-input": proof.signatureInput,
			signature: proof.signature,
		};
		// Stamped BESIDE the proof rather than covered by it: the correlation id
		// identifies the request in two sets of logs, it authorises nothing. It matters on
		// THIS leg in particular — the RPC legs correlate through the transport, which a
		// plain GET never traverses, so without it the delivery fetch is the one leg
		// carrying no id and an edge that mints its own logs a refusal under a value
		// nothing else knows.
		if (opts.requestId !== undefined) headers[RequestIDHeader] = opts.requestId();

		const response = await undiciRequest(signedURL, {
			method: "GET",
			headers,
			signal: controller.signal,
			maxRedirections: 0,
			// The guard is composed here and cannot be handed in already built: a caller
			// supplies what sits UNDER it, never what replaces it. A delivery URL names a
			// host chosen by another party, so the address pin applies in every case.
			dispatcher: opts.dispatcher ?? sharedContentDispatcher(),
		}).catch((cause: unknown) => {
			throw new RampCallError({ kind: "unreachable", op, cause: redact(cause) });
		});

		if (response.statusCode < 200 || response.statusCode >= 300) {
			throw await edgeRefusal(op, response.statusCode, response.body);
		}
		const body = await readBody(op, response.body, maxBytes);
		return {
			url: signedURL,
			mimeType: mimeTypeOf(headerValue(response.headers, "content-type")),
			body,
		};
	} finally {
		clearTimeout(timer);
	}
}

/** The three proof header values one bound fetch presents. */
interface Proof {
	agentKey: string;
	signatureInput: string;
	signature: string;
}

// mintProof signs a GET of the target through the shipped RFC 9421 proof-of-possession
// signer. It reuses core/sign.ts rather than restating the covered-component set, so the
// bytes stay identical to what the edge's verifier reconstructs.
//
// The proof is minted AFTER the URL has been accepted as dialable and BEFORE anything is
// sent, so a URL that cannot be used never costs a signing operation.
async function mintProof(
	op: string,
	signedURL: string,
	opts: ContentFetchOptions,
): Promise<Proof> {
	let request: Request;
	try {
		request = await signInbound(
			opts.keyPair,
			signedURL,
			opts.window !== undefined ? { window: opts.window } : {},
		);
	} catch (cause) {
		// The given URL is deliberately NOT echoed: this error reaches a log, and a
		// delivery URL carries a live credential in its query.
		throw new RampCallError({ kind: "not_signable", op, cause: redact(cause) });
	}
	// The proof covers @target-uri as the VERBATIM string, while the request line carries
	// whatever the URL re-serializes to. The signed-URL contract treats scheme/host/path
	// as opaque bytes, so an Exchange can legitimately mint a URL those two disagree on —
	// a raw space in the path is the reachable case. The signature then cannot verify and
	// the edge reports only an undifferentiated 403, so refusing here names the cause.
	if (request.url !== signedURL) {
		throw new RampCallError({
			kind: "malformed",
			op,
			cause: new Error(
				"url is not round-trip stable: it re-serializes to a different value (value withheld: it carries a live credential)",
			),
		});
	}
	return {
		agentKey: request.headers.get(AGENT_KEY_HEADER) ?? "",
		signatureInput: request.headers.get("signature-input") ?? "",
		signature: request.headers.get("signature") ?? "",
	};
}

// edgeRefusal builds the failure for an edge that answered and said no, promoting the
// edge's own refusal token to a typed protocol reason when the vocabularies line up.
//
// The detail is SYNTHESIZED here rather than received: a delivery edge answers a small
// JSON object, not a protobuf. Its domain names the delivery edge as the failing SURFACE
// — a stable grouping, matching the value the cross-language error-detail corpus already
// uses for this reason block. Deliberately not the fetched URL: domain mirrors
// google.rpc.ErrorInfo.domain so generic tooling can group errors, and a per-URL value
// has unbounded cardinality and groups nothing.
async function edgeRefusal(
	op: string,
	status: number,
	body: AsyncIterable<Uint8Array>,
): Promise<RampCallError> {
	const token = await edgeReason(body);
	const init = {
		kind: "refused" as const,
		op,
		status,
		...(token !== "" ? { reason: token } : {}),
	};
	if (token === "") return new RampCallError(init);
	const detail = retrievalAuthFailureDetailOrUndefined(token);
	return new RampCallError(
		detail !== undefined ? { ...init, detail } : init,
	);
}

// retrievalAuthFailureDetailOrUndefined promotes an edge token to the typed reason when
// it names one of the protocol's own values, and answers undefined otherwise. The edge's
// vocabulary and the protocol's are deliberately separate, and this is the single place
// they meet.
function retrievalAuthFailureDetailOrUndefined(token: string) {
	const upper = token.toUpperCase();
	const named = upper.startsWith("RETRIEVAL_AUTH_FAILURE_REASON_")
		? upper
		: `RETRIEVAL_AUTH_FAILURE_REASON_${upper}`;
	try {
		return retrievalAuthFailureDetail(
			EDGE_ERROR_DOMAIN,
			`delivery refused: ${token}`,
			named as never,
		);
	} catch {
		return undefined;
	}
}

// edgeReason pulls the edge's own refusal token out of a rejection body. The edge answers
// {"error": "...", "reason": "..."} on a binding failure; anything else yields "".
async function edgeReason(body: AsyncIterable<Uint8Array>): Promise<string> {
	let text: string;
	try {
		text = await readText(body, MAX_ERROR_BODY_BYTES);
	} catch {
		return "";
	}
	try {
		const payload: unknown = JSON.parse(text);
		const reason =
			typeof payload === "object" && payload !== null
				? (payload as Record<string, unknown>)["reason"]
				: undefined;
		return typeof reason === "string" && EDGE_REASON_TOKEN.test(reason)
			? reason
			: "";
	} catch {
		return "";
	}
}

// readBody consumes the content under the configured cap, one byte past it so an
// oversized body is DETECTED rather than silently truncated. Truncated content that looks
// whole is worse than a refusal: the caller has paid for it and has no way to tell.
async function readBody(
	op: string,
	body: AsyncIterable<Uint8Array>,
	maxBytes: number,
): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	let total = 0;
	for await (const chunk of body) {
		total += chunk.length;
		if (total > maxBytes) {
			throw new RampCallError({
				kind: "too_large",
				op,
				cause: new Error(`body exceeds the ${maxBytes} byte cap`),
			});
		}
		chunks.push(chunk);
	}
	return concat(chunks, total);
}

async function readText(
	body: AsyncIterable<Uint8Array>,
	maxBytes: number,
): Promise<string> {
	const chunks: Uint8Array[] = [];
	let total = 0;
	for await (const chunk of body) {
		if (total >= maxBytes) break;
		const take = chunk.subarray(0, maxBytes - total);
		total += take.length;
		chunks.push(take);
	}
	return new TextDecoder().decode(concat(chunks, total));
}

/**
 * mimeTypeOf reduces a Content-Type to its media type, dropping parameters such as
 * charset. The charset belongs to whoever decodes the bytes; the content carries the
 * media type alone.
 */
export function mimeTypeOf(header: string | undefined): string {
	if (header === undefined || header === "") return DEFAULT_CONTENT_MIME_TYPE;
	const mediaType = header.split(";", 1)[0]?.trim().toLowerCase() ?? "";
	return mediaType === "" ? DEFAULT_CONTENT_MIME_TYPE : mediaType;
}

function headerValue(
	headers: Record<string, string | string[] | undefined>,
	name: string,
): string | undefined {
	const value = headers[name];
	if (Array.isArray(value)) return value[0];
	return value;
}

// redact strips a credential out of a failure that names the URL it was dialing. For a
// delivery fetch that query IS the credential, and on a refused redirect it is the
// credential of a URL the FIRST HOP chose, so a message carrying it leaks even when this
// module's own wording is already redacted.
function redact(cause: unknown): Error {
	const message = cause instanceof Error ? cause.message : String(cause);
	return new Error(message.replace(/\bhttps?:\/\/\S+/gi, "<url redacted>"));
}

// The delivery leg's dispatcher, guarded like every host chosen by another party and
// built once: an Agent holds a connection pool, so one per fetch would discard every
// kept-alive connection and re-dial for each item of a batch.
let contentDispatcher: Agent | undefined;

function sharedContentDispatcher(): Agent {
	contentDispatcher ??= new Agent({ connect: ssrfGuard() });
	return contentDispatcher;
}
