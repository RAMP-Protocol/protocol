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
import { escapePair } from "../src/host-ref.ts";
import { MAX_BODY_DEPTH, rawNestingDepth } from "../src/jsondepth.ts";
import { RequestIDHeader } from "../src/wire.ts";
import { IDENTITY_ENCODING, refuseUnrequestedEncoding } from "./transport.ts";
import { requireScheme, skipSSRF, ssrfGuard } from "../resolvers/http.ts";
import { RampCallError } from "./errors.ts";
import { concat, reclaim } from "./send.ts";

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

/** The range a TCP port has. A delivery URL naming one outside it names nothing
 * reachable, whatever a URL parser makes of the value. */
const MIN_PORT = 1;
const MAX_PORT = 65535;

/** type "/" subtype over RFC 9110's token characters, lowercased. */
const MEDIA_TYPE_SHAPE = /^[!#$%&'*+.^_`|~0-9a-z-]+\/[!#$%&'*+.^_`|~0-9a-z-]+$/;

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
	 * own; the same obligations come with it — no redirects, the address pin, and a body
	 * whose socket is released even when this leg refuses without reading it. */
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
		vetDialable(op, signedURL);
		const proof = await mintProof(op, signedURL, opts);
		const headers: Record<string, string> = {
			[AGENT_KEY_HEADER]: proof.agentKey,
			"signature-input": proof.signatureInput,
			signature: proof.signature,
			...IDENTITY_ENCODING,
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
			throw dialFailure(op, cause);
		});

		try {
			// Before either branch reads a byte, refusal included: its 4 KiB bound is the
			// tightest here, so it is the one an unnegotiated coding overshoots furthest.
			refuseUnrequestedEncoding(op, response.statusCode, response.headers);

			// A 3xx reached this client only because the dial refused to follow it, so it
			// is a server that did not answer rather than one that declined — the class
			// every failure taxonomy here already documents for a redirect. Checked BEFORE
			// the refusal reader, which would otherwise promote a token out of the redirect
			// body: a 302 carrying {"reason":"moved"} surfaced as though the edge had named
			// a typed refusal.
			if (response.statusCode >= 300 && response.statusCode < 400) {
				throw new RampCallError({
					kind: "unreachable",
					op,
					status: response.statusCode,
					cause: new Error("peer answered with a redirect, which this client does not follow"),
				});
			}
			if (response.statusCode < 200 || response.statusCode >= 300) {
				throw await edgeRefusal(op, response.statusCode, response.body);
			}
			const body = await readBody(op, response.body, maxBytes);
			return {
				url: signedURL,
				mimeType: mimeTypeOf(headerValue(response.headers, "content-type")),
				body,
			};
		} catch (failure) {
			// The answer arrived, and then went wrong: the deadline fired mid-body, or the
			// connection reset under the read. Both raise the dialing library's own error
			// out of the loop, and this leg had no catch of its own — so a caller branching
			// on the contract this package states, that every verb raises RampCallError and
			// nothing else, silently dropped it. Measured before this: a mid-body deadline
			// surfaced as a bare DOMException. The RPC legs route the identical case through
			// their own classifier; this is that, plus the redaction only this leg needs,
			// because a delivery URL carries a live credential in its query.
			throw failure instanceof RampCallError ? failure : dialFailure(op, failure);
		} finally {
			// Every exit, not every throw — including a future one that returns early.
			reclaim(response.body);
		}
	} finally {
		clearTimeout(timer);
	}
}

/**
 * vetDialable refuses a delivery URL this SDK will not dial, before anything is spent on
 * it — which is what makes mintProof's "after the URL has been accepted as dialable" true.
 *
 * THE VALUE'S OWN FAULTS ARE MALFORMED; the dial's refusals are unreachable. That split is
 * the rule all three languages state, and it is stated rather than delegated to whichever
 * URL parser the language ships — the three parsers disagree about what "unparseable" even
 * means, and a class that changes with the parser is not a contract. Measured before this:
 * every refusal here answered unreachable, so a URL that can never parse sat in the
 * retryable class, and it wore the address guard's own reason while doing it.
 *
 * A value fault is: the URL does not parse, it names no scheme or no host, it names a port
 * outside the range a port has, it carries a malformed percent-escape where a parse would
 * unescape one, or it does not re-serialize to itself (mintProof's check, which runs next).
 * Each will refuse identically forever, so a caller must fix the value.
 *
 * The dial's are the rest. The dispatcher's guard is the CONNECTOR: it decides what a
 * hostname may resolve to and never sees a scheme, because by then the URL is already a
 * host and a port. A delivery URL names a host another party chose, carries a live
 * credential in its query and presents a proof of possession of the agent's key in a
 * header, so plaintext here hands both to anyone on the path. Reported as unreachable,
 * matching Go: there the same refusal comes out of the transport, where Fetch reads it as
 * a dial that did not happen.
 *
 * The URL is never echoed, on either side: it carries a live credential in its query.
 */
function vetDialable(op: string, signedURL: string): void {
	let parsed: URL;
	try {
		// WHATWG `new URL` with no base rejects a value naming no scheme, and one naming no
		// host, in the same throw — which is the rule's first two clauses together rather
		// than a parser quirk being inherited.
		parsed = new URL(signedURL);
	} catch {
		throw malformedURL(op, "url is unparseable, or names no scheme or no host");
	}
	// A port outside the range a port has. WHATWG rejects a non-numeric one and one past
	// 65535, and admits 0 — which is a port nothing listens on. Checked rather than left to
	// the parse, because the rule is the rule and not whatever each language's parser
	// happens to refuse; Go and Python check the same range over their own parsers.
	if (parsed.port !== "") {
		const port = Number(parsed.port);
		if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
			throw malformedURL(op, `url names a port outside ${MIN_PORT}-${MAX_PORT}`);
		}
	}
	// Read PER COMPONENT, the way the host rule already reads it: a malformed escape is
	// refused in a path and in a fragment, and admitted in a query, which a parse does not
	// unescape — and a delivery URL's query is exactly where a credential lives. The
	// predicate is the host rule's own, imported rather than restated.
	if (escapePair.test(parsed.pathname) || escapePair.test(parsed.hash)) {
		throw malformedURL(op, "url carries a malformed percent-escape");
	}
	try {
		requireScheme(signedURL);
	} catch (cause) {
		throw dialFailure(op, cause);
	}
}

// malformedURL names a fault in the VALUE without naming the value: a delivery URL's query
// is a live credential, and this reaches a log.
function malformedURL(op: string, what: string): RampCallError {
	return new RampCallError({
		kind: "malformed",
		op,
		cause: new Error(`${what} (value withheld: it carries a live credential)`),
	});
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

/** The edge's refusal token, mapped to its typed reason.
 *
 * The two vocabularies are separate on purpose — the edge is a code-capable worker with
 * no protobuf runtime, so it answers a string — and `ramp.proto` records which token each
 * enum value stands for, beside the value. This table IS that record; it is not derived
 * from the enum's own spelling, and deriving it would be wrong: `expired` names
 * URL_EXPIRED, `pop_expired` names PROOF_EXPIRED, and neither is the enum suffix
 * lowercased. A port that computed the name instead of reading the record typed two of
 * the eleven tokens and silently dropped the rest.
 *
 * `missing_sig` is deliberately ABSENT rather than guessed at: both checkers emit it —
 * the signed-URL check for a missing `sig` parameter and the proof check for a missing
 * Signature header — and the enum has a distinct value for each, so the body does not say
 * which ran. An unmapped token still reaches the caller as the raw refusal string; only
 * the typed reason is withheld, which is the honest outcome when the wire cannot say
 * which failure occurred. The edge's parse-level tokens have no enum value at all. */
const EDGE_REASON_TOKENS: Readonly<Record<string, string>> = {
	// Signed-URL checks.
	expired: "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED",
	missing_exp: "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING",
	signature_mismatch: "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH",
	// Proof-of-possession checks.
	missing_agent_key: "RETRIEVAL_AUTH_FAILURE_REASON_AGENT_KEY_MISSING",
	keyid_mismatch: "RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH",
	thumbprint_mismatch: "RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
	pop_missing_created: "RETRIEVAL_AUTH_FAILURE_REASON_PROOF_CREATED_MISSING",
	pop_missing_exp: "RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRY_MISSING",
	pop_expired: "RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED",
	pop_sig_invalid: "RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_INVALID",
};

// retrievalAuthFailureDetailOrUndefined promotes an edge token to the typed reason when
// the protocol records one for it, and answers undefined otherwise. The edge's vocabulary
// and the protocol's are deliberately separate, and this is the single place they meet.
function retrievalAuthFailureDetailOrUndefined(token: string) {
	const named = EDGE_REASON_TOKENS[token];
	if (named === undefined) return undefined;
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
//
// Bounded at the same depth the response reader bounds, and for the same reason: the two
// JSON clients must answer one thing for a document neither of them wrote. The 4 KiB cap
// above does not bound the nesting — 4 KiB of "[" nests four thousand deep — and Python's
// parser raises out of a reader that promises a value at a depth that varies by release.
//
// A body past the bound yields "" rather than a new failure: the fetch has already been
// refused by the edge, and the token is the one part of that refusal the SDK does not own.
// Falling back to the failure class is what this reader already answers for any body it
// cannot interpret.
async function edgeReason(body: AsyncIterable<Uint8Array>): Promise<string> {
	let text: string;
	try {
		text = await readText(body, MAX_ERROR_BODY_BYTES);
	} catch {
		return "";
	}
	if (rawNestingDepth(text) > MAX_BODY_DEPTH) return "";
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
 *
 * The parameters are DISCARDED WITHOUT BEING PARSED, and the media type's shape is checked
 * rather than delegated to a parser, because the three SDKs must answer one thing for one
 * header. Go's stdlib parser reports a malformed PARAMETER as an error beside a perfectly
 * good media type — honouring that answers "unknown" for `text/plain; ;`, discarding the one
 * thing the field carries because of the part this is defined to ignore — and it accepts a
 * bare token with no slash, which is not a media type at all. The rule is stated instead:
 * the text before the first `;`, trimmed and lowercased, must be token "/" token over RFC
 * 9110's token characters.
 */
export function mimeTypeOf(header: string | undefined): string {
	if (header === undefined || header === "") return DEFAULT_CONTENT_MIME_TYPE;
	const mediaType = header.split(";", 1)[0]?.trim().toLowerCase() ?? "";
	return MEDIA_TYPE_SHAPE.test(mediaType) ? mediaType : DEFAULT_CONTENT_MIME_TYPE;
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
//
// It returns a fresh Error rather than wrapping, which is the point: attaching the original
// as a `cause` would put the URL straight back into anything that walks the chain. So the
// CLASS has to be read off the original before it is discarded — see dialFailure.
function redact(cause: unknown): Error {
	const message = cause instanceof Error ? cause.message : String(cause);
	return new Error(message.replace(/\bhttps?:\/\/\S+/gi, "<url redacted>"));
}

// dialFailure is what a refusal of the DIAL answers, redacted.
//
// It carries NO reason. `reason` holds the peer's own refusal token, and a dial that was
// refused reached no peer — there is nothing for it to carry. This leg used to mint
// "ssrf_guard" here, which put the SDK's own verdict in a field documented across all
// three languages as the peer's; `not_canonical_wire_naming` says outright that it is the
// one place that happens. The shared corpus records `unreachable` for these rows, which is
// what Go and Python already answered.
//
// What that costs is worth naming: an address-pin refusal is a verdict about where this URL
// points and will refuse identically forever, while a momentary blip will not, and after
// this the two are indistinguishable to a caller. None of the three SDKs distinguishes
// them, so the answer is now the same everywhere rather than better in one — telling them
// apart is a change to the shared taxonomy, not to this function.
function dialFailure(op: string, cause: unknown): RampCallError {
	return new RampCallError({
		// A guard refusal is unreachable rather than not_sent, matching what Go answers for
		// the same condition: there it surfaces through the RoundTripper, so the client
		// reads it as a dial that did not happen. Both mean nothing was sent.
		kind: "unreachable",
		op,
		cause: redact(cause),
	});
}

// The delivery leg's dispatcher, guarded like every host chosen by another party and
// built once: an Agent holds a connection pool, so one per fetch would discard every
// kept-alive connection and re-dial for each item of a batch.
let contentDispatcher: Agent | undefined;

function sharedContentDispatcher(): Agent {
	// The address guard, unless the deployment turned it off — the same SKIP_SSRF switch
	// Go reads in NewGuardedTransport and Python in guarded_client. The scheme gate in
	// vetDialable is separate and is NOT covered by that flag.
	contentDispatcher ??= skipSSRF() ? new Agent() : new Agent({ connect: ssrfGuard() });
	return contentDispatcher;
}
