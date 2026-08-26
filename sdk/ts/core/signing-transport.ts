// sdk/ts outbound auto-sign transport — the TS sibling of Go
// core.NewSigningTransport (sdk/go/core/transport.go) and Python
// SigningTransport / SignedOutbound (sdk/python/ramp_sdk/signing_transport.py).
//
// Core Invariant: this module is a pure ORCHESTRATION of the already
// byte-parity-locked primitives signRequest / appendSignature (core/sign-request.ts)
// and clockWindow / monotonicWindow (core/window.ts). It stamps EVERY covered header
// at the value that entered the signature base — Content-Digest / Signature-Input /
// Signature, and the Authorization / Signature-Agent whose values may be empty —
// byte-identical to the shared Go/Python oracle, forwards the request body UNMODIFIED,
// and adds NO new crypto and NO new signature-base rendering.
//
// Two faces, mirroring Python's transport-neutral shape (the cleaner fit for TS's
// multi-runtime edge, which has no Go http.RoundTripper):
//   - signOutbound(...): the transport-NEUTRAL header core (Python SignedOutbound
//     sibling) — computes the RFC 9421 headers for one request and returns them
//     with the untouched body. Wraps no client.
//   - createSigningTransport(send, opts): wraps a WHATWG-fetch-shaped outbound seam
//     send(url, init) — buffers the body, computes headers via signOutbound, and
//     forwards the SAME body bytes to send.
//
// Signature-Agent is SET-IF-ABSENT (mirror Go transport.go:143-145, NOT Python's
// always-stamp): TS carries the relay/append chain, where an upstream sig1 already
// covers its own Signature-Agent value and must never be overwritten.

import { SignatureAgentHeader } from "../src/wire.ts";
import {
	appendSignature,
	type PriorSignatures,
	type SignRequestOptions,
	signRequest,
} from "./sign-request.ts";
import { clockWindow, type Window } from "./window.ts";

// The DEFAULT freshness window: clock-derived created + a 5-minute TTL, matching
// Go's `signWindow = 5 * time.Minute` (transport.go:18) — NOT Python's 600s. The
// clock reads seconds (Date.now()/1000); clockWindow floors to Go's .Unix().
const DEFAULT_WINDOW_TTL_SEC = 300;

function defaultWindow(): Window {
	return clockWindow(() => Date.now() / 1000, DEFAULT_WINDOW_TTL_SEC);
}

// Case-insensitive header lookup over a plain header record. Incoming requests may
// spell header names in any case; the covered values (authorization, prior
// Signature state, Signature-Agent) must be read regardless of casing.
function getHeader(
	headers: Record<string, string>,
	name: string,
): string | undefined {
	const lower = name.toLowerCase();
	for (const k of Object.keys(headers)) {
		if (k.toLowerCase() === lower) return headers[k];
	}
	return undefined;
}

/**
 * mergeSigned overlays the signed headers onto the caller's, REPLACING any the caller
 * spelled in a different case rather than letting both survive.
 *
 * A plain spread would not: header names are case-insensitive on the wire, JS object keys
 * are not, so a caller's `Authorization` and a signed `authorization` become two field
 * lines. getHeader above already reads case-insensitively; this is the write side
 * agreeing with it. See docs/design-history.md, "A covered header the peer never receives
 * is not bound".
 */
function mergeSigned(
	callerHeaders: Record<string, string>,
	signedHeaders: Record<string, string>,
): Record<string, string> {
	const claimed = new Set(Object.keys(signedHeaders).map((k) => k.toLowerCase()));
	const merged: Record<string, string> = {};
	for (const [name, value] of Object.entries(callerHeaders)) {
		if (!claimed.has(name.toLowerCase())) merged[name] = value;
	}
	return { ...merged, ...signedHeaders };
}

/** Inputs for signOutbound — the transport-neutral header core. */
export interface SignOutboundOptions {
	privKey: CryptoKey;
	keyid: string;
	method: string;
	url: string;
	// Uint8Array<ArrayBuffer> (never SharedArrayBuffer-backed), matching the
	// sdk/ts WebCrypto convention (core/sign-request.ts, core/verifier.ts).
	body: Uint8Array<ArrayBuffer>;
	authorization: string;
	// The COVERED Signature-Agent value to bind ("" binds an empty header, the
	// no-directory bootstrap path). The transport resolves set-if-absent BEFORE
	// calling — this is the already-resolved value.
	signatureAgent: string;
	// Freshness window; defaults to clockWindow(now, 300s) (Go 5m) when absent.
	window?: Window;
	// appendOnly routes through appendSignature even for a fresh request (relay
	// mode); AppendSignature degrades to a byte-identical sig1 when prior is empty.
	appendOnly?: boolean;
	// Prior signature state carried by the incoming request (the relay/chain path).
	prior?: PriorSignatures;
}

/** The RFC 9421 header set (plus the untouched body) a signed request carries. */
export interface SignedOutbound {
	headers: Record<string, string>;
	body: Uint8Array<ArrayBuffer>;
}

/**
 * signOutbound computes the RFC 9421 Content-Digest / Signature-Input / Signature
 * headers for one outbound request and returns them with the body untouched — the
 * transport-neutral core (Python SignedOutbound sibling). It orchestrates the
 * parity-locked primitives: appendSignature when appendOnly is set OR a prior
 * Signature is present (forwarding chain), signRequest otherwise.
 *
 * It returns EVERY covered header at the value that entered the signature base, empty
 * values included — see the emit below for why. The keys are LOWERCASE, which is the
 * spelling the corpus records and Python emits, and is what lets a merge over a caller's
 * own headers replace rather than duplicate.
 */
export async function signOutbound(
	o: SignOutboundOptions,
): Promise<SignedOutbound> {
	const [created, expires] = (o.window ?? defaultWindow())();
	const signOpts: SignRequestOptions = {
		method: o.method,
		url: o.url,
		body: o.body,
		authorization: o.authorization,
		signatureAgent: o.signatureAgent,
		keyid: o.keyid,
		created,
		expires,
	};
	const prior = o.prior ?? { signatureInput: "", signature: "" };
	const chained = (o.appendOnly ?? false) || prior.signature !== "";
	const signed = chained
		? await appendSignature(o.privKey, prior, signOpts)
		: await signRequest(o.privKey, signOpts);

	// EVERY covered header is emitted, at exactly the value that entered the signature
	// base — empty values included. A verifier rebuilds the base from the request it
	// received, so a value bound but never sent is not bound at all: it reads the covered
	// names off signature-input, finds nothing on the wire under one of them, and refuses.
	// Measured: the covered set binds authorization and signature-agent unconditionally,
	// and a request carrying neither is answered `header "authorization" missing from
	// request` by every conformant verifier — so the ports agreed byte-for-byte with the
	// oracle on what they signed and could not complete a single call.
	//
	// EVERY covered header, at exactly the value that entered the signature base — empty
	// values included. See docs/design-history.md, "A covered header the peer never
	// receives is not bound", for why binding one without sending it is not binding it,
	// and why the emitted key is LOWERCASE (a signed key spelled differently from the
	// caller's survives the merge beside it, putting the name on the wire twice).
	//
	// Taken straight off `signed`, never re-read from `o`: the primitive echoes what it
	// bound, so there is one place the emitted value can come from and no way for the two
	// to drift.
	const headers: Record<string, string> = {
		"content-digest": signed.contentDigest,
		"signature-input": signed.signatureInput,
		signature: signed.signature,
		authorization: signed.authorization,
		[SignatureAgentHeader.toLowerCase()]: signed.signatureAgent,
	};
	return { headers, body: o.body };
}

/** The WHATWG-fetch-shaped outbound request the transport inspects / forwards. */
export interface OutboundInit {
	method?: string;
	headers?: Record<string, string>;
	body?: Uint8Array<ArrayBuffer>;
}

/** The seam createSigningTransport wraps: a WHATWG-fetch-shaped send(url, init). */
export type OutboundSend<R> = (url: string, init: OutboundInit) => Promise<R>;

/** What a sign predicate inspects to decide whether a request is signed. */
export interface OutboundRequest {
	url: string;
	method: string;
	headers: Record<string, string>;
	body: Uint8Array<ArrayBuffer> | undefined;
}

/**
 * Options for createSigningTransport — an idiomatic TS options object, one field per
 * Go WithX (transport.go:47-96). window replaces the default freshness window;
 * appendOnly forces the relay append branch; signatureAgent supplies the covered
 * directory value stamped SET-IF-ABSENT; predicate gates which requests are signed
 * (default: sign every bodied request).
 */
export interface SigningTransportOptions {
	privKey: CryptoKey;
	keyid: string;
	window?: Window;
	appendOnly?: boolean;
	signatureAgent?: string;
	predicate?: (req: OutboundRequest) => boolean;
}

/**
 * createSigningTransport wraps a WHATWG-fetch-shaped send and returns a send with the
 * same shape that auto-signs each outbound request: it buffers the body, computes
 * the RFC 9421 headers via signOutbound, merges them, and forwards the SAME body
 * bytes to the wrapped send. A request with no body — or one the predicate
 * excludes — passes through UNSIGNED (there is nothing to bind a Content-Digest
 * to); that is not an error. A request already carrying a Signature is CHAINED
 * onto (appendSignature), never replaced. Naming stays family-consistent with the
 * newXResolver siblings; the whole-surface newX -> create rename is a separate,
 * broader change, not this module's concern.
 */
export function createSigningTransport<R>(
	send: OutboundSend<R>,
	opts: SigningTransportOptions,
): OutboundSend<R> {
	const window = opts.window ?? defaultWindow();
	return async (url, init) => {
		const body = init.body;
		const method = init.method ?? "GET";
		const headers = init.headers ?? {};

		// No body / predicate-excluded: pass through UNSIGNED, body untouched.
		const excluded =
			opts.predicate !== undefined &&
			!opts.predicate({ url, method, headers, body });
		if (body === undefined || excluded) {
			return send(url, init);
		}

		// Signature-Agent SET-IF-ABSENT: the incoming header (an upstream sig1's
		// covered directory) wins; otherwise the transport stamps its own.
		const existingAgent = getHeader(headers, SignatureAgentHeader);
		const signatureAgent = existingAgent ?? opts.signatureAgent ?? "";

		const prior: PriorSignatures = {
			signatureInput: getHeader(headers, "signature-input") ?? "",
			signature: getHeader(headers, "signature") ?? "",
		};

		const signed = await signOutbound({
			privKey: opts.privKey,
			keyid: opts.keyid,
			method,
			url,
			body,
			authorization: getHeader(headers, "authorization") ?? "",
			signatureAgent,
			window,
			appendOnly: opts.appendOnly ?? false,
			prior,
		});

		// Forward the SAME body bytes (body integrity — buffer for the digest
		// but never consume/replace the payload; Go resets req.Body + GetBody).
		return send(url, {
			...init,
			headers: mergeSigned(headers, signed.headers),
			body,
		});
	};
}
