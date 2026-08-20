// The default dialing seam for the client tier.
//
// It runs on undici, like the resolver tier's transport, with one deliberate difference:
// REDIRECTS ARE REFUSED rather than followed under a cap. The resolvers fetch public
// well-known documents, where following a hop is harmless; every leg here carries a
// credential — an RFC 9421 signature, or a proof of possession bound to one URL — and
// following a 3xx would either replay that credential at a host the peer chose or mint a
// fresh one for it. A 3xx is an answer to report, never a hop to take.
//
// The SSRF guard is composed here and cannot be handed in already built: a caller
// supplies what sits UNDER it, never what replaces it. That matters most on the
// offer-derived leg, where the caller names a domain, the manifest it serves names an
// endpoint, and a signed call then goes there — without the guard one hop down, that is
// a signed request aimed at an arbitrary internal address.
//
// An edge runtime with no undici injects its own send. That is the same escape hatch the
// resolver tier offers, and the same obligations come with it: no redirects, and no
// reading past the caller's byte bound.

import { Agent, type Dispatcher, request as undiciRequest } from "undici";

import { requireScheme, ssrfGuard } from "../resolvers/http.ts";
import { RampCallError } from "./errors.ts";
import type { UnaryRequest, UnaryResponse, UnarySend } from "./transport.ts";

/** How the default send decides whether to dial through the SSRF guard. */
export interface SendOptions {
	/**
	 * Whether the dial-time address guard is applied. It exists for the legs whose host
	 * is chosen by a party on the network — the offer-derived Exchange and the delivery
	 * edge. The home Exchange and the Broker are operator-configured, so their address is
	 * trusted as far as that configuration is.
	 */
	guarded: boolean;
}

/**
 * createUnarySend returns the SDK's own dialing seam.
 *
 * One dispatcher per send, holding the guard connector and no redirect interceptor, so a
 * proxied CONNECT cannot tunnel a private target past the dial guard and a 3xx arrives as
 * an ordinary response this tier can classify.
 */
export function createUnarySend(opts: SendOptions): UnarySend {
	const dispatcher: Dispatcher = opts.guarded
		? new Agent({ connect: ssrfGuard() })
		: new Agent();
	return async (req: UnaryRequest): Promise<UnaryResponse> => {
		// The scheme, before the dial. ssrfGuard above is the connector — it decides what
		// a hostname may resolve to and never sees a scheme, because by then the URL is
		// already a host and a port. Without this the guarded legs, whose host another
		// party named, would carry the RFC 9421 signature over plaintext http.
		if (opts.guarded) requireScheme(req.url);
		const response = await undiciRequest(req.url, {
			method: "POST",
			headers: req.headers,
			body: req.body,
			signal: req.signal,
			dispatcher,
			// undici follows nothing unless the redirect interceptor is composed in, so
			// the refusal is the absence of that interceptor rather than a setting.
			maxRedirections: 0,
		});
		return {
			status: response.statusCode,
			body: await readBounded(response.body, req.maxBytes),
		};
	};
}

/**
 * readBounded consumes a body under the caller's cap.
 *
 * It reads one byte past the cap so an oversized body is DETECTED rather than silently
 * truncated. Truncated content that looks whole is worse than a refusal: a caller has no
 * way to tell it is incomplete, and on the delivery leg it has already paid for it.
 */
export async function readBounded(
	body: AsyncIterable<Uint8Array>,
	maxBytes: number,
): Promise<string> {
	const chunks: Uint8Array[] = [];
	let total = 0;
	for await (const chunk of body) {
		total += chunk.length;
		if (total > maxBytes) {
			throw new RampCallError({
				kind: "too_large",
				op: "read response",
				cause: new Error(`body exceeds the ${maxBytes} byte cap`),
			});
		}
		chunks.push(chunk);
	}
	return new TextDecoder().decode(concat(chunks, total));
}

/** concat joins the read chunks into one buffer. */
export function concat(chunks: Uint8Array[], total: number): Uint8Array {
	const out = new Uint8Array(total);
	let at = 0;
	for (const chunk of chunks) {
		out.set(chunk, at);
		at += chunk.length;
	}
	return out;
}
