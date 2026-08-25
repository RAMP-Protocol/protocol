// The default dialing seam for the client tier.
//
// It runs on undici, like the resolver tier's transport, with one deliberate difference:
// REDIRECTS ARE REFUSED rather than followed under a cap. The resolvers fetch public
// well-known documents, where following a hop is harmless; every leg here carries a
// credential — an RFC 9421 signature, or a proof of possession bound to one URL — and
// following a 3xx would either replay that credential at a host the peer chose or mint a
// fresh one for it. A 3xx is an answer to report, never a hop to take.
//
// The address pin is composed here rather than accepted already built: this factory takes
// what sits UNDER it, never what replaces it. It matters most on the offer-derived leg,
// where the caller names a domain, the manifest it serves names an endpoint, and a signed
// call then goes there — without the pin one hop down, that is a signed request aimed at
// an arbitrary internal address.
//
// A caller CAN replace this whole factory, by passing their own UnarySend to the client.
// That takes the address pin with it, which is the same latitude the Python client gives
// an injected httpx client and more than Go gives at all. What it does NOT take is the
// scheme gate: that lives in unaryCall, above the send, so no injected dial reaches a
// plaintext endpoint carrying a signature.
//
// An edge runtime with no undici injects its own send. That is the same escape hatch the
// resolver tier offers, and the same obligations come with it: no redirects, no reading
// past the caller's byte bound, and the lifetime of a body it does NOT read — a refusal
// that walks away from an unread stream holds the socket open until the peer hangs up,
// and a peer that never does is the case the guard exists for. See reclaim.

import { Agent, type Dispatcher, request as undiciRequest } from "undici";

import { skipSSRF, ssrfGuard } from "../resolvers/http.ts";
import { RampCallError } from "./errors.ts";
import {
	refuseUnrequestedEncoding,
	type UnaryRequest,
	type UnaryResponse,
	type UnarySend,
} from "./transport.ts";

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
	// The address guard, unless the deployment turned it off — the same SKIP_SSRF switch
	// Go reads in NewGuardedTransport and Python in guarded_client. The scheme gate below
	// is separate and is NOT covered by that flag; ALLOW_INSECURE is its own decision.
	const dispatcher: Dispatcher =
		opts.guarded && !skipSSRF() ? new Agent({ connect: ssrfGuard() }) : new Agent();
	return async (req: UnaryRequest): Promise<UnaryResponse> => {
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
		try {
			// Before a byte is read: a coding the client did not negotiate cannot be
			// bounded, because a decoder expands a whole raw read at once. The headers are
			// only visible here, which is why the check lives in the send rather than
			// beside the decode.
			refuseUnrequestedEncoding(req.op, response.statusCode, response.headers);
			return {
				status: response.statusCode,
				body: await readBounded(response.body, req.maxBytes, req.op),
			};
		} finally {
			reclaim(response.body);
		}
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
	op = "read response",
): Promise<string> {
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
	return new TextDecoder().decode(concat(chunks, total));
}

/**
 * reclaim releases the socket behind a response body that was not read to the end.
 *
 * Every refusal above a read is one of these: the check that rejects a coding, the class
 * that rejects a redirect. Each throws while the body is still mid-stream, and undici
 * cannot return a connection whose response nobody consumed — so the socket stays open
 * until the PEER hangs up, and a peer that never does is exactly the party these guards
 * exist to contain. Measured before this: six refusals left six live sockets, still six
 * after fifteen seconds idle, on a dispatcher the delivery leg shares process-wide. With a
 * bounded pool one refusal wedged it outright and the client's own deadline did not break
 * it.
 *
 * Both siblings get this from an idiom TypeScript has no equivalent of — Go from
 * `defer resp.Body.Close()`, Python from `with … stream()` — so here it is spelled out, in
 * a `finally` rather than at each throw. That placement is the point: the last regression
 * added a throw ABOVE the branch that happened to be doing the reclaiming, and a fix
 * attached to the throws we can currently name would go the same way.
 *
 * DESTROY rather than drain. Reading the body to free the socket would be an unbounded read
 * from a peer whose answer is already refused, and draining under a cap is what undici's
 * `dump` does — but `dump` settles only when the stream closes, so awaiting it hands a peer
 * that trickles control of how long the refusal takes. Nothing is owed to a body that is
 * being discarded.
 *
 * Idempotent, so the paths that already consumed can run through it unharmed: a read that
 * finished has ended, and one that threw mid-iteration was destroyed by the loop's own
 * exit. `destroy` alone would be safe on an ended stream — undici raises the abort only
 * while `endEmitted` is false — but the guard says so where a reader will see it.
 */
export function reclaim(body: {
	readonly destroyed: boolean;
	readonly readableEnded: boolean;
	on: (event: "error", listener: () => void) => unknown;
	destroy: () => void;
}): void {
	if (body.destroyed || body.readableEnded) return;
	// Tearing down a stream that has not ended raises an abort ON that stream, and an
	// "error" nothing is listening for is an uncaught exception in Node — so releasing the
	// socket would take the caller's process down on every refusal, which is worse than the
	// leak. The listener is what makes the teardown survivable, and undici's own discard
	// helper carries the same one for the same reason.
	body.on("error", () => {});
	body.destroy();
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
