// sdk/ts/hono — the OPT-IN server/verify binding over sdk/ts/core, the natural
// adapter for Edge (src/edge/src/app.ts, a SERVER/VERIFIER). It is a thin Hono
// middleware that verifies an inbound RFC 9421 GET proof-of-possession at the HTTP
// seam (where the exact request exists) via the L1 verifyAgentBinding, and
// fail-closes: an unsigned/forged request never reaches the guarded handler and
// the binding sets a 403 deny response.
//
// This binding depends one-directionally on core + L1; core NEVER imports Hono.
// Hono is a PEER dependency of this binding, not of the core. The middleware is
// framework-shaped (a (ctx, next) pair) but does not import Hono's runtime — it
// operates over the standard Fetch Request the Hono context exposes as ctx.req.raw
// and the standard Response it assigns to ctx.res, so it is testable without a
// running Hono app and stays byte-neutral to the web standard.

import type { Ed25519Verify } from "../core/verifier.ts";
import { decodeBase64Url } from "../src/base64url.ts";
import { AGENT_KEY_HEADER, verifyAgentBinding } from "../src/pop.ts";
import { thumbprint } from "../src/thumbprint.ts";

const ED25519_PUBLIC_KEY_BYTES = 32;

/**
 * A minimal structural view of the Hono context the middleware touches: the raw
 * inbound Fetch Request and a Response slot the binding sets on deny. Declared
 * structurally (not imported from Hono) so the core-adjacent binding stays free of
 * a hard Hono runtime import while remaining drop-in for a real Hono `Context`.
 */
export interface RampVerifyContext {
	req: { raw: Request };
	res: Response | undefined;
}

export type RampVerifyNext = () => Promise<void> | void;

/** Options for the server-verify binding. The clock + verify primitive are
 * injected exactly as the core Verifier's are; the binding owns no state. The
 * GET-PoP path is self-verifying via the presented key, so no key resolver is
 * accepted — a resolver here would be dead weight the middleware never reads. */
export interface RampVerifyOptions {
	now?: () => number;
	verifyEd25519?: Ed25519Verify;
}

/**
 * rampVerify builds the opt-in Hono server-verify middleware. On an inbound
 * request it verifies the RFC 9421 GET PoP through the L1 verifyAgentBinding; on
 * success it calls next() (the guarded handler runs); on failure it sets a 403 deny
 * response and does NOT call next() (fail-closed).
 *
 * SCOPE LIMIT — presenter self-consistency only: the binding derives agentId
 * from the PRESENTED key (thumbprint), so the 3-way check collapses to "the
 * presenter signed with the key it presented". It does NOT anchor a URL-bound
 * agent_id. A consumer enforcing URL-bound delivery (e.g. an edge serving
 * signed URLs whose agent_id query param binds the fetcher) MUST call the L1
 * verifyAgentBinding directly with the URL's agent_id as the anchor — building
 * URL-bound verification on this middleware would silently accept any
 * self-consistent presenter.
 */
export function rampVerify(
	opts: RampVerifyOptions,
): (ctx: RampVerifyContext, next: RampVerifyNext) => Promise<void> {
	return async (ctx, next) => {
		const req = ctx.req.raw;

		// The presented key is the PoP authority; its thumbprint is the identity the
		// 3-way check anchors on (keyid == thumbprint(presented) == agent_id). Derive
		// agent_id from the presented key so a request that omits the URL param still
		// verifies self-consistently.
		const presentedRaw = req.headers.get(AGENT_KEY_HEADER);
		const presented = presentedRaw ? decodeBase64Url(presentedRaw) : undefined;
		if (!presented || presented.length !== ED25519_PUBLIC_KEY_BYTES) {
			ctx.res = deny();
			return;
		}
		const agentId = await thumbprint(presented);

		const result = await verifyAgentBinding({
			url: req.url,
			method: req.method,
			headers: req.headers,
			agentId,
			...(opts.now ? { now: opts.now } : {}),
			...(opts.verifyEd25519 ? { verifyEd25519: opts.verifyEd25519 } : {}),
		});

		if (!result.ok) {
			ctx.res = deny();
			return;
		}
		await next();
	};
}

function deny(): Response {
	return new Response("forbidden", { status: 403 });
}
