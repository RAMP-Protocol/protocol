// sdk/ts/core sign seam — the client/inbound sign face over the WHATWG Fetch
// Request, mirror of the Go RoundTripper sign face (transport.go) but adapted to
// the IMMUTABLE Fetch Request: it returns a NEW signed Request (headers set on a
// clone), never mutating in place. It signs the RFC 9421 covered components over
// the EXACT request (for a GET PoP: @method + @target-uri), reusing the L1
// signatureBase byte contract so the signed bytes are byte-identical to what the
// L1 pop verifier reconstructs.
//
// ZERO framework import (no hono, no connect-es) — only WebCrypto + the L1
// helpers. The Hono binding (sdk/ts/hono) composes this seam; this seam composes
// nothing above the web standard.

import { encodeBase64Url } from "../src/base64url.ts";
import { opaqueUrl } from "../src/opaque-url.ts";
import { AGENT_KEY_HEADER, signatureBase } from "../src/pop.ts";
import { thumbprint } from "../src/thumbprint.ts";

// A default signing window (seconds) for the GET PoP created/expires params.
const DEFAULT_POP_TTL_SEC = 600;

/**
 * Ed25519 sign primitive: (privateKey, message) -> signature. Injected so a
 * non-WebCrypto runtime can supply its own without changing the byte contract.
 * Defaults to WebCrypto crypto.subtle over a CryptoKey.
 */
export type Ed25519SignFn = (message: Uint8Array) => Promise<Uint8Array>;

/** Options for signInbound — the created/expires window + an injectable clock. */
export interface SignInboundOptions {
	now?: () => number;
	ttlSec?: number;
}

/**
 * signInbound produces a genuinely RFC 9421 GET-PoP-signed inbound Request over
 * @method + @target-uri, bound to the agent keypair's RFC 7638 thumbprint (keyid =
 * agent_id). It is the sign side the Hono server-verify binding accepts; it returns
 * a NEW Request carrying the X-RAMP-Agent-Key, Signature-Input, and Signature
 * headers (the Fetch Request is immutable — we clone + set headers, never mutate).
 *
 * The covered set is exactly ("@method" "@target-uri"), matching the L1 pop
 * verifier's coversExactly, and the signature base is the L1 signatureBase byte
 * contract, so the produced request verifies through verifyAgentBinding unchanged.
 */
export async function signInbound(
	kp: CryptoKeyPair,
	url: string,
	opts: SignInboundOptions = {},
): Promise<Request> {
	const rawPub = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	);
	const agentId = await thumbprint(rawPub);

	const nowSec = Math.floor((opts.now?.() ?? Date.now()) / 1000);
	const created = nowSec;
	const expires = nowSec + (opts.ttlSec ?? DEFAULT_POP_TTL_SEC);

	// The @signature-params inner list the verifier rebuilds verbatim: covered
	// components then keyid/alg/created/expires, RFC 9421 order.
	const rawParams = `("@method" "@target-uri");keyid="${agentId}";alg="ed25519";created=${created};expires=${expires}`;

	// Coerce a URL-like input (a Fastly Compute request URL object) to its opaque
	// string form ONCE at the boundary, so the signed @target-uri and the emitted
	// Request carry the same verbatim bytes. No-op for string callers.
	const target = opaqueUrl(url);
	const base = signatureBase("GET", target, rawParams);
	const sig = await crypto.subtle.sign(
		"Ed25519",
		kp.privateKey,
		new TextEncoder().encode(base),
	);
	const sigStd = stdBase64(new Uint8Array(sig));

	const headers = new Headers();
	headers.set(AGENT_KEY_HEADER, encodeBase64Url(rawPub));
	headers.set("signature-input", `sig1=${rawParams}`);
	headers.set("signature", `sig1=:${sigStd}:`);

	return new Request(target, { method: "GET", headers });
}

// stdBase64 encodes bytes as standard (padded) base64 — the RFC 9421 Signature
// header byte-string encoding the L1 parseSignature decodes. Exported so the
// 5-component request signer (core/sign-request.ts) shares the exact encoder.
export function stdBase64(bytes: Uint8Array): string {
	let bin = "";
	for (let i = 0; i < bytes.length; i += 1)
		bin += String.fromCharCode(bytes[i] as number);
	return btoa(bin);
}
