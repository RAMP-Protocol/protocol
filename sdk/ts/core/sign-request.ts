// sdk/ts outbound RFC 9421 request signer over the full 5-component RAMP covered
// set (@method @target-uri content-digest authorization signature-agent) — the
// TS sibling of Go helpers.SignRequest and Python httpsig.sign_request. It signs
// byte-identical to the shared Go oracle so a request signed in TS verifies
// unchanged at any Go/Python broker/exchange.
//
// This is the 5-component sibling of core/sign.ts::signInbound (the 2-component
// GET PoP). It does NOT reuse pop.ts::signatureBase (hardcoded to 2 components);
// it renders its own base, mirroring Python ramp_sdk/httpsig.py::sign_request.
//
// created/expires are INJECTED unix seconds (L1-pure, no wall clock).
// authorization + signature-agent are ALWAYS bound — an empty string still
// renders (with the load-bearing trailing space), so a later token/directory
// injection cannot piggy-back the signature. Values pass through verbatim: the
// caller supplies an absolute @target-uri; the signer never normalizes it.

import { stdBase64 } from "./sign.ts";

// The RAMP request covered set: exactly these five, in this order. No conditional
// biscuit component — it is bound only when an entitlement header is present,
// which this signer's inputs never carry.
const COVERED_COMPONENTS = [
	"@method",
	"@target-uri",
	"content-digest",
	"authorization",
	"signature-agent",
] as const;

/** Inputs for signRequest. All fields required; signatureAgent is "" to pin its absence. */
export interface SignRequestOptions {
	method: string;
	url: string;
	// Byte param is Uint8Array<ArrayBuffer> (never SharedArrayBuffer-backed),
	// matching the sdk/ts WebCrypto convention (see core/verifier.ts, src/pop.ts).
	body: Uint8Array<ArrayBuffer>;
	authorization: string;
	signatureAgent: string;
	keyid: string;
	created: number;
	expires: number;
}

/** The RFC 9421 artifacts a signed request carries, plus the covered base bytes. */
export interface SignedRequest {
	contentDigest: string;
	signatureInput: string;
	signature: string;
	signatureBase: string;
}

// RFC 9530 Content-Digest header value: `sha-256=:<STANDARD-base64(SHA-256)>:`.
async function contentDigest(body: Uint8Array<ArrayBuffer>): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
	return `sha-256=:${stdBase64(digest)}:`;
}

// The @signature-params inner list: the covered components then keyid/alg/
// created/expires, RFC 9421 order — byte-identical to Go signatureInputInner.
function signatureParams(
	keyid: string,
	created: number,
	expires: number,
): string {
	const covered = COVERED_COMPONENTS.map((c) => `"${c}"`).join(" ");
	return `(${covered});keyid="${keyid}";alg="ed25519";created=${created};expires=${expires}`;
}

// The signature base: one `"name": value` line per covered component, joined by
// "\n", with @signature-params last and NO trailing newline. Empty authorization/
// signature-agent still render (name + ": " + "" ) — the trailing space is part
// of the covered bytes, so it must never be trimmed.
function buildSignatureBase(
	opts: SignRequestOptions,
	digestHeader: string,
	sigParams: string,
): string {
	return [
		`"@method": ${opts.method.toUpperCase()}`,
		`"@target-uri": ${opts.url}`,
		`"content-digest": ${digestHeader}`,
		`"authorization": ${opts.authorization}`,
		`"signature-agent": ${opts.signatureAgent}`,
		`"@signature-params": ${sigParams}`,
	].join("\n");
}

/**
 * signRequest signs opts over the RAMP 5-component covered set with privKey and
 * returns the RFC 9421 Content-Digest, Signature-Input, and Signature header
 * values plus the exact signature base the signature covers. The Signature is
 * `sig1=:<STANDARD-base64(sig)>:` (NOT b64url — do not unify with the thumbprint
 * encoding); Signature-Input is `sig1=` + the same inner the base carries.
 */
export async function signRequest(
	privKey: CryptoKey,
	opts: SignRequestOptions,
): Promise<SignedRequest> {
	const digestHeader = await contentDigest(opts.body);
	const sigParams = signatureParams(opts.keyid, opts.created, opts.expires);
	const base = buildSignatureBase(opts, digestHeader, sigParams);
	const sig = await crypto.subtle.sign(
		"Ed25519",
		privKey,
		new TextEncoder().encode(base),
	);
	return {
		contentDigest: digestHeader,
		signatureInput: `sig1=${sigParams}`,
		signature: `sig1=:${stdBase64(new Uint8Array(sig))}:`,
		signatureBase: base,
	};
}
