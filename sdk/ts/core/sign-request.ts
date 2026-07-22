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

import { opaqueUrl } from "../src/opaque-url.ts";
import {
	maxSigLabelN,
	signatureBytesByLabel,
} from "./multisig-parse.ts";
import { stdBase64 } from "./sign.ts";

// The RAMP request covered set: exactly these five, in this order. No conditional
// biscuit component — it is bound only when an entitlement header is present,
// which this signer's inputs never carry. Exported so the verify sibling
// (core/verify-request.ts) enforces the SAME required set without duplicating it.
export const COVERED_COMPONENTS = [
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
// Exported so the verify sibling recomputes the digest over the exact body bytes
// and compares against the covered Content-Digest header byte-for-byte.
export async function contentDigest(
	body: Uint8Array<ArrayBuffer>,
): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
	return `sha-256=:${stdBase64(digest)}:`;
}

// A forwarding-chain link: the pre-rendered covered token
// `"signature";key="sigN"` and its base value `:<std-base64(prev sig bytes)>:`.
// The token is inserted as the LAST covered component before @signature-params
// and is rendered VERBATIM (NOT re-wrapped in the naive per-element quoting) —
// it already carries its own quotes and the key= param.
export interface ChainLink {
	token: string;
	value: string;
}

// The @signature-params inner list: the covered components then keyid/alg/
// created/expires, RFC 9421 order — byte-identical to Go signatureInputInner. An
// optional chain-link token appends as the final covered component (sigN, N>1),
// defaulting absent so the single-sig (N=1) inner list stays byte-identical.
function signatureParams(
	keyid: string,
	created: number,
	expires: number,
	chainLinkToken?: string,
): string {
	const tokens = COVERED_COMPONENTS.map((c) => `"${c}"`);
	if (chainLinkToken !== undefined) tokens.push(chainLinkToken);
	const covered = tokens.join(" ");
	return `(${covered});keyid="${keyid}";alg="ed25519";created=${created};expires=${expires}`;
}

/** The covered request field values a 5-component RAMP signature base is built over. */
export interface RequestBaseFields {
	method: string;
	url: string;
	digestHeader: string;
	authorization: string;
	signatureAgent: string;
}

/**
 * The RFC 9421 signature base over the RAMP 5-component covered set: one
 * `"name": value` line per component, joined by "\n", terminated by
 * `"@signature-params": <sigParams>` with NO trailing newline. Empty
 * authorization/signature-agent still render (name + ": " + "") — the trailing
 * space is part of the covered bytes and must never be trimmed. Exported and
 * shared with the verify sibling (core/verify-request.ts) so sign and verify
 * reconstruct byte-identical bases; `sigParams` is the VERBATIM inner-list +
 * params tail (the signer's own on sign, the wire's on verify).
 */
export function buildRequestSignatureBase(
	fields: RequestBaseFields,
	sigParams: string,
	chainLink?: ChainLink,
): string {
	const lines = [
		`"@method": ${fields.method.toUpperCase()}`,
		`"@target-uri": ${opaqueUrl(fields.url)}`,
		`"content-digest": ${fields.digestHeader}`,
		`"authorization": ${fields.authorization}`,
		`"signature-agent": ${fields.signatureAgent}`,
	];
	// The chain-link line is the LAST covered component BEFORE @signature-params
	// (Go buildSignatureBase renders params.Covered in order, chain link last).
	if (chainLink !== undefined) {
		lines.push(`${chainLink.token}: ${chainLink.value}`);
	}
	lines.push(`"@signature-params": ${sigParams}`);
	return lines.join("\n");
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
	const base = buildRequestSignatureBase(
		{
			method: opts.method,
			url: opts.url,
			digestHeader,
			authorization: opts.authorization,
			signatureAgent: opts.signatureAgent,
		},
		sigParams,
	);
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

/** A request's prior signature state — the Signature-Input / Signature header
 * values already on the request (both "" for an unsigned request). */
export interface PriorSignatures {
	signatureInput: string;
	signature: string;
}

/**
 * appendSignature chains sig(N+1) onto `prev` WITHOUT disturbing existing members
 * (forwarding chain), the TS port of Go helpers.AppendSignature. It finds
 * the next label sig(N+1) and predecessor sigN, binds the RAMP base plus a
 * `"signature";key="sigN"` link whose value is `:<std-base64(decoded predecessor
 * sig bytes)>:` (re-encoded canonically, NOT a wire splice), Ed25519-signs, and
 * returns the APPENDED Signature-Input / Signature strings. Appending to an
 * unsigned request (empty prev) produces a sig1 byte-for-byte identical to
 * signRequest — single-sig is the N=1 case.
 */
export async function appendSignature(
	privKey: CryptoKey,
	prev: PriorSignatures,
	opts: SignRequestOptions,
): Promise<SignedRequest> {
	const digestHeader = await contentDigest(opts.body);
	const hasPrev = prev.signatureInput !== "";
	const prevN = hasPrev ? maxSigLabelN(prev.signatureInput) : 0;
	const label = `sig${prevN + 1}`;

	let chainLink: ChainLink | undefined;
	let chainLinkToken: string | undefined;
	if (prevN > 0) {
		const prevLabel = `sig${prevN}`;
		const prevBytes = signatureBytesByLabel(prev.signature)[prevLabel];
		if (!prevBytes) {
			throw new Error(`appendSignature: predecessor ${prevLabel} not in Signature`);
		}
		chainLinkToken = `"signature";key="${prevLabel}"`;
		chainLink = { token: chainLinkToken, value: `:${stdBase64(prevBytes)}:` };
	}

	const sigParams = signatureParams(opts.keyid, opts.created, opts.expires, chainLinkToken);
	const base = buildRequestSignatureBase(
		{
			method: opts.method,
			url: opts.url,
			digestHeader,
			authorization: opts.authorization,
			signatureAgent: opts.signatureAgent,
		},
		sigParams,
		chainLink,
	);
	const sig = await crypto.subtle.sign("Ed25519", privKey, new TextEncoder().encode(base));
	const memberInput = `${label}=${sigParams}`;
	const memberSig = `${label}=:${stdBase64(new Uint8Array(sig))}:`;
	return {
		contentDigest: digestHeader,
		signatureInput: hasPrev ? `${prev.signatureInput}, ${memberInput}` : memberInput,
		signature: prev.signature !== "" ? `${prev.signature}, ${memberSig}` : memberSig,
		signatureBase: base,
	};
}
