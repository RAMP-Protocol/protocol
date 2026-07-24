// sdk/ts offer-acceptance sign/verify face — the AGENT-role acceptance surface,
// mirror of Go helpers.SignOfferAcceptance / VerifyOfferAcceptance and Python
// core.sign_offer_acceptance_jcs / verify_offer_acceptance_jcs.
//
// An agent signs a DETACHED, content-bound acceptance over an accepted Offer;
// the Exchange verifies it to bind the agent to the transaction. Unlike the
// transport RFC 9421 request signature, the acceptance is topology-independent:
// it stays valid no matter how many brokers relay the request, because it covers
// the offer signature + requester + idempotency, not the HTTP envelope.
//
// The signed bytes are JCS(protojson(AgentAcceptancePayload)) — snake_case,
// omit-unpopulated — the SAME primitive the offer signature uses, so every
// language reproduces the exact bytes. Ed25519 is deterministic (RFC 8032), so a
// given (payload, key) always yields the same signature; the parity suite pins
// the TS output byte-identical to the Go oracle.
//
// WebCrypto is the crypto primitive (the same one the L1 pop/verify faces use);
// the caller supplies the imported CryptoKey, exactly as core/sign.ts does.

import canonicalize from "canonicalize";

import { utf8Bytes } from "./base64url.ts";

/** The JWS alg advertised on AgentAcceptance.signature. Always EdDSA for Ed25519
 * (mirror helpers.AcceptanceSignatureAlgorithm). */
export const ACCEPTANCE_SIGNATURE_ALGORITHM = "EdDSA";

/** The acceptance binding fields. requesterDomain is omitted from the canonical
 * payload when empty (proto omit-unpopulated); an empty offerSig is rejected
 * fail-closed — an empty anchor would let the acceptance float free of any
 * concrete offer. */
export interface AcceptanceInput {
	offerSig: string;
	requesterId: string;
	requesterDomain: string;
	idempotencyKey: string;
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i += 1) {
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

function bytesToHex(bytes: Uint8Array): string {
	let hex = "";
	for (const b of bytes) hex += b.toString(16).padStart(2, "0");
	return hex;
}

/**
 * acceptancePayload reproduces the canonical signed bytes:
 * JCS(protojson(AgentAcceptancePayload)) with EVERY empty string field omitted.
 * Throws on an empty offer signature (fail-closed, mirror Go
 * CanonicalAcceptanceBytes / Python jcs_acceptance_payload).
 */
export function acceptancePayload(input: AcceptanceInput): Uint8Array<ArrayBuffer> {
	if (input.offerSig === "") {
		throw new Error(
			"ramp/acceptance: cannot accept an unsigned offer (empty offer signature)",
		);
	}
	// proto omit-unpopulated: every empty string field is absent before JCS. The Go
	// oracle gets that from EmitUnpopulated=false; this hand-built object has to do it
	// per field, or an empty requester_id would sign bytes Go never produces and
	// cross-language verification would fail on a wire-valid input (Requester.id
	// carries no min_len).
	const obj: Record<string, string> = { offer_sig: input.offerSig };
	if (input.requesterId !== "") obj.requester_id = input.requesterId;
	if (input.requesterDomain !== "") obj.requester_domain = input.requesterDomain;
	if (input.idempotencyKey !== "") obj.idempotency_key = input.idempotencyKey;
	const jcs = canonicalize(obj);
	if (jcs === undefined) {
		throw new Error("ramp/acceptance: payload is not JSON-serializable");
	}
	return utf8Bytes(jcs);
}

/**
 * signOfferAcceptance signs the canonical acceptance payload with the agent's
 * Ed25519 private key and returns the hex signature for AgentAcceptance.signature.
 */
export async function signOfferAcceptance(
	input: AcceptanceInput,
	privateKey: CryptoKey,
): Promise<string> {
	const payload = acceptancePayload(input);
	const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, payload));
	return bytesToHex(sig);
}

/**
 * verifyOfferAcceptance verifies a hex acceptance signature over the canonical
 * payload with the agent's Ed25519 public key. Returns false (never throws) on a
 * bad binding, a bad key, or an unsigned offer.
 */
export async function verifyOfferAcceptance(
	input: AcceptanceInput,
	signatureHex: string,
	publicKey: CryptoKey,
): Promise<boolean> {
	let payload: Uint8Array<ArrayBuffer>;
	try {
		payload = acceptancePayload(input);
	} catch {
		return false;
	}
	try {
		return await crypto.subtle.verify(
			"Ed25519",
			publicKey,
			hexToBytes(signatureHex),
			payload,
		);
	} catch {
		return false;
	}
}
