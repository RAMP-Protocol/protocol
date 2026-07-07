// sdk/ts offer SIGN face — the Exchange-minting sibling of the core Verifier's
// offer-verification path. Mirror of the Go oracle helpers.SignOffer and Python
// core.sign_offer_jcs.
//
// The signed bytes are JCS(protojson(offer with signature+signature_algorithm
// cleared)) — the SAME canonical builder the verify face reuses
// (core/verifier.ts canonicalOfferPayload), never a re-derived canonicalization.
// Ed25519 is deterministic (RFC 8032), so the hex signature is byte-identical to
// the Go oracle. This half is UNAFFECTED by the signed-URL opaque-bytes decision:
// JCS over proto-JSON is already deterministic and cross-language byte-agreed.
//
// WebCrypto is the crypto primitive (the same one the acceptance/verify faces
// use); the caller supplies the imported CryptoKey, exactly as acceptance.ts does.

import { canonicalOfferPayload, OFFER_SIGNATURE_ALGORITHM } from "../core/verifier.ts";

export { OFFER_SIGNATURE_ALGORITHM };

/**
 * signOffer signs the canonical offer payload (JCS over the offer with its
 * signature/signature_algorithm cleared) with the exchange's Ed25519 private key
 * and returns the hex signature for Offer.signature. The offer must already be
 * canonical proto-JSON (snake_case, enums-as-names, omit-unpopulated), as the
 * verify face requires — canonicalOfferPayload clears the two signature keys and
 * re-JCS-es.
 */
export async function signOffer(
	offer: Record<string, unknown>,
	privateKey: CryptoKey,
): Promise<string> {
	const payload = canonicalOfferPayload(offer);
	const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, payload));
	let hex = "";
	for (const b of sig) hex += b.toString(16).padStart(2, "0");
	return hex;
}
