import { encodeBase64Url } from "./base64url.ts";

const ED25519_PUBLIC_KEY_BYTES = 32;

/**
 * Compute the RFC 7638 JWK Thumbprint of a raw 32-byte Ed25519 public key,
 * base64url-no-pad encoded.
 *
 * The canonical JWK is fixed by RFC 7638 §3.2 for OKP keys —
 * `{"crv":"Ed25519","kty":"OKP","x":"<base64url-nopad(pubkey)>"}`, members in
 * lexicographic order, no whitespace — and the thumbprint is
 * `base64url-nopad(SHA-256(canonical JWK))`.
 *
 * This MUST stay byte-identical to the sdk/go oracle (helpers.Thumbprint, which
 * builds the same canonical JWK via go-jose). Both are pinned to the shared
 * testdata/thumbprint-vectors.json.
 */
export async function thumbprint(pubkey: Uint8Array): Promise<string> {
  if (pubkey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(`thumbprint: public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes`);
  }
  const x = encodeBase64Url(pubkey);
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return encodeBase64Url(new Uint8Array(digest));
}
