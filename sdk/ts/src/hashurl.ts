// HashURL — TS port of the sdk/go oracle (helpers/signedurl.go HashURL). It
// returns the SHA-256 digest of a signed URL (the transaction_log.signed_url_hash
// value, 32 bytes). The hash is over the URL string bytes VERBATIM (opaque
// bytes, no WHATWG renormalization — consistent with the opaque-URL signing
// contract). The TS face is async (crypto.subtle.digest); the shared vector
// encodes the digest as hex.

import { utf8Bytes } from "./base64url.ts";

/**
 * hashUrl returns the raw 32-byte SHA-256 digest of the signed URL's verbatim
 * UTF-8 bytes.
 */
export async function hashUrl(signed: string): Promise<Uint8Array> {
	const digest = await crypto.subtle.digest("SHA-256", utf8Bytes(signed));
	return new Uint8Array(digest);
}
