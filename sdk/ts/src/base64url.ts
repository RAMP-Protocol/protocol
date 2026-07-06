// base64url codec — the shared byte primitive under the thumbprint, signed-URL,
// and PoP helpers. Relocated verbatim from the app edge (src/edge/src/verify.ts)
// so the SDK's canonical encodings stay byte-identical to the wire contract the
// sdk/go oracle emits.
//
// The decoder accepts both url- and std-alphabet input (it remaps `-_` -> `+/`
// and pads), so an RFC 9421 Signature header — which carries STANDARD base64 —
// decodes correctly through the same path (the remap is a no-op on std input).

/** Decode a base64url (or std-base64) string to bytes, or `undefined` on error.
 * Typed `Uint8Array<ArrayBuffer>` (never SharedArrayBuffer-backed) so decoded
 * bytes satisfy WebCrypto's BufferSource without casts. */
export function decodeBase64Url(input: string): Uint8Array<ArrayBuffer> | undefined {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const b64 = input.replaceAll("-", "+").replaceAll("_", "/") + pad;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return undefined;
  }
}

/** UTF-8 encode, pinned ArrayBuffer-backed. TextEncoder.encode always allocates
 * a fresh ArrayBuffer, but some lib typings widen the return to ArrayBufferLike;
 * pin it once here so consumers on any TS/lib version feed WebCrypto without
 * casts of their own. */
export function utf8Bytes(s: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(s) as Uint8Array<ArrayBuffer>;
}

/** Encode bytes as base64url with no padding. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
