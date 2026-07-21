// Ad-hoc JWKS decode for the well-known KEY document. The publisher's
// ramp.json key set is the kid-carrying RFC 7517 subset
// `{"keys":[{"kid","kty":"OKP","crv":"Ed25519","x":"<base64url>"}]}` — NOT the
// gen JsonWebKey/WellKnownManifest schemas, which carry no `kid` and no JWK-set
// (decoding through them would resolve ZERO keys). The gen schemas are reserved
// for the WBA path (thumbprint-keyed, needs no kid). base64url `x` decode reuses
// the byte-parity-pinned primitive.
//
// Extraction is SKIP-NOT-FAIL (mirroring go-jose ed25519KeysFromJWKS): a key
// with an empty/missing kid, a non-OKP/Ed25519 type, or a wrong-length `x` is
// skipped, survivors are keyed by kid, and one bad key never fails the whole set.

import { decodeBase64UrlStrict } from "../src/base64url.ts";

const ED25519_PUBLIC_KEY_BYTES = 32;

/** Extract the Ed25519 public keys (keyed by kid) from a parsed JWKS doc. */
export function ed25519KeysFromJwks(doc: unknown): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const keys = (doc as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) return out;
  for (const entry of keys) {
    const extracted = extractEd25519(entry);
    if (extracted) out.set(extracted.kid, extracted.pub);
  }
  return out;
}

function extractEd25519(entry: unknown): { kid: string; pub: Uint8Array } | undefined {
  if (typeof entry !== "object" || entry === null) return undefined;
  const e = entry as Record<string, unknown>;
  if (typeof e.kid !== "string" || e.kid === "") return undefined;
  if (e.kty !== "OKP" || e.crv !== "Ed25519") return undefined;
  if (typeof e.x !== "string") return undefined;
  // JWK OKP `x` is UNPADDED base64url (RFC 8037); reject padding / the standard
  // alphabet to match Go's go-jose JWKS parse (RawURLEncoding).
  const raw = decodeBase64UrlStrict(e.x);
  if (!raw || raw.length !== ED25519_PUBLIC_KEY_BYTES) return undefined;
  return { kid: e.kid, pub: raw };
}
