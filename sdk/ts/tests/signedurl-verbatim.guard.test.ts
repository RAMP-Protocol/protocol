// sdk/ts verbatim-canonicalization guard (TDD red for ov97t.16).
//
// THE CONTRACT (Constantine, 2026-07-07): the signed-URL signature covers
// `GET\n<url>` as OPAQUE URL BYTES. Signer and verifier MUST agree on `<url>`
// byte-for-byte. The ONLY permitted transform is deterministic query handling
// (add exp/kid/agent_id, remove sig, sort query) — NEVER host-lowercasing,
// default-port stripping, or path-escaping.
//
// This guard pins that invariant WITHOUT touching a Go vector: it asserts that
// the sign face and the verify face build the SAME canonical `GET\n<url>` bytes
// for a TRICKY URL. Because Ed25519 is deterministic, byte-identical canonical
// bytes are exactly what makes a self-signed URL verify — so the guard is:
//   sign(sourceUrl) -> signedUrl ; verify(signedUrl) === valid
// over a URL whose host case, explicit :443, and path space/percent would be
// mangled by any `new URL()` normalization on EITHER side.
//
// RED now for reasons that are ALL intended:
//   1. sdk/ts/src/signurl.ts (the SIGN face) does not exist yet — import fails.
//   2. Even once the sign face lands, verify.ts::canonicalMessage currently
//      round-trips through `new URL().toString()` (WHATWG lowercases the host,
//      strips :443, re-escapes the path). A verbatim signer + a normalizing
//      verifier disagree on the tricky URL → the self-signed URL fails to verify.
//      This guard therefore stays RED until BOTH faces canonicalize verbatim.
import { describe, it, expect } from "vitest";
// RED: the SIGN face does not exist yet.
import { signEd25519SignedUrl } from "../src/signurl.ts";
import { verifyEd25519SignedUrl } from "../src/verify.ts";

const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// A fixed 32-byte Ed25519 seed and its derived raw public key are NOT hardcoded
// here — we derive the public key by importing seed → sign, then exporting is not
// available for Ed25519 raw pub via WebCrypto pkcs8 import. Instead we round-trip:
// sign yields a signature the SAME key's public half verifies. We obtain the raw
// public key from the seed via a jwk import.
async function importSigningKey(seedHex: string): Promise<CryptoKey> {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
    "sign",
  ]);
}

// Derive the matching raw public key for a seed by generating the key pair the
// seed defines. WebCrypto has no seed→public path, so we import the pkcs8 private
// AND import the same seed's public via a known-answer jwk is overkill; instead we
// import the private key as extractable to read its public half.
async function publicKeyForSeed(seedHex: string): Promise<CryptoKey> {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", priv)) as JsonWebKey;
  // The public half (x) round-trips into a verify key. kty/crv/x are always present
  // on an exported Ed25519 JWK; the ?? "" pins the string type under
  // exactOptionalPropertyTypes without affecting the (always-present) values.
  const pubJwk: JsonWebKey = {
    kty: jwk.kty ?? "OKP",
    crv: jwk.crv ?? "Ed25519",
    x: jwk.x ?? "",
  };
  return crypto.subtle.importKey(
    "jwk",
    pubJwk,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

// TRICKY URLs — mixed-case host, explicit :443, space and percent in the PATH.
// These are exactly the inputs a `new URL()`-normalizing canonicalizer mangles.
const TRICKY_SOURCE_URLS = [
  "https://CDN.Example:443/a path/doc",
  "https://CDN.Example/Doc%2Fpart?z=9&a=2",
  "https://Origin.EXAMPLE.com:443/deep/a b/c",
];

const SEED_HEX = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
const NOW_UNIX = 1_700_000_100;
const EXP_UNIX = 1_700_000_300;

describe("sdk/ts signed-URL canonicalization is VERBATIM (no host/port/path normalization)", () => {
  for (const source of TRICKY_SOURCE_URLS) {
    it(`self-signed tricky URL verifies (verbatim contract): ${source}`, async () => {
      const priv = await importSigningKey(SEED_HEX);
      const pub = await publicKeyForSeed(SEED_HEX);

      const signed = await signEd25519SignedUrl(
        source,
        { kid: "ex.v1", agentId: "", expUnix: EXP_UNIX },
        priv,
      );

      // If EITHER face normalizes the host/port/path, the sign-time bytes and the
      // verify-time bytes differ and this verification fails — proving the leak.
      const res = await verifyEd25519SignedUrl(signed, {
        now: () => NOW_UNIX * 1000,
        resolveKey: async (kid) => (kid === "ex.v1" ? pub : undefined),
      });
      expect(res.valid).toBe(true);
    });

    it(`signed URL preserves host case + explicit port + path bytes verbatim: ${source}`, async () => {
      const priv = await importSigningKey(SEED_HEX);
      const signed = await signEd25519SignedUrl(
        source,
        { kid: "ex.v1", agentId: "", expUnix: EXP_UNIX },
        priv,
      );
      // The emitted URL must still carry the ORIGINAL host casing and the explicit
      // :443 — a WHATWG round-trip would have dropped both. Split off the query we
      // deterministically appended; the scheme+host+path prefix must be verbatim.
      // split() always yields >=1 element, so [0] is defined (narrow for
      // noUncheckedIndexedAccess without changing what is asserted).
      const prefix = source.split("?")[0]!;
      expect(signed.startsWith(prefix)).toBe(true);
    });
  }
});
