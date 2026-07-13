// sdk/ts injectable-Ed25519-verifier guard (DRY-02).
//
// verifyEd25519SignedUrl owns the signed-URL verify ENVELOPE — param parse,
// expiry, sig/agent decode, reason mapping. The Ed25519 primitive is the ONE
// injectable seam (VerifyDeps.verify), defaulting to WebCrypto native. A runtime
// whose SubtleCrypto lacks Ed25519 (Fastly Compute) injects @noble/ed25519 and
// reuses the whole envelope instead of re-hand-rolling it. These tests pin:
//   (1) the injected verifier is actually called, with the resolved key + the
//       canonical message bytes + the signature bytes, and its verdict decides
//       validity — so a NON-CryptoKey key type (raw bytes) flows through untouched;
//   (2) the default (no verify injected) path stays byte-identical — a WebCrypto
//       self-signed URL still verifies.
import { describe, it, expect } from "vitest";
import { signEd25519SignedUrl } from "../src/signurl.ts";
import { canonicalMessage, verifyEd25519SignedUrl } from "../src/verify.ts";

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

async function importSigningKey(seedHex: string): Promise<CryptoKey> {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
    "sign",
  ]);
}

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
  const pubJwk: JsonWebKey = {
    kty: jwk.kty ?? "OKP",
    crv: jwk.crv ?? "Ed25519",
    x: jwk.x ?? "",
  };
  return crypto.subtle.importKey("jwk", pubJwk, { name: "Ed25519" }, false, [
    "verify",
  ]);
}

const SEED_HEX = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
const SOURCE = "https://cdn.example.com/doc?z=9&a=2";
const NOW_UNIX = 1_700_000_100;
const EXP_UNIX = 1_700_000_300;

async function sign(): Promise<string> {
  const priv = await importSigningKey(SEED_HEX);
  return signEd25519SignedUrl(
    SOURCE,
    { kid: "ex.v1", agentId: "", expUnix: EXP_UNIX },
    priv,
  );
}

describe("sdk/ts verifyEd25519SignedUrl: injectable Ed25519 primitive (DRY-02)", () => {
  it("routes through the INJECTED verifier with the resolved key + canonical message + sig, and its verdict decides validity", async () => {
    const signed = await sign();

    // A NON-CryptoKey key type: a raw sentinel the injected verifier receives
    // verbatim — proving the envelope does not touch the key itself, so a
    // @noble consumer can resolve raw public-key bytes.
    const RAW_KEY = Uint8Array.from([1, 2, 3, 4]);
    let sawKey: Uint8Array | undefined;
    let sawMessage: Uint8Array | undefined;
    let sawSig: Uint8Array | undefined;

    const res = await verifyEd25519SignedUrl<Uint8Array>(signed, {
      now: () => NOW_UNIX * 1000,
      resolveKey: async (kid) => (kid === "ex.v1" ? RAW_KEY : undefined),
      verify: (key, message, sig) => {
        sawKey = key;
        sawMessage = message;
        sawSig = sig;
        return true; // stub verdict — decides validity regardless of real crypto
      },
    });

    expect(res.valid).toBe(true);
    expect(res.kid).toBe("ex.v1");
    expect(sawKey).toBe(RAW_KEY); // passed through untouched
    // The envelope handed the verifier the SAME canonical bytes the signer covered.
    expect(sawMessage).toEqual(canonicalMessage(signed));
    expect(sawSig).toBeInstanceOf(Uint8Array);
    expect(sawSig!.length).toBe(64); // decoded Ed25519 signature
  });

  it("a false verdict from the injected verifier maps to signature_mismatch (envelope owns the reason)", async () => {
    const signed = await sign();
    let called = false;
    const res = await verifyEd25519SignedUrl<Uint8Array>(signed, {
      now: () => NOW_UNIX * 1000,
      resolveKey: async () => Uint8Array.from([9]),
      verify: () => {
        called = true;
        return false;
      },
    });
    expect(called).toBe(true);
    expect(res.valid).toBe(false);
    expect(res.reason).toBe("signature_mismatch");
  });

  it("default path (no verifier injected) stays byte-identical: a WebCrypto self-signed URL verifies", async () => {
    const signed = await sign();
    const pub = await publicKeyForSeed(SEED_HEX);
    const res = await verifyEd25519SignedUrl(signed, {
      now: () => NOW_UNIX * 1000,
      resolveKey: async (kid) => (kid === "ex.v1" ? pub : undefined),
    });
    expect(res.valid).toBe(true);
  });
});
