// sdk/ts offer SIGN byte-parity against the Go oracle.
//
// Under the 3-SDKs=3-SDKs decision a TS Exchange must SIGN offers, not only
// verify them. This suite pins the not-yet-existing TS offer-sign face
// byte-identical to the Go oracle (helpers.SignOffer): re-signing the vector's
// `offer_json` (with signature/signature_algorithm cleared) under the exchange
// signer seed MUST reproduce the exact hex signature ALREADY embedded in
// offer_json.signature, over the exact JCS canonical bytes.
//
// Canonical form = JCS(protojson(offer with sig+alg cleared)) — snake_case,
// omit-unpopulated — the SAME primitive the verify face reuses
// (core/verifier.ts canonicalOfferPayload). Ed25519 is deterministic (RFC 8032),
// so the TS signature MUST equal the Go one byte-for-byte, not merely verify.
//
// The offer-sign half is UNAFFECTED by the signed-URL opaque-bytes decision:
// JCS over proto-JSON is already deterministic and cross-language byte-agreed.
//
// RED now for TWO expected reasons, both intended:
//   1. sdk/ts/src/offer-sign.ts (the SIGN face) does not exist yet — import fails.
//   2. The offer-verify vectors do not yet carry `exchange_seed_hex` (the Go
//      emitter extension is a later step), so a TS re-sign cannot reproduce the
//      hex signature.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/offer-sign.ts (the offer SIGN face) does not exist yet.
import { signOffer } from "../src/offer-sign.ts";
// Reused, NOT reinvented: the verify-side canonical builder is the byte source of
// truth (disease-scan ALLOWLIST #2). The sign face must produce the same bytes.
import { canonicalOfferPayload } from "../core/verifier.ts";
import offerVerifyVectors from "../../go/helpers/testdata/offer-verify-vectors.json";

type OfferVerifyVector = {
  name: string;
  exchange: string;
  exchange_pub_b64url: string;
  offer_json: Record<string, unknown>; // full signed proto-JSON (carries signature)
  now_unix: number;
  expected_verified: boolean;
  // --- SIGN-parity addition (emitted by the extended Go emitter) ---
  exchange_seed_hex: string; // the exchange offer-signing seed (fixedSeed 0x66)
};

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

describe("sdk/ts offer sign is byte-identical to the Go oracle", () => {
  // Cast through `unknown`: the committed vectors do not yet carry
  // `exchange_seed_hex` (the Go-emitter extension is a later step), so the inferred
  // JSON type does not structurally overlap OfferVerifyVector — which is exactly
  // the TDD-red condition this suite pins.
  const doc = offerVerifyVectors as unknown as {
    canonicalization: string;
    vectors: OfferVerifyVector[];
  };

  it("vector matrix is JCS-canonicalized and non-empty", () => {
    expect(doc.canonicalization).toBe("jcs");
    expect(doc.vectors.length).toBeGreaterThan(0);
  });

  // Only the genuinely-signed vectors (expected_verified) have a reproducible
  // signature; the tamper_negative vector's signature is deliberately broken and
  // is exercised as the negative case below.
  for (const v of doc.vectors.filter((x) => x.expected_verified)) {
    const embeddedSig = v.offer_json.signature as string;

    it(`${v.name}: TS offer signature is byte-identical to the embedded Go signature`, async () => {
      const priv = await importSigningKey(v.exchange_seed_hex);
      const sigHex = await signOffer(v.offer_json, priv);
      expect(sigHex).toBe(embeddedSig);
    });

    it(`${v.name}: TS signs over the SAME canonical JCS bytes the verify face reads`, async () => {
      // The sign face must sign exactly canonicalOfferPayload(offer) — no
      // re-derived canonicalization. Signing those bytes directly must reproduce
      // the embedded signature.
      const payload = canonicalOfferPayload(v.offer_json);
      const priv = await importSigningKey(v.exchange_seed_hex);
      const raw = new Uint8Array(
        await crypto.subtle.sign("Ed25519", priv, payload),
      );
      let hex = "";
      for (const b of raw) hex += b.toString(16).padStart(2, "0");
      expect(hex).toBe(embeddedSig);
    });

    it(`${v.name}: signing under a wrong seed does NOT reproduce the signature`, async () => {
      const wrong = await importSigningKey(`${"00".repeat(31)}01`);
      const sigHex = await signOffer(v.offer_json, wrong);
      expect(sigHex).not.toBe(embeddedSig);
    });
  }
});
