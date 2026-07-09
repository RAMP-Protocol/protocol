// sdk/ts offer-acceptance sign/verify parity against the shared Go oracle.
//
// The agent role must be buildable in TS (the 3-SDKs decision): an agent signs a
// DETACHED, content-bound acceptance over an accepted Offer, and the Exchange
// verifies it. Go (helpers.SignOfferAcceptance) and Python
// (core.sign_offer_acceptance_jcs) already ship this face; this suite pins the TS
// face byte-identical to the SAME oracle they verify against.
//
// The canonical form is JCS(protojson(AgentAcceptancePayload)) — snake_case,
// omit-unpopulated — so an empty requester_domain is absent before JCS. Ed25519
// is deterministic (RFC 8032), so signOfferAcceptance MUST reproduce the oracle's
// signature_hex byte-for-byte, not merely verify.
//
// RED until sdk/ts/src/acceptance.ts exists; the implement step adds it.
import { describe, it, expect } from "vitest";
import {
  acceptancePayload,
  signOfferAcceptance,
  verifyOfferAcceptance,
} from "../src/acceptance.ts";
import acceptanceVectors from "../../go/helpers/testdata/acceptance-vectors.json";

type AcceptanceVector = {
  name: string;
  offer_sig: string;
  requester_id: string;
  requester_domain: string;
  idempotency_key: string;
  canonical_jcs: string; // the exact JCS bytes the signature covers
  signature_hex: string; // Go-oracle Ed25519 signature (deterministic)
  pubkey_b64: string; // std-base64 raw 32-byte Ed25519 public key
  seed_hex: string; // 32-byte Ed25519 seed the oracle signed with
};

// The fixed PKCS8 DER prefix for an Ed25519 private key (SEQUENCE + version +
// AlgorithmIdentifier(1.3.101.112) + OCTET STRING wrapper); the 32-byte seed
// follows. WebCrypto cannot import a bare Ed25519 seed as "raw", so the seed is
// wrapped in PKCS8 and imported as "pkcs8".
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

function stdB64ToBytes(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
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

async function importVerifyKey(pubB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    stdB64ToBytes(pubB64),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

describe("sdk/ts offer-acceptance matches the shared Go oracle (byte-identical)", () => {
  const doc = acceptanceVectors as {
    canonicalization: string;
    vectors: AcceptanceVector[];
  };

  it("vector matrix is JCS-canonicalized and non-empty", () => {
    expect(doc.canonicalization).toBe("jcs");
    expect(doc.vectors.length).toBeGreaterThan(0);
  });

  for (const v of doc.vectors) {
    const input = {
      offerSig: v.offer_sig,
      requesterId: v.requester_id,
      requesterDomain: v.requester_domain,
      idempotencyKey: v.idempotency_key,
    };

    it(`${v.name}: canonical payload equals the oracle JCS`, () => {
      const got = new TextDecoder().decode(acceptancePayload(input));
      expect(got).toBe(v.canonical_jcs);
    });

    it(`${v.name}: TS signature is byte-identical to the Go oracle`, async () => {
      const priv = await importSigningKey(v.seed_hex);
      const sigHex = await signOfferAcceptance(input, priv);
      expect(sigHex).toBe(v.signature_hex);
    });

    it(`${v.name}: oracle signature verifies through the TS face`, async () => {
      const pub = await importVerifyKey(v.pubkey_b64);
      expect(await verifyOfferAcceptance(input, v.signature_hex, pub)).toBe(true);
    });

    it(`${v.name}: a tampered idempotency key fails verification`, async () => {
      const pub = await importVerifyKey(v.pubkey_b64);
      const tampered = { ...input, idempotencyKey: `${input.idempotencyKey}-x` };
      expect(await verifyOfferAcceptance(tampered, v.signature_hex, pub)).toBe(
        false,
      );
    });
  }

  it("an unsigned offer (empty offer_sig) is rejected fail-closed", () => {
    expect(() =>
      acceptancePayload({
        offerSig: "",
        requesterId: "a",
        requesterDomain: "a.example",
        idempotencyKey: "i",
      }),
    ).toThrow();
  });
});
