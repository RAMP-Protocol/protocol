import { describe, it, expect } from "vitest";
import {
  requestAcceptancePayload,
  signRequestAcceptance,
  verifyRequestAcceptance,
} from "../src/acceptance.ts";
import vectors from "../../go/helpers/testdata/request-acceptance-vectors.json";

const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function privateKey(seedHex: string): Promise<CryptoKey> {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

async function publicKey(value: string): Promise<CryptoKey> {
  const bin = atob(value);
  const raw = Uint8Array.from(bin, (char) => char.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

describe("request acceptance matches the Go oracle", () => {
  for (const vector of vectors.vectors) {
    const input = {
      items: vector.items.map((item) => ({
        offerSig: item.offer_sig,
        exchange: item.exchange,
      })),
      requesterId: vector.requester_id,
      requesterDomain: vector.requester_domain,
      idempotencyKey: vector.idempotency_key,
    };

    it(`${vector.name}: canonical bytes and signature`, async () => {
      expect(new TextDecoder().decode(requestAcceptancePayload(input))).toBe(
        vector.canonical_jcs,
      );
      expect(await signRequestAcceptance(input, await privateKey(vector.seed_hex))).toBe(
        vector.signature_hex,
      );
      expect(
        await verifyRequestAcceptance(
          input,
          vector.signature_hex,
          await publicKey(vector.pubkey_b64),
        ),
      ).toBe(true);
    });
  }

  it("signs item order", async () => {
    const vector = vectors.vectors[0]!;
    const input = {
      items: vector.items
        .map((item) => ({ offerSig: item.offer_sig, exchange: item.exchange }))
        .reverse(),
      requesterId: vector.requester_id,
      requesterDomain: vector.requester_domain,
      idempotencyKey: vector.idempotency_key,
    };
    expect(
      await verifyRequestAcceptance(
        input,
        vector.signature_hex,
        await publicKey(vector.pubkey_b64),
      ),
    ).toBe(false);
  });
});
