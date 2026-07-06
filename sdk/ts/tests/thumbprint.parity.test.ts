// Thumbprint parity (TypeScript side) — TDD red for ixs7u.5.
//
// sdk/ts `thumbprint(pubkey)` MUST reproduce, byte-for-byte, the RFC 7638 JWK
// Thumbprint the sdk/go oracle emits. The shared vectors at
// sdk/go/helpers/testdata/thumbprint-vectors.json are the cross-language guard:
// each entry is a base64url-no-pad raw 32-byte Ed25519 public key and its
// expected base64url-no-pad thumbprint (= base64url(SHA-256(canonical JWK))).
// The last vector uses the RFC 8032 Ed25519 test-vector public key.
//
// This test is RED now purely because sdk/ts does not exist yet (the module
// import below cannot resolve). The implement step relocates the app's
// src/edge/src/thumbprint.ts into sdk/ts/src/thumbprint.ts, at which point this
// goes green with no change to the assertions.
import { describe, it, expect } from "vitest";
import { thumbprint } from "../src/thumbprint.ts";
import vectorsFile from "../../go/helpers/testdata/thumbprint-vectors.json";

type ThumbVector = { public_key_b64url: string; thumbprint: string };
type ThumbVectorsFile = { vectors: ThumbVector[] };

// base64url-no-pad decode — the vectors carry the pubkey in the same encoding
// the SDK's own encodeBase64Url produces, so decoding here is the inverse the
// oracle's Go side already round-trips.
function decodeBase64UrlNoPad(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

describe("sdk/ts thumbprint matches the sdk/go oracle vectors", () => {
  const vectors = (vectorsFile as ThumbVectorsFile).vectors;

  it("vector file is non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    it(`thumbprint(${v.public_key_b64url}) === ${v.thumbprint}`, async () => {
      const pub = decodeBase64UrlNoPad(v.public_key_b64url);
      expect(pub.length).toBe(32);
      const got = await thumbprint(pub);
      expect(got).toBe(v.thumbprint);
    });
  }
});
