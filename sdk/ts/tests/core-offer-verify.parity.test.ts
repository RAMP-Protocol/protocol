// sdk/ts/core offer-verify parity — TDD red for ixs7u.10.
//
// The L2 core Verifier splits received offers into {verified, rejected} by
// ed25519-verifying the canonical offer-signature. Per the BINDING amendment on
// ixs7u.10 (user-decided), the signed payload is NO LONGER Go deterministic
// protobuf-binary — it is RFC 8785 JCS over the canonical proto-JSON of the Offer
// with signature/signature_algorithm cleared:
//
//     signed_payload = JCS(protojson(offer with sig+alg cleared))
//
// so any component (Go/TS/Python) can reproduce the exact signed bytes without a
// protobuf binary codec. TS core reproduces JCS(protojson(offer)) via a vetted
// JCS npm package over the generated types' JSON aligned to the pinned proto-JSON
// option set, then ed25519-verifies, returning {verified, rejected} + the
// unforgeable VerifiedOffer.
//
// This test is RED now for TWO expected reasons:
//   1. sdk/ts/core does not exist yet (the Verifier import cannot resolve).
//   2. The shared offer-verify vector MATRIX
//      sdk/go/helpers/testdata/offer-verify-vectors.json does not exist yet — the
//      implement step (a) switches Go canonicalOfferPayload to JCS(protojson),
//      (b) extends the Go golden emitter to emit this matrix. Referencing it by
//      its planned path keeps this test RED now.
//
// The matrix MUST exercise the hard encodings, not just a happy path (per the
// architect-review MEDIUM): minimal / Struct-ext-with->1-key (forces recursive
// JCS key-sort) / two-Timestamps / repeated-terms+enum / tamper-negative. A
// single vector would let Struct-key-ordering or Timestamp encoding diverge
// silently on real offers while the guard stays green.
import { describe, it, expect } from "vitest";
import { createVerifier } from "../core/verifier.ts";
import offerVerifyVectors from "../../go/helpers/testdata/offer-verify-vectors.json";

// Each vector is emitted by the Go oracle: an Offer (as canonical proto-JSON),
// the exchange offer-signing public key, the hex Ed25519 signature over
// JCS(protojson(offer)), the exchange identity the KeyResolver resolves, and the
// recorded verdict. A tamper vector carries a signature that does NOT verify.
type OfferVerifyVector = {
  name: string;
  exchange: string; // exchange identity the resolver keys on
  exchange_pub_b64url: string; // raw 32-byte Ed25519 offer-signing public key
  offer_json: unknown; // canonical proto-JSON of the Offer (incl. signature+alg)
  now_unix: number; // clock the Verifier's freshness gate is pinned to
  expected_verified: boolean; // true → lands in Verified, false → Rejected
};

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

describe("sdk/ts/core Verifier offer-verify matches the shared JCS oracle matrix", () => {
  const vectors = offerVerifyVectors as { vectors: OfferVerifyVector[] };

  it("vector matrix is non-empty", () => {
    expect(vectors.vectors.length).toBeGreaterThan(0);
  });

  it("matrix covers the hard JCS encodings (not just a happy path)", () => {
    // The architect-review MEDIUM: one happy-path vector passes while
    // Struct-key-ordering / Timestamp encoding / repeated-field ordering diverge
    // silently. Pin the required matrix names so the guard actually exercises
    // JCS's recursive key-sort, both Timestamps, repeated fields, and a negative.
    const names = new Set(vectors.vectors.map((v) => v.name));
    for (const required of [
      "minimal",
      "struct_ext_multi_key",
      "two_timestamps",
      "repeated_terms_enum",
      "tamper_negative",
    ]) {
      expect(names).toContain(required);
    }
  });

  it("matrix covers the freshness dimension (M-7 fail-closed contract)", () => {
    // The fail-closed expires_at verdict must stay exercised across ports; if the
    // corpus loses these, this guard goes red before a fail-open regression (a
    // missing expires_at silently treated as "fresh") can ship.
    const names = new Set(vectors.vectors.map((v) => v.name));
    for (const required of [
      "fresh_at_now_inclusive",
      "expired_past",
      "missing_expires_at",
    ]) {
      expect(names).toContain(required);
    }
  });

  for (const v of vectors.vectors) {
    it(`${v.name} -> verified=${v.expected_verified}`, async () => {
      const exchangePub = b64urlToBytes(v.exchange_pub_b64url);
      // Strict mode (fail-closed default): resolver knows exactly this exchange's
      // offer-signing key; the Verifier reproduces JCS(protojson(offer)) and
      // ed25519-verifies. Clock injected for the freshness gate.
      const verifier = createVerifier("strict", {
        resolve: async (exchange: string) =>
          exchange === v.exchange ? exchangePub : undefined,
        now: () => v.now_unix * 1000,
      });
      const result = await verifier.sort([v.offer_json]);
      if (v.expected_verified) {
        expect(result.verified).toHaveLength(1);
        expect(result.rejected).toHaveLength(0);
      } else {
        expect(result.verified).toHaveLength(0);
        expect(result.rejected).toHaveLength(1);
        expect(result.rejected[0]?.reason).toBeTruthy();
      }
    });
  }
});
