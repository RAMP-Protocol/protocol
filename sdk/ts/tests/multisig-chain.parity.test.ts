// sdk/ts multisig forwarding-chain append+verify parity against the shared Go
// oracle (agentic-content-access-o3szv). Go carries the ONLY multisig surface
// today (helpers.AppendSignature, VerifyMultisigRequest[Resolved], hop budget);
// under the 3-SDKs decision a TS broker must append and verify chains too. This
// suite is the TDD-red contract for the NEW ported faces.
//
// Core Invariant (o3szv): the RFC 9421 signature base — including the
// parameterized "signature";key="sigN" forwarding-chain component rendered as
// :stdbase64(decoded-predecessor-signature-bytes): — must reconstruct BYTE-FOR-
// BYTE in Go and TS, so a chain signed in Go verifies in TS AND the
// hop-budget / broken-chain / tampered-predecessor rejections match the Go
// taxonomy token-for-token. The shared Go emitter is the sole oracle.
//
// Faces under test (do NOT exist yet — RED):
//   - core/sign-request.ts::appendSignature — chains sig(N+1) onto a prior
//     {signatureInput, signature} WITHOUT disturbing existing members; appending
//     to an unsigned request (empty prev) is byte-identical to signRequest (N=1).
//   - core/verify-multisig-request.ts::verifyMultisigRequestServer — parses ALL
//     labels, enforces the hop budget FIRST (hop_budget), the structural chain
//     next (broken_chain), then verifies each hop (signature); returns a verdict
//     carrying the verified keyids in chain order, never throws.
//
// Reject precedence the verdict must expose (mirrors Go verify.go:477):
//   hop_budget → broken_chain → signature.
//
// RED until BOTH faces exist. The imports below resolve to nonexistent modules,
// so tsc errors and vitest fails at collection — a clean TDD-red signal.

import { describe, it, expect } from "vitest";
// RED: neither module exists yet (TDD red step).
import { signRequest, appendSignature } from "../core/sign-request.ts";
import {
  verifyMultisigRequestServer,
  type MultisigRejectReason,
  type MultisigKeyResolver,
} from "../core/verify-multisig-request.ts";
import multisigVectors from "../../go/helpers/testdata/multisig-chain-vectors.json";

type MultisigHop = {
  keyid: string;
  pubkey_b64url: string;
  seed_hex: string;
};

// A Go-emitted forwarding-chain vector: the full wire request (all labels), the
// per-hop identities, and the outcome the REAL Go oracle reaches — verified
// keyids in chain order for a positive, or the reject reason token for a
// negative (hop_budget / broken_chain / signature).
type MultisigChainVector = {
  name: string;
  method: string;
  url: string;
  body_hex: string;
  authorization: string;
  signature_agent: string;
  created: number;
  expires: number;
  content_digest: string;
  signature_input: string;
  signature: string;
  hops: MultisigHop[];
  max_signatures: number;
  expected_verified: boolean;
  expected_keyids: string[] | null;
  expected_reason: string;
};

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

async function importSigningKey(seedHex: string): Promise<CryptoKey> {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
    "sign",
  ]);
}

// A resolver that serves the per-hop pubkeys keyed by keyid — the injected
// boundary the multisig verify face resolves EVERY hop key through.
function hopResolver(hops: MultisigHop[]): MultisigKeyResolver {
  const keys: Record<string, Uint8Array<ArrayBuffer>> = {};
  for (const h of hops) keys[h.keyid] = b64urlToBytes(h.pubkey_b64url);
  return {
    resolve(keyid: string | null): Uint8Array<ArrayBuffer> | undefined {
      return keyid === null ? undefined : keys[keyid];
    },
  };
}

const fixedClock = (nowUnix: number) => () => nowUnix;

describe("sdk/ts multisig forwarding-chain append+verify mirrors the Go oracle", () => {
  const doc = multisigVectors as { vectors: MultisigChainVector[] };
  const byName = (n: string): MultisigChainVector => {
    const v = doc.vectors.find((x) => x.name === n);
    if (!v) throw new Error(`missing vector ${n}`);
    return v;
  };
  const hopAt = (v: MultisigChainVector, i: number): MultisigHop => {
    const h = v.hops[i];
    if (!h) throw new Error(`vector ${v.name} missing hop ${i}`);
    return h;
  };

  it("vector set covers the positive + all four negative chain cases", () => {
    const names = new Set(doc.vectors.map((v) => v.name));
    expect(names.has("positive_two_hop")).toBe(true);
    expect(names.has("hop_budget_three_over_two")).toBe(true);
    expect(names.has("broken_chain_reordered")).toBe(true);
    expect(names.has("broken_chain_stripped_middle")).toBe(true);
    expect(names.has("broken_chain_missing_link")).toBe(true);
    expect(names.has("tampered_predecessor")).toBe(true);
  });

  // POSITIVE: the Go-signed 2-hop chain verifies through the TS face and returns
  // the verified keyids in chain order (sig1 agent, sig2 broker).
  it("positive_two_hop verifies and returns keyids in chain order", async () => {
    const v = byName("positive_two_hop");
    const now = Math.floor((v.created + v.expires) / 2);
    const verdict = await verifyMultisigRequestServer({
      method: v.method,
      url: v.url,
      body: hexToBytes(v.body_hex),
      headers: {
        "content-digest": v.content_digest,
        "signature-input": v.signature_input,
        signature: v.signature,
        authorization: v.authorization,
        "signature-agent": v.signature_agent,
      },
      resolve: hopResolver(v.hops),
      now: fixedClock(now),
    });
    expect(verdict.valid).toBe(true);
    expect(verdict.keyids).toEqual(v.expected_keyids);
  });

  // BYTE-IDENTITY: re-signing the chain live (signRequest sig1 + appendSignature
  // sig2) under the Go hop seeds reproduces the Go-emitted Signature-Input and
  // Signature byte-for-byte — the cross-language chain-link contract.
  it("appendSignature reproduces the Go 2-hop chain byte-identically", async () => {
    const v = byName("positive_two_hop");
    const h1 = hopAt(v, 0);
    const h2 = hopAt(v, 1);
    const body = hexToBytes(v.body_hex);

    const sig1 = await signRequest(await importSigningKey(h1.seed_hex), {
      method: v.method,
      url: v.url,
      body,
      authorization: v.authorization,
      signatureAgent: v.signature_agent,
      keyid: h1.keyid,
      created: v.created,
      expires: v.expires,
    });

    const chained = await appendSignature(
      await importSigningKey(h2.seed_hex),
      { signatureInput: sig1.signatureInput, signature: sig1.signature },
      {
        method: v.method,
        url: v.url,
        body,
        authorization: v.authorization,
        signatureAgent: v.signature_agent,
        keyid: h2.keyid,
        created: v.created,
        expires: v.expires,
      },
    );

    expect(chained.signatureInput).toBe(v.signature_input);
    expect(chained.signature).toBe(v.signature);
  });

  // N=1 INVARIANT: appending to an unsigned request (empty prev) is byte-identical
  // to signRequest — the load-bearing single-sig-is-N=1 property.
  it("appendSignature to an unsigned request equals signRequest (N=1)", async () => {
    const v = byName("positive_two_hop");
    const h1 = hopAt(v, 0);
    const body = hexToBytes(v.body_hex);
    const opts = {
      method: v.method,
      url: v.url,
      body,
      authorization: v.authorization,
      signatureAgent: v.signature_agent,
      keyid: h1.keyid,
      created: v.created,
      expires: v.expires,
    };
    const signed = await signRequest(await importSigningKey(h1.seed_hex), opts);
    const appended = await appendSignature(
      await importSigningKey(h1.seed_hex),
      { signatureInput: "", signature: "" },
      opts,
    );
    expect(appended.signatureInput).toBe(signed.signatureInput);
    expect(appended.signature).toBe(signed.signature);
  });

  // NEGATIVES: each Go-emitted chain reject case rejects (valid=false) with the
  // exact taxonomy token, honoring the hop_budget → broken_chain → signature
  // precedence encoded in the vectors.
  for (const name of [
    "hop_budget_three_over_two",
    "broken_chain_reordered",
    "broken_chain_stripped_middle",
    "broken_chain_missing_link",
    "tampered_predecessor",
  ]) {
    it(`${name} rejects with the Go-emitted reason`, async () => {
      const v = byName(name);
      const now = Math.floor((v.created + v.expires) / 2);
      const verdict = await verifyMultisigRequestServer({
        method: v.method,
        url: v.url,
        body: hexToBytes(v.body_hex),
        headers: {
          "content-digest": v.content_digest,
          "signature-input": v.signature_input,
          signature: v.signature,
          authorization: v.authorization,
          "signature-agent": v.signature_agent,
        },
        resolve: hopResolver(v.hops),
        now: fixedClock(now),
        maxSignatures: v.max_signatures,
      });
      expect(verdict.valid).toBe(false);
      expect(verdict.reason).toBe(v.expected_reason as MultisigRejectReason);
    });
  }

  // SEC-NEW-2: entitlement coverage is enforced PER HOP on the multisig path,
  // mirroring Go's verifySingleSignature (which runs enforceEntitlementCoverage)
  // being called per hop by VerifyMultisigRequest. A live 2-hop chain — whose
  // covered set is the RAMP required-5 and NEVER commits to x-entitlement-token —
  // carrying an X-Entitlement-Token header MUST be rejected "signature", exactly
  // like the single-sig neg_entitlement_uncovered vector. Without threading the
  // header into the per-hop verify this gate is dead on the multisig path.
  it("a 2-hop chain carrying an uncovered X-Entitlement-Token header is rejected (signature)", async () => {
    const v = byName("positive_two_hop");
    const h1 = hopAt(v, 0);
    const h2 = hopAt(v, 1);
    const body = hexToBytes(v.body_hex);
    const shared = {
      method: v.method,
      url: v.url,
      body,
      authorization: v.authorization,
      signatureAgent: v.signature_agent,
      created: v.created,
      expires: v.expires,
    };

    const sig1 = await signRequest(await importSigningKey(h1.seed_hex), {
      ...shared,
      keyid: h1.keyid,
    });
    const chained = await appendSignature(
      await importSigningKey(h2.seed_hex),
      { signatureInput: sig1.signatureInput, signature: sig1.signature },
      { ...shared, keyid: h2.keyid },
    );

    const now = Math.floor((v.created + v.expires) / 2);
    const base = {
      method: v.method,
      url: v.url,
      body,
      headers: {
        "content-digest": chained.contentDigest,
        "signature-input": chained.signatureInput,
        signature: chained.signature,
        authorization: v.authorization,
        "signature-agent": v.signature_agent,
      },
      resolve: hopResolver(v.hops),
      now: fixedClock(now),
    };

    // Control: without the header the same chain verifies (coverage constraint
    // only bites when the entitlement header is present).
    const ok = await verifyMultisigRequestServer(base);
    expect(ok.valid).toBe(true);

    // With the uncovered entitlement header present, EVERY hop's coverage gate
    // fires and the chain is rejected "signature".
    const verdict = await verifyMultisigRequestServer({
      ...base,
      headers: {
        ...base.headers,
        "x-entitlement-token": "jwt:demo-unsigned-entitlement-token",
      },
    });
    expect(verdict.valid).toBe(false);
    expect(verdict.reason).toBe("signature");
  });

  // R2-4: per-hop MaxSignatureAge lifetime clamp, enforced on EVERY hop exactly
  // like the single-sig path (Go enforceCreatedExpires with maxAge, called per
  // hop). The bound is inclusive: a window equal to it passes, one exceeding it is
  // rejected "signature"; 0/undefined is unbounded.
  describe("R2-4 per-hop MaxSignatureAge clamp on the multisig path", () => {
    const v = () => byName("positive_two_hop");

    async function verifyWithMaxAge(
      maxSignatureAge: number | undefined,
    ): Promise<MultisigRejectReason | "valid"> {
      const vec = v();
      const now = Math.floor((vec.created + vec.expires) / 2);
      const verdict = await verifyMultisigRequestServer({
        method: vec.method,
        url: vec.url,
        body: hexToBytes(vec.body_hex),
        headers: {
          "content-digest": vec.content_digest,
          "signature-input": vec.signature_input,
          signature: vec.signature,
          authorization: vec.authorization,
          "signature-agent": vec.signature_agent,
        },
        resolve: hopResolver(vec.hops),
        now: fixedClock(now),
        ...(maxSignatureAge !== undefined ? { maxSignatureAge } : {}),
      });
      return verdict.valid ? "valid" : (verdict.reason as MultisigRejectReason);
    }

    it("unbounded (undefined) accepts the chain's declared window", async () => {
      expect(await verifyWithMaxAge(undefined)).toBe("valid");
    });

    it("maxAge exactly equal to the window is accepted (inclusive bound)", async () => {
      const window = v().expires - v().created;
      expect(await verifyWithMaxAge(window)).toBe("valid");
    });

    it("maxAge above the window is accepted", async () => {
      const window = v().expires - v().created;
      expect(await verifyWithMaxAge(window + 1)).toBe("valid");
    });

    it("maxAge below the window rejects the chain (signature)", async () => {
      const window = v().expires - v().created;
      expect(await verifyWithMaxAge(window - 1)).toBe("signature");
    });
  });
});
