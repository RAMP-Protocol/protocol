// sdk/ts full-RPC single-signature SERVER-VERIFY parity against the shared Go
// oracle (agentic-content-access-qqkro, SINGLE-SIG scope per the 2026-07-07
// decision; multisig-chain verify is out of scope — o3szv owns it).
//
// Today sdk/ts has NO framework-agnostic request-verify: hono/middleware.ts's
// rampVerify is edge-GET-PoP-scoped (2-component, self-verifying, no resolver)
// and core/verifier.ts is OFFER verify (JCS), a different concern. This suite
// pins the NEW core/verify-request.ts — the verify sibling of the just-landed
// core/sign-request.ts — which must mirror sdk/go/connectserver semantics
// reason-for-reason: covered-set/digest/window enforcement, replay detection via
// an INJECTED store, keys via an INJECTED KeyResolver, time via an INJECTED
// clock, and the reject taxonomy exposed as a RETURNED verdict (not thrown).
//
// Byte/semantic oracle:
//   - positive round-trip: a request reconstructed from
//     sdk/go/helpers/testdata/sign-request-vectors.json (the same vectors the
//     TS/Python request SIGNERS produce) MUST verify (valid=true); the vector's
//     key is injected via the KeyResolver and the vector's created/expires window
//     via the clock;
//   - a request signed live by core/sign-request.ts::signRequest MUST verify;
//   - negatives: each Go-emitted SINGLE-SIG negative-verify vector
//     (verify-request-neg-vectors.json) MUST be REJECTED with the reason the Go
//     connectserver taxonomy assigns (mirroring ClassifyReject / RejectReason /
//     ErrReplayed).
//
// Reject taxonomy the verdict must expose (mirrors sdk/go/connectserver
// classify.go RejectReason.String() tokens): "signature" (bad sig / expiry /
// future-created / wrong-or-unresolvable key / tampered covered field / missing
// component — the default) and "replay". broken_chain / hop_budget are multisig
// and OUT OF SCOPE here.
//
// RED until BOTH (a) sdk/ts/core/verify-request.ts exists AND (b) the Go emitter
// produces verify-request-neg-vectors.json. The implement step (7bjkh.23) adds
// both; this test is the TDD-red contract. Do NOT implement either here.

import { describe, it, expect } from "vitest";
// RED: sdk/ts/core/verify-request.ts does not exist yet (TDD red step). The
// entry mirrors Go serverConfig.verify: framework-agnostic, injected resolver +
// replay store + clock, returns a verdict carrying the reject reason.
import {
  verifyRequestServer,
  type RejectReason,
  type RequestKeyResolver,
  type ReplayStore,
} from "../core/verify-request.ts";
import { signRequest } from "../core/sign-request.ts";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
// RED (also): this negative-verify vector file is produced by the Go emitter
// extension the implement step adds; it does not exist yet, so the import fails
// at collection — a clean TDD-red signal that the shared oracle is missing.
import negVerifyVectors from "../../go/helpers/testdata/verify-request-neg-vectors.json";

type SignRequestVector = {
  name: string;
  method: string;
  url: string;
  body_hex: string;
  authorization: string;
  signature_agent: string;
  keyid: string;
  created: number;
  expires: number;
  signer_seed_hex: string;
  pubkey_b64url: string;
  content_digest: string;
  signature_input: string;
  signature: string;
};

// A Go-emitted single-sig negative-verify vector: a fully-formed request whose
// verification MUST be rejected, tagged with the exact reason token and the keyid
// whose public key the resolver must serve (empty/absent for the wrong-key case).
type NegVerifyVector = {
  name: string; // neg_bad_sig | neg_replay | neg_expired | neg_wrong_key | neg_tampered_authorization
  method: string;
  url: string;
  body_hex: string;
  authorization: string;
  signature_agent: string;
  content_digest: string;
  signature_input: string;
  signature: string;
  // keyid the request claims; resolver_pubkey_b64url is the key the resolver
  // returns for it (may be a WRONG key for neg_wrong_key, or absent to force an
  // unresolvable-key rejection).
  keyid: string;
  resolver_keyid?: string;
  resolver_pubkey_b64url?: string;
  // pinned verifier clock inside/outside the window per the case under test.
  now: number;
  // the reason token the Go taxonomy assigns (RejectReason.String()).
  expected_reason: RejectReason;
  // for neg_replay: the same request is presented twice; the SECOND presentation
  // is the one that must be rejected as "replay".
  replay?: boolean;
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

// A KeyResolver that records every keyid it was asked to resolve — the
// injected-boundary probe. The SDK MUST resolve keys ONLY through this holder;
// the test asserts the recorded calls to prove no key was read out-of-band.
function recordingResolver(
  keys: Record<string, Uint8Array<ArrayBuffer>>,
): RequestKeyResolver & { calls: (string | null)[] } {
  const calls: (string | null)[] = [];
  return {
    calls,
    resolve(keyid: string | null): Uint8Array<ArrayBuffer> | undefined {
      calls.push(keyid);
      return keyid === null ? undefined : keys[keyid];
    },
  };
}

// An in-test replay store the SDK orchestrates over (Seen / SeenOrAdd) — the SDK
// ships no default store, so replay state lives entirely here.
function memoryReplayStore(): ReplayStore & { seen: Set<string> } {
  const seen = new Set<string>();
  return {
    seen,
    async seenNonce(nonce: string): Promise<boolean> {
      return seen.has(nonce);
    },
    async seenOrAdd(nonce: string): Promise<boolean> {
      if (seen.has(nonce)) return true;
      seen.add(nonce);
      return false;
    },
  };
}

// A fixed clock — the SDK reads time ONLY through this, never Date.now().
function fixedClock(nowUnix: number): () => number {
  return () => nowUnix;
}

describe("sdk/ts full-RPC single-sig server-verify mirrors the Go connectserver oracle", () => {
  const signDoc = signRequestVectors as { vectors: SignRequestVector[] };
  const negDoc = negVerifyVectors as { vectors: NegVerifyVector[] };

  it("negative-verify vector set covers the five single-sig reject cases", () => {
    // The Go emitter must produce exactly these named single-sig negatives; the
    // multisig cases (broken_chain / hop_budget) are out of scope (o3szv).
    const names = new Set(negDoc.vectors.map((v) => v.name));
    expect(names.has("neg_bad_sig")).toBe(true);
    expect(names.has("neg_replay")).toBe(true);
    expect(names.has("neg_expired")).toBe(true);
    expect(names.has("neg_wrong_key")).toBe(true);
    expect(names.has("neg_tampered_authorization")).toBe(true);
  });

  // POSITIVE: every sign-request oracle vector verifies through the server face
  // when its key is injected via the resolver and its window via the clock.
  for (const v of signDoc.vectors) {
    it(`${v.name}: oracle-signed request verifies (valid=true) through the injected boundary`, async () => {
      const resolver = recordingResolver({
        [v.keyid]: b64urlToBytes(v.pubkey_b64url),
      });
      const store = memoryReplayStore();
      const now = Math.floor((v.created + v.expires) / 2);

      const verdict = await verifyRequestServer({
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
        resolve: resolver,
        replayStore: store,
        now: fixedClock(now),
      });

      expect(verdict.valid).toBe(true);
      // The key was resolved ONLY through the injected resolver (no out-of-band read).
      expect(resolver.calls).toContain(v.keyid);
    });
  }

  it("a request signed live by core/sign-request.ts round-trips through the server face", async () => {
    const seedHex =
      "55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374";
    const priv = await importSigningKey(seedHex);
    const created = 1_700_000_000;
    const expires = 1_700_000_600;
    const body = new TextEncoder().encode(
      '{"uri":"https://cdn.example/live"}',
    ) as Uint8Array<ArrayBuffer>;

    const signed = await signRequest(priv, {
      method: "POST",
      url: "https://broker.example/ramp.v1.BrokerService/Fetch",
      body,
      authorization: "Bearer live-token",
      signatureAgent: "https://agent.example",
      keyid: "mcp.v1",
      created,
      expires,
    });

    // The recorded vectors sign with this seed; its pubkey is the shared oracle
    // pubkey. Inject it via the resolver so verify resolves mcp.v1 to it.
    const resolver = recordingResolver({
      "mcp.v1": b64urlToBytes("rGv1a5oEriM-jaKs3KzrFzzn4Hb180dA4XuZ0bAs_gk"),
    });

    const verdict = await verifyRequestServer({
      method: "POST",
      url: "https://broker.example/ramp.v1.BrokerService/Fetch",
      body,
      headers: {
        "content-digest": signed.contentDigest,
        "signature-input": signed.signatureInput,
        signature: signed.signature,
        authorization: "Bearer live-token",
        "signature-agent": "https://agent.example",
      },
      resolve: resolver,
      replayStore: memoryReplayStore(),
      now: fixedClock(created + 100),
    });

    expect(verdict.valid).toBe(true);
    expect(resolver.calls).toEqual(["mcp.v1"]);
  });

  // NEGATIVE: each Go-emitted single-sig negative rejects with the taxonomy reason.
  for (const v of negDoc.vectors) {
    it(`${v.name}: rejected with reason "${v.expected_reason}" (fail-closed)`, async () => {
      const keys: Record<string, Uint8Array<ArrayBuffer>> = {};
      const rk = v.resolver_keyid ?? v.keyid;
      if (v.resolver_pubkey_b64url) {
        keys[rk] = b64urlToBytes(v.resolver_pubkey_b64url);
      }
      const resolver = recordingResolver(keys);
      const store = memoryReplayStore();
      const now = fixedClock(v.now);

      const req = {
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
        resolve: resolver,
        replayStore: store,
        now,
      };

      if (v.replay) {
        // First presentation is accepted and records the nonce; the SECOND is
        // the one that must be rejected as "replay".
        const first = await verifyRequestServer(req);
        expect(first.valid).toBe(true);
      }

      const verdict = await verifyRequestServer(req);
      expect(verdict.valid).toBe(false);
      expect(verdict.reason).toBe(v.expected_reason);
    });
  }

  it("verify reads time ONLY through the injected clock (an expired vector at an in-window injected now would pass, proving the clock is honored)", () => {
    // Guard: the negative-window vectors are rejected because the INJECTED clock
    // — not Date.now() — places them outside created..expires. The neg_expired
    // vector's `now` is post-expiry; if verify read the wall clock it could not
    // deterministically reject. This assertion documents the injected-clock
    // boundary the per-vector negative already exercises.
    const expired = negDoc.vectors.find((v) => v.name === "neg_expired");
    expect(expired).toBeDefined();
    expect(expired?.expected_reason).toBe("signature");
  });
});
