// Signed-URL + RFC 9421 GET-PoP byte-parity (TypeScript side) — TDD red for ixs7u.5.
//
// The Core Invariant for these two helpers is byte-identical output to the
// sdk/go oracle. Per the user-decided parity contract (see ixs7u.5 notes: "Go
// golden-emitter -> shared testdata"), the implement step adds a Go golden
// emitter under sdk/go/helpers that signs with the REAL Go signer and writes:
//
//   sdk/go/helpers/testdata/signedurl-vectors.json  (SignURLEd25519 output)
//   sdk/go/helpers/testdata/pop-vectors.json        (RFC 9421 GET-PoP output)
//
// This test asserts sdk/ts verify reaches the recorded verdict for each vector.
// It is RED now for TWO reasons, both expected:
//   1. sdk/ts/src/{verify,pop}.ts do not exist yet (imports cannot resolve).
//   2. The two vector JSON files do not exist yet (the Go emitter is a later
//      step). A missing vector file is itself a clean red — the guard is not
//      yet in place.
//
// LOAD-BEARING (why vectors come from the Go signer, never hand-authored):
// SignURLEd25519 emits the URL with a SORTED query (url.Values.Encode()); the
// TS verifier does NOT re-sort — it only strips `sig` and verifies "GET\n<url>".
// They agree ONLY when the verifier is fed the Go signer's canonically-sorted
// output. Hand-authored vectors would silently defeat that guard.
//
// PoP portability: pop.ts must expose the Ed25519 verify primitive as an
// INJECTABLE dependency (Fastly Compute lacks Ed25519 in SubtleCrypto). We drive
// BOTH a default-WebCrypto-primitive case (byte-identical output observed on the
// default path, not merely asserted in prose) AND an injected-primitive case.
import { describe, it, expect } from "vitest";
import { verifyEd25519SignedUrl } from "../src/verify.ts";
import { verifyAgentBinding } from "../src/pop.ts";
// These vector files are produced by the Go golden-emitter in a later step;
// referencing them by their planned paths keeps this test RED now (missing
// module) and green once the emitter + sdk/ts land.
import signedUrlVectors from "../../go/helpers/testdata/signedurl-vectors.json";
import popVectors from "../../go/helpers/testdata/pop-vectors.json";

// ---- signed-URL vectors ----------------------------------------------------
// Each vector is produced by SignURLEd25519 signing an unsigned URL; the TS
// verify (fed the injected resolveKey that returns the vector's public key) must
// reach the recorded verdict.
type SignedUrlVector = {
  name: string;
  pub_b64url: string; // raw 32-byte Ed25519 public key
  kid: string;
  signed_url: string; // SignURLEd25519 output (canonically-sorted query, incl. sig)
  now_unix: number; // clock the verifier is pinned to
  expected_valid: boolean;
};

// ---- PoP vectors -----------------------------------------------------------
// Each vector carries the full RFC 9421 GET-PoP material the Go signer emitted:
// the presented raw public key, the request line, the Signature-Input / Signature
// headers, the URL-bound agent_id (== thumbprint of presented key), and the
// clock. TS verifyAgentBinding must reach the recorded verdict.
type PopVector = {
  name: string;
  method: string;
  url: string; // @target-uri (carries agent_id param)
  agent_id: string; // thumbprint of the presented key
  presented_key_b64url: string; // raw 32-byte Ed25519 public key
  signature_input: string; // RFC 9421 Signature-Input header value
  signature: string; // RFC 9421 Signature header value
  now_unix: number;
  expected_valid: boolean;
};

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importEd25519PublicKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, [
    "verify",
  ]);
}

describe("sdk/ts signed-URL verify matches the Go signer vectors", () => {
  const vectors = signedUrlVectors as SignedUrlVector[];

  it("vector file is non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    it(`${v.name} -> valid=${v.expected_valid}`, async () => {
      const pub = await importEd25519PublicKey(b64urlToBytes(v.pub_b64url));
      const res = await verifyEd25519SignedUrl(v.signed_url, {
        now: () => v.now_unix * 1000,
        resolveKey: async (kid: string | undefined) =>
          kid === v.kid ? pub : undefined,
      });
      expect(res.valid).toBe(v.expected_valid);
    });
  }
});

describe("sdk/ts RFC 9421 GET-PoP verify matches the Go signer vectors", () => {
  const vectors = popVectors as PopVector[];

  it("vector file is non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  function headersFor(v: PopVector): Headers {
    const h = new Headers();
    h.set("x-ramp-agent-key", v.presented_key_b64url);
    h.set("signature-input", v.signature_input);
    h.set("signature", v.signature);
    return h;
  }

  // DEFAULT-primitive path: verifyAgentBinding uses its built-in WebCrypto
  // Ed25519 verify. This observes byte-identical output on the default path.
  for (const v of vectors) {
    it(`[default primitive] ${v.name} -> ok=${v.expected_valid}`, async () => {
      const res = await verifyAgentBinding({
        method: v.method,
        url: v.url,
        headers: headersFor(v),
        agentId: v.agent_id,
        now: () => v.now_unix * 1000,
      });
      expect(res.ok).toBe(v.expected_valid);
    });
  }

  // INJECTED-primitive path: the same vectors verified through a caller-supplied
  // Ed25519 verify primitive (the Fastly-style non-WebCrypto path). The verdict
  // MUST match the default path — the byte contract is the signature base, not
  // the primitive.
  for (const v of vectors) {
    it(`[injected primitive] ${v.name} -> ok=${v.expected_valid}`, async () => {
      const injectedVerify = async (
        pub: Uint8Array<ArrayBuffer>,
        sig: Uint8Array<ArrayBuffer>,
        msg: Uint8Array<ArrayBuffer>,
      ): Promise<boolean> => {
        const key = await importEd25519PublicKey(pub);
        return crypto.subtle.verify("Ed25519", key, sig, msg);
      };
      const res = await verifyAgentBinding({
        method: v.method,
        url: v.url,
        headers: headersFor(v),
        agentId: v.agent_id,
        now: () => v.now_unix * 1000,
        verifyEd25519: injectedVerify,
      });
      expect(res.ok).toBe(v.expected_valid);
    });
  }
});
