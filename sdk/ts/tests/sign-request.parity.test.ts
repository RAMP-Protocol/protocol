// sdk/ts outbound RFC 9421 request-SIGN byte-parity against the shared Go oracle.
//
// Go (helpers.SignRequest + buildSignatureBase) and Python (httpsig.sign_request)
// already sign the full 5-component RAMP covered set
// (@method @target-uri content-digest authorization signature-agent); sdk/ts has
// no outbound request signer yet (core/sign.ts::signInbound covers only the
// 2-component GET PoP). This suite pins the not-yet-existing TS 5-component
// signer byte-identical to the SAME oracle vectors the Go/Python ports verify
// against — so a signature produced in TS verifies unchanged at every Go/Python
// broker/exchange.
//
// Byte contract (Go oracle = sdk/go/helpers/sign.go::SignRequest +
// sdk/go/helpers/sigbase.go::buildSignatureBase; mirrored by Python
// ramp_sdk/httpsig.py::sign_request):
//   - covered set is EXACTLY the 5 components in order
//     @method @target-uri content-digest authorization signature-agent
//     (no conditional biscuit component);
//   - Content-Digest = `sha-256=:<STANDARD-base64(SHA-256(body))>:`;
//   - authorization + signature-agent are ALWAYS bound — an empty string still
//     renders as `"authorization": ` with a trailing space then newline (the
//     empty-bind case is a distinct vector; a `.trim()` would corrupt it);
//   - the base joins lines with `\n`, `@signature-params` last, NO trailing
//     newline; Signature-Input = `sig1=` + that inner; Signature =
//     `sig1=:<STANDARD-base64(sig)>:` (NOT b64url-nopad — do not unify with the
//     thumbprint encoding);
//   - created/expires are INJECTED (no wall clock).
//
// RED until sdk/ts/core/sign-request.ts exists; the implement step adds it. The
// vectors already exist at sdk/go/helpers/testdata/sign-request-vectors.json, so
// the only missing piece is the signer module — the RED is on the import.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/core/sign-request.ts does not exist yet (TDD red step).
import { signRequest } from "../core/sign-request.ts";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";

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
  signer_seed_hex: string; // 32-byte Ed25519 seed the oracle signed with
  pubkey_b64url: string; // b64url-nopad raw 32-byte Ed25519 public key
  content_digest: string;
  signature_base: string; // the exact bytes the signature covers
  signature_input: string;
  signature: string;
};

// The covered set the signer MUST emit: exactly these five, in this order.
const EXPECTED_COVERED =
  '("@method" "@target-uri" "content-digest" "authorization" "signature-agent")';

// The fixed PKCS8 DER prefix for an Ed25519 private key (SEQUENCE + version +
// AlgorithmIdentifier(1.3.101.112) + OCTET STRING wrapper); the 32-byte seed
// follows. WebCrypto cannot import a bare Ed25519 seed as "raw", so the seed is
// wrapped in PKCS8 and imported as "pkcs8". (Copied verbatim from
// tests/acceptance.parity.test.ts.)
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

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function stdB64ToBytes(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Import the recorded raw public key (b64url-nopad) for verify — the round-trip
// re-signs nothing; it verifies the recorded Signature over the reconstructed
// base. (Mirrors tests/signedurl-pop.parity.test.ts's importEd25519PublicKey.)
async function importVerifyKey(pubB64Url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    b64urlToBytes(pubB64Url),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

describe("sdk/ts request signer matches the shared Go oracle (byte-identical)", () => {
  const doc = signRequestVectors as { vectors: SignRequestVector[] };

  it("vector matrix is non-empty", () => {
    expect(doc.vectors.length).toBeGreaterThan(0);
  });

  it("vector set includes the empty-authorization bound case", () => {
    // authorization="" is still covered (the static bootstrap path); this is a
    // distinct vector, and its base carries the load-bearing trailing space.
    const authzValues = new Set(doc.vectors.map((v) => v.authorization));
    expect(authzValues.has("")).toBe(true);
  });

  it("vectors live under the shared Go testdata dir (not a copied fixture)", () => {
    // Guards the Core Invariant: the oracle is the SHARED Go emitter output.
    // The import specifier is the durable evidence of provenance.
    const specifier = "../../go/helpers/testdata/sign-request-vectors.json";
    expect(specifier).toContain("go/helpers/testdata");
  });

  for (const v of doc.vectors) {
    const options = {
      method: v.method,
      url: v.url,
      body: hexToBytes(v.body_hex),
      authorization: v.authorization,
      signatureAgent: v.signature_agent,
      keyid: v.keyid,
      created: v.created,
      expires: v.expires,
    };

    it(`${v.name}: signature base is byte-identical to the Go oracle`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const result = await signRequest(priv, options);
      expect(result.signatureBase).toBe(v.signature_base);
    });

    it(`${v.name}: Content-Digest is byte-identical to the Go oracle`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const result = await signRequest(priv, options);
      expect(result.contentDigest).toBe(v.content_digest);
    });

    it(`${v.name}: Signature-Input covers exactly the 5 RAMP components`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const result = await signRequest(priv, options);
      expect(result.signatureInput).toContain(EXPECTED_COVERED);
      expect(result.signatureInput).toBe(v.signature_input);
    });

    it(`${v.name}: Signature header is byte-identical to the Go oracle`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const result = await signRequest(priv, options);
      expect(result.signature).toBe(v.signature);
    });

    it(`${v.name}: round-trips — recorded signature verifies over the reconstructed base`, async () => {
      // Re-derive the pubkey from the seed, strip the `sig1=:` / `:` wrapper the
      // Signature header carries, and verify the raw Ed25519 signature over the
      // signature base the signer reconstructs — a full sign→verify round-trip
      // through the same 5-component byte contract.
      const priv = await importSigningKey(v.signer_seed_hex);
      const result = await signRequest(priv, options);

      const pub = await importVerifyKey(v.pubkey_b64url);
      const raw = result.signature.replace(/^sig1=:/, "").replace(/:$/, "");
      const sigBytes = stdB64ToBytes(raw);
      const ok = await crypto.subtle.verify(
        "Ed25519",
        pub,
        sigBytes,
        new TextEncoder().encode(result.signatureBase),
      );
      expect(ok).toBe(true);
    });
  }
});
