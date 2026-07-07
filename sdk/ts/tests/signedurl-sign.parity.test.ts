// sdk/ts signed-URL SIGN byte-parity against the Go oracle (TDD red for ov97t.16).
//
// Under the 3-SDKs=3-SDKs decision a TS Exchange must MINT signed delivery URLs,
// not only verify them. This suite pins the not-yet-existing TS sign face
// byte-identical to the Go oracle (helpers.SignURLEd25519): the emitted URL
// STRING must equal the Go-emitted `signed_url` for the same source URL, kid,
// agent_id, exp, and signer seed.
//
// THE CONTRACT UNDER TEST (Constantine, 2026-07-07): the signature covers
// `GET\n<url>` as OPAQUE URL BYTES. Neither signer nor verifier re-normalizes
// scheme/host/path — the ONLY permitted transform is deterministic query handling
// (add exp/kid/agent_id, remove sig, sort query). Today the verify faces normalize
// via `new URL()` (WHATWG lowercases host / strips :443 / percent-escapes path);
// that is the divergence this contract eliminates.
//
// RED now for THREE expected reasons, all intended:
//   1. sdk/ts/src/signurl.ts (the sign face) does not exist yet — import fails.
//   2. The signed-URL vectors do not yet carry `signer_seed_hex` (the Go emitter
//      extension is a later step), so a TS re-sign cannot reproduce the string.
//   3. The TRICKY-URL vectors named below (mixed-case host, explicit :443,
//      space/percent in the PATH) do not exist yet — they are the cases that
//      expose the normalization divergence, and are emitted in the implement step.
//
// LOAD-BEARING (why the sign vectors must come from the Go signer, and why the
// tricky ones are mandatory): a TS sign face that round-trips a raw origin URL
// through `new URL().toString()` for the canonical bytes silently diverges from
// Go on `https://CDN.Example:443/a path/doc` (Go preserves `CDN.Example:443` and
// escapes the space to `%20`; WHATWG lowercases the host, strips the :443, and
// re-escapes differently). Asserting the whole emitted STRING === the Go
// `signed_url` — over URLs that stress host case, default port, and path
// escaping — is the only assertion that catches it. A happy-ASCII vector would
// pass while the contract is broken.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/signurl.ts (the SIGN face) does not exist yet (TDD red).
import { signEd25519SignedUrl } from "../src/signurl.ts";
// The signed-URL vectors are extended with signer_seed_hex + tricky-URL sources
// by the Go emitter in a later step; referencing them keeps this RED until both
// the sign face and the extended vectors land.
import signedUrlVectors from "../../go/helpers/testdata/signedurl-vectors.json";

// Each vector is produced by SignURLEd25519. For SIGN parity the vector must also
// carry the SIGNER SEED (so TS can re-sign) and the SOURCE inputs (raw URL, kid,
// agent_id, exp) so the port reconstructs the exact same signed string.
type SignedUrlVector = {
  name: string;
  pub_b64url: string;
  kid: string;
  signed_url: string; // SignURLEd25519 output STRING (the byte oracle)
  now_unix: number;
  expected_valid: boolean;
  // --- SIGN-parity additions (emitted by the extended Go emitter) ---
  signer_seed_hex: string; // 32-byte Ed25519 seed the oracle signed with
  source_url: string; // the raw (unsigned) URL fed to SignURLEd25519
  agent_id: string; // "" for a bearer URL
  exp_unix: number; // the exp the oracle embedded
};

// The tricky-URL vector names the implement step MUST emit — the cases that expose
// the host-lowercasing / port-stripping / path-escaping divergence. Naming them
// here keeps the suite RED until they exist, and documents the contract they pin.
const REQUIRED_TRICKY_VECTORS = [
  "tricky_mixed_case_host",
  "tricky_explicit_default_port",
  "tricky_space_in_path",
  "tricky_percent_in_path",
];

// The fixed PKCS8 DER prefix for an Ed25519 private key; the 32-byte seed follows.
// WebCrypto cannot import a bare seed as "raw" for signing, so it is wrapped in
// PKCS8 and imported as "pkcs8" (idiom copied verbatim from acceptance.parity).
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

describe("sdk/ts signed-URL sign is byte-identical to the Go oracle", () => {
  // Cast through `unknown`: the committed vectors do not yet carry the SIGN-parity
  // fields (signer_seed_hex / source_url / agent_id / exp_unix), so the inferred
  // JSON type does not structurally overlap SignedUrlVector — exactly the TDD-red
  // condition this suite pins (the Go-emitter extension is a later step).
  const vectors = signedUrlVectors as unknown as SignedUrlVector[];

  it("vector file is non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  it("the tricky-URL vectors that expose the normalization divergence exist", () => {
    // These vectors — mixed-case host, explicit :443, space/percent in the PATH —
    // are the cases a `new URL()`-normalizing sign face gets WRONG. Their absence
    // is a legitimate TDD-red signal for the Go-emitter extension.
    const names = new Set(vectors.map((v) => v.name));
    for (const req of REQUIRED_TRICKY_VECTORS) {
      expect(names.has(req)).toBe(true);
    }
  });

  // POSITIVE parity: re-sign the vector's SOURCE under its signer seed and assert
  // the emitted string is byte-identical to the oracle's signed_url. Only genuine
  // (expected_valid, non-tampered) vectors carry a reproducible source.
  for (const v of vectors.filter((x) => x.expected_valid)) {
    it(`${v.name}: TS-emitted signed URL equals the Go oracle string`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const emitted = await signEd25519SignedUrl(
        v.source_url,
        { kid: v.kid, agentId: v.agent_id, expUnix: v.exp_unix },
        priv,
      );
      expect(emitted).toBe(v.signed_url);
    });
  }

  // NEGATIVE (Testing Doctrine point 10): re-signing the SAME source under the
  // WRONG seed MUST NOT reproduce the genuine signed_url. Ed25519 is deterministic,
  // so a different key yields a different sig → a different string.
  for (const v of vectors.filter((x) => x.expected_valid)) {
    it(`${v.name}: signing under a wrong seed does NOT match the oracle string`, async () => {
      const wrongSeedHex = `${"00".repeat(31)}01`;
      const wrong = await importSigningKey(wrongSeedHex);
      const emitted = await signEd25519SignedUrl(
        v.source_url,
        { kid: v.kid, agentId: v.agent_id, expUnix: v.exp_unix },
        wrong,
      );
      expect(emitted).not.toBe(v.signed_url);
    });
  }
});
