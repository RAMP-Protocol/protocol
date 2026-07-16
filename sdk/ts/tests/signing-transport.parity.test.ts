// sdk/ts SigningTransport / signOutbound outbound auto-sign parity + behavior.
//
// GAP: Go core.NewSigningTransport + SigningOption and Python SigningTransport /
// SignedOutbound exist; TS has only the low-level signRequest / appendSignature
// primitives — no outbound auto-sign wrapper. This suite is the TDD-red contract
// for the NEW sdk/ts/core/signing-transport.ts module:
//   - signOutbound({ privKey, keyid, method, url, body, authorization,
//     signatureAgent, window, appendOnly, prior? }) -> { headers, body }
//     (transport-neutral header core, Python SignedOutbound sibling);
//   - createSigningTransport(send, opts) -> a WHATWG-fetch-shaped send that buffers
//     the body, stamps Content-Digest / Signature-Input / Signature via signOutbound,
//     and forwards the SAME body bytes to the wrapped send.
//
// Core Invariant (agentic-content-access-hp5o2.2): the transport is a pure
// ORCHESTRATION of the already-parity-locked signRequest / appendSignature +
// clockWindow / monotonicWindow primitives — it stamps RFC 9421 headers
// byte-identical to the shared Go/Python oracle, forwards the request body
// UNMODIFIED, and adds NO new crypto and NO new signature-base rendering.
//
// Proof strategy (corpus-first, no new emitter): replay the SAME shared Go
// vectors the primitive suites already verify against
// (sdk/go/helpers/testdata/sign-request-vectors.json for the fresh-sig path,
// multisig-chain-vectors.json for the append/relay path) THROUGH the transport
// via a capturing fake send, and assert the stamped headers equal the vector
// fields byte-for-byte. Per the refined plan (MED-3) each vector injects a FIXED
// window ()=>[v.created, v.expires] — the DEFAULT clockWindow(now) drifts
// created/expires and the base would not reproduce; the windowless
// sign-request.parity.test.ts harness is adapted, NOT copied verbatim.
//
// RED until sdk/ts/core/signing-transport.ts exists: the import below resolves to
// a nonexistent module, so vitest fails at collection — the intended TDD-red
// signal for this additive-gap ticket (same convention as sign-request.parity /
// multisig-chain.parity, which are RED-on-import until their module lands).

import { describe, it, expect } from "vitest";
// RED: sdk/ts/core/signing-transport.ts does not exist yet (TDD red step).
import { createSigningTransport, signOutbound } from "../core/signing-transport.ts";
// The append/relay path reuses the already-landed primitives to arrange the
// upstream sig1 state the relay transport chains onto.
import { signRequest } from "../core/sign-request.ts";
// Use the EXPORTED header constant (do NOT string-literal "signature-agent").
import { SignatureAgentHeader } from "../src/wire.ts";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
import multisigVectors from "../../go/helpers/testdata/multisig-chain-vectors.json";

// ---------------------------------------------------------------------------
// Vector shapes (shared Go emitter output — the sole oracle).
// ---------------------------------------------------------------------------

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
  content_digest: string;
  signature_input: string;
  signature: string;
};

type MultisigHop = { keyid: string; pubkey_b64url: string; seed_hex: string };
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
};

// ---------------------------------------------------------------------------
// Byte helpers (adapted from sign-request.parity.test.ts — but the transport
// replay injects a FIXED window, it is NOT the windowless direct-signRequest
// harness).
// ---------------------------------------------------------------------------

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

function utf8(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(s)) as Uint8Array<ArrayBuffer>;
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

// A freshly generated signer for the option-behavior legs, which pin plumbing
// (window/append/predicate/set-if-absent), NOT byte-parity — any real key works.
async function genSigner(): Promise<{ privKey: CryptoKey; keyid: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { privKey: kp.privateKey, keyid: "test-key.v1" };
}

function bytesEqual(
  a: Uint8Array | undefined,
  b: Uint8Array | undefined,
): boolean {
  if (a === undefined || b === undefined) return a === b;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// The WHATWG-fetch-shaped outbound seam the transport wraps: send(url, init)
// carrying method/headers/body. The capturing fake records every forwarded call
// so a test can inspect the stamped headers AND the forwarded body bytes.
type Init = {
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array<ArrayBuffer>;
};
type Captured = { url: string; init: Init };

function capturingSend(): {
  send: (url: string, init: Init) => Promise<{ status: number }>;
  calls: Captured[];
} {
  const calls: Captured[] = [];
  const send = async (url: string, init: Init) => {
    calls.push({ url, init });
    return { status: 200 };
  };
  return { send, calls };
}

// ---------------------------------------------------------------------------
// (a)+(b) PARITY + BODY-INTEGRITY through the transport.
// ---------------------------------------------------------------------------

describe("createSigningTransport replays the shared Go sign-request vectors byte-identically", () => {
  const doc = signRequestVectors as { vectors: SignRequestVector[] };

  it("vector matrix is non-empty and includes the empty-signature-agent case", () => {
    expect(doc.vectors.length).toBeGreaterThan(0);
    const agents = new Set(doc.vectors.map((v) => v.signature_agent));
    expect(agents.has("")).toBe(true);
    expect(agents.has("https://agent.example")).toBe(true);
  });

  for (const v of doc.vectors) {
    it(`${v.name}: transport stamps Content-Digest/Signature-Input/Signature === Go oracle AND forwards the body unmodified`, async () => {
      const { send, calls } = capturingSend();
      const priv = await importSigningKey(v.signer_seed_hex);

      // FIXED window per vector (MED-3): reproduce the vector's created/expires;
      // the default clockWindow(now) would drift the base. Source the covered
      // signature_agent via the option when the vector's is non-empty.
      const signing = createSigningTransport(send, {
        privKey: priv,
        keyid: v.keyid,
        window: () => [v.created, v.expires] as [number, number],
        ...(v.signature_agent !== ""
          ? { signatureAgent: v.signature_agent }
          : {}),
      });

      const body = hexToBytes(v.body_hex);
      await signing(v.url, {
        method: v.method,
        headers: { authorization: v.authorization },
        body,
      });

      expect(calls.length).toBe(1);
      const fwd = calls[0] as Captured;
      const h = fwd.init.headers ?? {};

      // (a) PARITY: the stamped RFC 9421 artifacts equal the Go oracle fields.
      expect(h["content-digest"]).toBe(v.content_digest);
      expect(h["signature-input"]).toBe(v.signature_input);
      expect(h.signature).toBe(v.signature);

      // (b) BODY-INTEGRITY (the key regression guard): the FORWARDED body bytes
      // must equal the input body. A wrapper that buffers-for-digest but forwards
      // a consumed/empty body would still stamp a correct header and ship green —
      // so assert the body itself, not only the header.
      expect(bytesEqual(fwd.init.body, body)).toBe(true);
      // Recompute the digest over the FORWARDED body to double-lock (b): a body
      // swap that preserved length would still be caught here.
      const fwdDigest = new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          fwd.init.body ?? new Uint8Array(),
        ),
      );
      let b64 = "";
      // eslint-disable-next-line no-undef
      b64 = btoa(String.fromCharCode(...fwdDigest));
      expect(h["content-digest"]).toBe(`sha-256=:${b64}:`);
    });
  }
});

// ---------------------------------------------------------------------------
// signOutbound — the transport-neutral header core (Python SignedOutbound
// sibling). Same vectors, asserted directly on the returned {headers, body}.
// ---------------------------------------------------------------------------

describe("signOutbound returns the RFC 9421 header set byte-identical to the Go oracle", () => {
  const doc = signRequestVectors as { vectors: SignRequestVector[] };

  for (const v of doc.vectors) {
    it(`${v.name}: header core matches the oracle and returns the body unchanged`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const body = hexToBytes(v.body_hex);
      const out = await signOutbound({
        privKey: priv,
        keyid: v.keyid,
        method: v.method,
        url: v.url,
        body,
        authorization: v.authorization,
        signatureAgent: v.signature_agent,
        window: () => [v.created, v.expires] as [number, number],
      });

      expect(out.headers["content-digest"]).toBe(v.content_digest);
      expect(out.headers["signature-input"]).toBe(v.signature_input);
      expect(out.headers.signature).toBe(v.signature);
      // Transport-neutral core forwards the body untouched.
      expect(bytesEqual(out.body, body)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// (c) APPEND / relay path — set-if-absent preserves the upstream covered
// Signature-Agent, and the appended sig2 reproduces the Go 2-hop chain.
// ---------------------------------------------------------------------------

describe("createSigningTransport append/relay path mirrors the Go multisig chain", () => {
  const doc = multisigVectors as { vectors: MultisigChainVector[] };
  const byName = (n: string): MultisigChainVector => {
    const v = doc.vectors.find((x) => x.name === n);
    if (!v) throw new Error(`missing vector ${n}`);
    return v;
  };

  it("positive_two_hop: appendOnly transport chains sig2 AND preserves the upstream Signature-Agent (set-if-absent)", async () => {
    const v = byName("positive_two_hop");
    const h1 = v.hops[0] as MultisigHop;
    const h2 = v.hops[1] as MultisigHop;
    const body = hexToBytes(v.body_hex);

    // Arrange the incoming relayed request state: hop-0's sig1, whose covered set
    // already binds Signature-Agent = "https://agent.example". (signRequest is the
    // already-parity-locked primitive; this is setup, the transport is under test.)
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

    // The relay/broker transport carries its OWN directory origin. Set-if-absent
    // MUST NOT overwrite the agent's covered Signature-Agent — doing so would
    // break sig1 at the verifier.
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      privKey: await importSigningKey(h2.seed_hex),
      keyid: h2.keyid,
      window: () => [v.created, v.expires] as [number, number],
      appendOnly: true,
      signatureAgent: "https://broker.example.com",
    });

    await signing(v.url, {
      method: v.method,
      headers: {
        authorization: v.authorization,
        [SignatureAgentHeader]: v.signature_agent,
        "content-digest": sig1.contentDigest,
        "signature-input": sig1.signatureInput,
        signature: sig1.signature,
      },
      body,
    });

    expect(calls.length).toBe(1);
    const fwd = calls[0] as Captured;
    const h = fwd.init.headers ?? {};

    // Set-if-absent preserves the upstream agent directory (NOT the broker's).
    expect(h[SignatureAgentHeader]).toBe(v.signature_agent);
    // The appended sig2 reproduces the Go-emitted 2-hop chain byte-for-byte.
    expect(h["signature-input"]).toBe(v.signature_input);
    expect(h.signature).toBe(v.signature);
    expect(bytesEqual(fwd.init.body, body)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (d) OPTION-behavior — ported from sdk/go/core/transport_options_test.go.
// These pin the transport's plumbing (window / append / predicate / set-if-absent
// / defaults / no-body), not byte-parity, so a freshly generated signer is used.
// ---------------------------------------------------------------------------

describe("createSigningTransport option behavior (ported from Go transport_options_test.go)", () => {
  const BODY = utf8('{"test":true}');

  it("WithWindow: injects the supplied created/expires into Signature-Input", async () => {
    const { privKey, keyid } = await genSigner();
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      privKey,
      keyid,
      window: () => [1_700_000_000, 1_700_000_300] as [number, number],
    });

    await signing(
      "https://exchange.example.com/ramp.exchange.v1.ExchangeService/DiscoverResources",
      { method: "POST", headers: {}, body: BODY },
    );

    const sigInput = (calls[0] as Captured).init.headers?.["signature-input"];
    expect(sigInput).toBeDefined();
    expect(sigInput).toContain("created=1700000000");
    expect(sigInput).toContain("expires=1700000300");
  });

  it("appendOnly on a FRESH request still produces a valid sig1", async () => {
    const { privKey, keyid } = await genSigner();
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, { privKey, keyid, appendOnly: true });

    await signing("https://exchange.example.com/ramp.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const sigInput = (calls[0] as Captured).init.headers?.["signature-input"] ?? "";
    expect(sigInput).toContain("sig1=");
    expect(sigInput).not.toContain("sig2=");
  });

  it("a request already carrying a Signature is CHAINED (sig2), never replaced", async () => {
    // Prior-detection branch (Go sign(): appendOnly || req has Signature) — even
    // WITHOUT appendOnly, an incoming Signature triggers the append path.
    const { privKey, keyid } = await genSigner();

    // Arrange a real upstream sig1 to chain onto.
    const upstream = await genSigner();
    const sig1 = await signRequest(upstream.privKey, {
      method: "POST",
      url: "https://exchange.example.com/ramp.x/Y",
      body: BODY,
      authorization: "",
      signatureAgent: "",
      keyid: upstream.keyid,
      created: 1_700_000_000,
      expires: 1_700_000_300,
    });

    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, { privKey, keyid }); // no appendOnly

    await signing("https://exchange.example.com/ramp.x/Y", {
      method: "POST",
      headers: {
        "content-digest": sig1.contentDigest,
        "signature-input": sig1.signatureInput,
        signature: sig1.signature,
      },
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toContain("sig1=");
    expect(h["signature-input"]).toContain("sig2=");
    expect(h.signature).toContain("sig1=");
    expect(h.signature).toContain("sig2=");
  });

  it("WithSignatureAgent: stamps the directory when the header is ABSENT", async () => {
    const { privKey, keyid } = await genSigner();
    const dir = "https://broker.example.com";
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      privKey,
      keyid,
      signatureAgent: dir,
    });

    await signing("https://exchange.example.com/ramp.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h[SignatureAgentHeader]).toBe(dir);
  });

  it("WithSignatureAgent: PRESERVES an existing Signature-Agent header", async () => {
    const { privKey, keyid } = await genSigner();
    const agentDir = "https://agent.example.com";
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      privKey,
      keyid,
      signatureAgent: "https://broker.example.com",
    });

    await signing("https://exchange.example.com/ramp.x/Y", {
      method: "POST",
      headers: { [SignatureAgentHeader]: agentDir },
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h[SignatureAgentHeader]).toBe(agentDir);
  });

  it("predicate returning FALSE: request passes through UNSIGNED (not an error)", async () => {
    const { privKey, keyid } = await genSigner();
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      privKey,
      keyid,
      predicate: () => false,
    });

    await signing(
      "https://exchange.example.com/ramp.exchange.v1.ExchangeService/DiscoverResources",
      { method: "POST", headers: {}, body: BODY },
    );

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeUndefined();
    // Pass-through still forwards the body untouched.
    expect(bytesEqual((calls[0] as Captured).init.body, BODY)).toBe(true);
  });

  it("predicate returning TRUE: signs even a non-/ramp path", async () => {
    const { privKey, keyid } = await genSigner();
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      privKey,
      keyid,
      predicate: () => true,
    });

    await signing("https://exchange.example.com/other.service/Method", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeDefined();
  });

  it("default (zero options): signs any bodied request", async () => {
    const { privKey, keyid } = await genSigner();
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, { privKey, keyid });

    await signing("https://exchange.example.com/ramp.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeDefined();
    expect(h["content-digest"]).toBeDefined();
  });

  it("no-body request: passes through UNSIGNED (nothing to bind Content-Digest to)", async () => {
    const { privKey, keyid } = await genSigner();
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, { privKey, keyid });

    await signing("https://exchange.example.com/ramp.x/Y", {
      method: "GET",
      headers: {},
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeUndefined();
    expect(h["content-digest"]).toBeUndefined();
    expect((calls[0] as Captured).init.body).toBeUndefined();
  });
});
