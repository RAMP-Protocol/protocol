// sdk/ts server-verify (Hono) binding smoke.
//
// Edge (src/edge/src/app.ts) is a SERVER/VERIFIER: it verifies inbound Ed25519
// signed-URLs and RFC 9421 GET-PoP agent-bindings and returns 403/deny. It is the
// ONLY in-repo TS consumer this ticket ships a binding for. This smoke drives an
// inbound signed request through the opt-in sdk/ts server/verify binding (a thin
// Hono middleware over sdk/ts/core's verify seam) and asserts the verdict comes
// back through that same binding — the outermost surface Edge actually adopts.
//
// The binding composes the shipped L1 verify primitives (verifyAgentBinding /
// verifyEd25519SignedUrl); the core adds NO new crypto — so the crypto is already
// covered by the L1 parity suites. This smoke pins the BINDING WIRING: a genuinely
// signed inbound request passes; an unsigned/forged one is denied, and the guarded
// handler never runs on the negative path (fail-closed, mirroring the Go
// connectserver verify middleware).
//
import { describe, it, expect } from "vitest";
import { rampVerify } from "../hono/middleware.ts";
import type { KeyResolverTs } from "../core/verifier.ts";

// A trivial WebCrypto Ed25519 keypair helper — the binding's verify primitive is
// WebCrypto by default (the same primitive the L1 pop/verify helpers use). The
// smoke does not re-test crypto; it exercises the middleware seam.
async function generateAgentKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;
}

describe("sdk/ts Hono server-verify binding (Edge's real consumer)", () => {
  it("an inbound signed request verifies through the binding and reaches the guarded handler", async () => {
    const kp = await generateAgentKey();
    const resolver: KeyResolverTs = {
      resolve: async () =>
        new Uint8Array(
          await crypto.subtle.exportKey("raw", kp.publicKey),
        ),
    };

    // The opt-in Hono middleware over sdk/ts/core: verifies the inbound RFC 9421
    // signature at the HTTP seam and, on success, passes control to next().
    const mw = rampVerify({ resolver });

    let reachedHandler = false;
    const next = async () => {
      reachedHandler = true;
    };

    // A minimal Hono-style context around a signed inbound Request. The binding
    // reads the request off the context and verifies it; wiring the exact signed
    // headers is the L1 sign side, exercised in the sign-request parity suite —
    // here we assert the seam accepts a genuinely-signed request.
    const signedReq = await signInboundRequest(kp);
    const ctx = { req: { raw: signedReq }, res: undefined as Response | undefined };

    await mw(ctx, next);
    expect(reachedHandler).toBe(true);
  });

  it("an unsigned inbound request is denied and never reaches the guarded handler (fail-closed)", async () => {
    const kp = await generateAgentKey();
    const resolver: KeyResolverTs = {
      resolve: async () =>
        new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
    };
    const mw = rampVerify({ resolver });

    let reachedHandler = false;
    const next = async () => {
      reachedHandler = true;
    };

    const nakedReq = new Request("https://edge.example/ramp.v1/resource", {
      method: "GET",
    });
    const ctx = { req: { raw: nakedReq }, res: undefined as Response | undefined };

    await mw(ctx, next);
    // Fail-closed: the guarded handler MUST NOT run, and the binding sets a deny
    // response.
    expect(reachedHandler).toBe(false);
    expect(ctx.res?.status).toBe(403);
  });
});

// signInboundRequest produces a genuinely RFC 9421 GET-PoP-signed inbound Request
// the binding must accept. Its body reuses the L1 sign path via sdk/ts/core's
// sign-over-Fetch-Request seam.
async function signInboundRequest(_kp: CryptoKeyPair): Promise<Request> {
  const { signInbound } = await import("../core/sign.ts");
  return signInbound(_kp, "https://edge.example/ramp.v1/resource");
}
