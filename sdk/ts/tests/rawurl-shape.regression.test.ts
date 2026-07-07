// Regression guard for the raw-URL runtime-shape divergence (RAMP-120).
//
// Some edge runtimes (Fastly Compute) hand the request URL as a URL-LIKE OBJECT
// rather than a primitive string. Both URL-consuming SDK faces — the Ed25519
// signed-URL verify (src/verify.ts) and the RFC 9421 GET-PoP verify (src/pop.ts)
// — assume a primitive string:
//
//   - verify.ts feeds the raw input to canonicalUrl(), which performs STRING ops
//     (indexOf/slice) to split the URL at its first "?" and preserve the
//     scheme+host+path VERBATIM (the OPAQUE-URL-BYTES contract). A non-string
//     input has no .indexOf and throws.
//   - pop.ts interpolates the raw input into the `@target-uri` line of the
//     signature base; a URL object stringifies via WHATWG toString() (lowercased
//     host, stripped :443, re-escaped path), silently diverging from the verbatim
//     bytes the agent signed -> pop_sig_invalid (a 403, not a 500, so it is
//     invisible to an e2e whose Request.url is already a normalized string).
//
// The fix coerces the raw URL to its opaque string form ONCE at each SDK
// boundary (String(input)), preserving verbatim bytes for the server-to-server
// string callers (a no-op) while making a Fastly-like URL-like object behave
// byte-identically to its string form.
//
// This test drives a Fastly-like URL-like object (a wrapper whose toString()
// returns the verbatim URL, exactly as a well-behaved edge runtime exposes the
// raw request URL) through BOTH faces and asserts byte-identical results to the
// string case. It goes RED if the boundary coercion is reverted: the verify face
// throws (canonicalUrl's string ops on a non-string), and the captured PoP
// signature base for the object case diverges from the string case.
import { describe, it, expect } from "vitest";
import { verifyEd25519SignedUrl } from "../src/verify.ts";
import { verifyAgentBinding, signatureBase } from "../src/pop.ts";
import { signEd25519SignedUrl } from "../src/signurl.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { encodeBase64Url, utf8Bytes } from "../src/base64url.ts";

// A "tricky" URL whose WHATWG-normalized form differs from its verbatim bytes:
// mixed-case host, explicit default :443, and a %20 in the path. If the SDK ever
// round-trips this through `new URL().toString()`, the bytes change and every
// signature over it breaks.
const TRICKY_PREFIX = "https://Example.COM:443/a%20b/c";
const NOW_SEC = 1_800_000_000;
const nowMs = () => NOW_SEC * 1000;

/**
 * A Fastly-like URL-like object: NOT a primitive string, but stringifies to the
 * verbatim URL via toString() (as a well-behaved edge runtime's request URL
 * does). `new URL(x)` and `String(x)` both coerce it losslessly; only the SDK's
 * own string ops (canonicalUrl.indexOf, the pop template literal) distinguish it
 * from a primitive string — which is exactly the shape the boundary coercion
 * must absorb.
 */
class FastlyLikeUrl {
  constructor(private readonly raw: string) {}
  toString(): string {
    return this.raw;
  }
}

async function genKeyPair(): Promise<{ priv: CryptoKey; pubRaw: Uint8Array<ArrayBuffer> }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { priv: kp.privateKey, pubRaw: raw as Uint8Array<ArrayBuffer> };
}

describe("signed-URL verify accepts a Fastly-like URL-like object (verbatim bytes preserved)", () => {
  it("URL-object input reaches the SAME verdict as the string input", async () => {
    const { priv, pubRaw } = await genKeyPair();
    const pub = await crypto.subtle.importKey("raw", pubRaw, { name: "Ed25519" }, false, [
      "verify",
    ]);
    const signed = await signEd25519SignedUrl(
      TRICKY_PREFIX,
      { kid: "k1", agentId: "", expUnix: NOW_SEC + 300 },
      priv,
    );
    const deps = {
      now: nowMs,
      resolveKey: async (kid: string | undefined) => (kid === "k1" ? pub : undefined),
    };

    const stringResult = await verifyEd25519SignedUrl(signed, deps);
    expect(stringResult.valid).toBe(true);

    // The URL-OBJECT shape MUST reach the identical verdict. On a revert of the
    // boundary coercion, canonicalUrl's string ops throw on this non-string input.
    const objectResult = await verifyEd25519SignedUrl(
      new FastlyLikeUrl(signed) as unknown as string,
      deps,
    );
    expect(objectResult).toEqual(stringResult);
    expect(objectResult.valid).toBe(true);
  });
});

describe("GET-PoP verify accepts a Fastly-like URL-like object (verbatim @target-uri)", () => {
  it("URL-object input produces a byte-identical signature base and verdict", async () => {
    const { priv, pubRaw } = await genKeyPair();
    const agentId = await thumbprint(pubRaw);
    const url = `${TRICKY_PREFIX}?agent_id=${agentId}&exp=${NOW_SEC + 300}`;

    const rawParams = `("@method" "@target-uri");keyid="${agentId}";alg="ed25519";created=${NOW_SEC};expires=${NOW_SEC + 300}`;
    const base = signatureBase("GET", url, rawParams);
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", priv, utf8Bytes(base)));

    const headers = new Headers();
    headers.set("x-ramp-agent-key", encodeBase64Url(pubRaw));
    headers.set("signature-input", `sig1=${rawParams}`);
    headers.set("signature", `sig1=:${encodeBase64Url(sig)}:`);

    // A capturing primitive records the exact signature-base bytes the verifier
    // reconstructs, so we can assert byte-identity between the string and object
    // shapes rather than merely comparing the boolean verdict.
    const captured: Uint8Array[] = [];
    const capturingVerify = async (
      pub: Uint8Array<ArrayBuffer>,
      s: Uint8Array<ArrayBuffer>,
      msg: Uint8Array<ArrayBuffer>,
    ): Promise<boolean> => {
      captured.push(msg);
      const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, [
        "verify",
      ]);
      return crypto.subtle.verify("Ed25519", key, s, msg);
    };

    const base_input = {
      method: "GET",
      headers,
      agentId,
      now: nowMs,
      verifyEd25519: capturingVerify,
    };

    const stringResult = await verifyAgentBinding({ ...base_input, url });
    expect(stringResult.ok).toBe(true);

    const objectResult = await verifyAgentBinding({
      ...base_input,
      url: new FastlyLikeUrl(url) as unknown as string,
    });
    expect(objectResult.ok).toBe(true);

    // Both faces reconstructed the SAME @target-uri bytes. On a revert of the pop
    // boundary coercion, the object shape's template-literal @target-uri diverges.
    expect(captured).toHaveLength(2);
    expect(Array.from(captured[1]!)).toEqual(Array.from(captured[0]!));
  });
});
