import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the "forked signature-base builder" disease.
//
// DISEASE: the RFC 9421 5-component request signature-base
// (@method @target-uri content-digest authorization signature-agent) is rendered
// by hardcoding those lines. Before the multisig work there was exactly ONE such
// renderer — buildRequestSignatureBase (core/sign-request.ts). The multisig
// append/verify faces MUST compose that generalized builder (via its optional
// chain-link arg), NOT fork a second copy of the 5-line template. A fork is how a
// future covered-component change silently drifts one path out of byte-parity with
// the Go oracle.
//
// This guard pins the invariant class-level: exactly one file under sdk/ts/core +
// sdk/ts/src renders the 5-component request base, and it is core/sign-request.ts.
// A new face that forks the template adds a second renderer and trips this guard.
//
// The 2-component GET-PoP base (src/pop.ts signatureBase) is a DISTINCT byte
// contract and is intentionally NOT counted — the fingerprint below
// requires the content-digest + authorization + signature-agent lines that only
// the 5-component request base carries, so the GET-PoP base never matches.
//
// The detector is REGEX-based and whitespace-tolerant on purpose (a formatter
// wrapping the template lines must not let a fork slip); the "would-be-missed"
// meta-test feeds a reformatted fork and asserts it is still caught.

const SRC_DIRS = ["core", "src"];
const CANONICAL_RENDERER = "core/sign-request.ts";

const dirPath = (name: string): string =>
  fileURLToPath(new URL(`../${name}`, import.meta.url));

// The 5-component request-base fingerprint: the three lines that distinguish the
// request base from the 2-component GET-PoP base. A file that renders all three
// as signature-base lines IS a request-base renderer.
const REQUEST_BASE_FINGERPRINT: RegExp[] = [
  /"content-digest":\s*\$\{/,
  /"authorization":\s*\$\{/,
  /"signature-agent":\s*\$\{/,
];

// rendersRequestBase is the pure predicate (extracted so the meta-tests can
// exercise it against synthetic source without touching the real files).
function rendersRequestBase(source: string): boolean {
  return REQUEST_BASE_FINGERPRINT.every((re) => re.test(source));
}

function tsFilesUnder(dir: string): string[] {
  const root = dirPath(dir);
  return readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts"))
    .map((e) => `${dir}/${e.name}`);
}

function requestBaseRenderers(): string[] {
  const found: string[] = [];
  for (const dir of SRC_DIRS) {
    for (const rel of tsFilesUnder(dir)) {
      if (rendersRequestBase(readFileSync(dirPath(rel), "utf8"))) found.push(rel);
    }
  }
  return found.sort();
}

describe("multisig base-builder reuse structural guard", () => {
  it("the 5-component request signature-base is rendered in exactly one file (no fork)", () => {
    expect(requestBaseRenderers()).toEqual([CANONICAL_RENDERER]);
  });

  it("the multisig verify face composes the shared verify helper, never a forked base", () => {
    const src = readFileSync(dirPath("core/verify-multisig-request.ts"), "utf8");
    expect(rendersRequestBase(src)).toBe(false);
    // and it must reuse the factored single-sig verify core
    expect(/verifyParsedSignature/.test(src)).toBe(true);
  });

  it("the append face composes the shared builder, never a forked base", () => {
    const src = readFileSync(dirPath("core/sign-request.ts"), "utf8");
    // appendSignature must call buildRequestSignatureBase, not re-render lines.
    expect(/export (async )?function appendSignature/.test(src)).toBe(true);
    const appendBody = src.slice(src.indexOf("function appendSignature"));
    expect(/buildRequestSignatureBase\(/.test(appendBody)).toBe(true);
  });

  // --- meta-tests: exercise the detector against synthetic source ------------
  it("[meta positive] catches a forked 5-component base template", () => {
    const fork = [
      'const base = [',
      '  `"@method": ${m}`,',
      '  `"@target-uri": ${u}`,',
      '  `"content-digest": ${d}`,',
      '  `"authorization": ${a}`,',
      '  `"signature-agent": ${s}`,',
      '].join("\\n");',
    ].join("\n");
    expect(rendersRequestBase(fork)).toBe(true);
  });

  it("[meta negative] does NOT flag the 2-component GET-PoP base", () => {
    const popBase = [
      'const base = [',
      '  `"@method": ${method}`,',
      '  `"@target-uri": ${url}`,',
      '  `"@signature-params": ${rawParams}`,',
      '].join("\\n");',
    ].join("\n");
    expect(rendersRequestBase(popBase)).toBe(false);
  });

  it("[meta would-be-missed] catches a reformatted fork (extra whitespace) a naive substring would slip", () => {
    const reformatted = [
      'const lines = [',
      '  `"content-digest":    ${digestHeader}`,',
      '  `"authorization":\t${authorization}`,',
      '  `"signature-agent":  ${signatureAgent}`,',
      "];",
    ].join("\n");
    expect(rendersRequestBase(reformatted)).toBe(true);
  });
});
