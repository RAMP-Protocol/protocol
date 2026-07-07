import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the raw-URL runtime-shape divergence (RAMP-120). The
// sweep-verify atom requires a class-level counter-measure so a future edit
// cannot silently re-introduce the disease the fix eliminated: a URL-consuming
// SDK boundary that feeds its RAW url parameter into a string-op / @target-uri
// sink (canonicalMessage/new URL/signatureBase) instead of the opaqueUrl-coerced
// value. A URL-like object (Fastly Compute) then either throws (canonicalUrl
// string ops) or silently WHATWG-normalizes (@target-uri template literal).
//
// SCOPE — the two public VERIFY faces only (src/verify.ts, src/pop.ts). The
// sibling sign faces + core/verify-request.ts are the SAME disease but are
// tracked/fixed under their own ticket (g5ok5); guarding them here would
// false-fire before that fix lands.
//
// The behavioral guard is rawurl-shape.regression.test.ts (drives a Fastly-like
// URL-like object through both faces). This file adds the source-level guard the
// sweep atom asks for: it pins that the boundary coercion stays in place.
//
// The detector is REGEX-based and whitespace-tolerant on purpose: a naive
// substring like "signatureBase(input.method, input.url" silently stops matching
// the moment a formatter wraps the args onto separate lines, so a revert would
// slip. The "would-be-missed" meta-test below feeds exactly that reformatted
// variant and asserts the guard still catches it.

const srcPath = (name: string): string =>
  fileURLToPath(new URL(`../src/${name}`, import.meta.url));

function readSource(name: string): string {
  return readFileSync(srcPath(name), "utf8");
}

interface SiteGuard {
  file: string;
  /** RAW-input-reaches-sink forms that MUST be absent (the disease). */
  forbidden: RegExp[];
  /** Boundary-coercion markers that MUST be present (the fix). */
  required: RegExp[];
}

// evalSite is the pure predicate (extracted so the meta-tests can exercise the
// guard logic against synthetic source without touching the real files). It
// returns one message per violation.
function evalSite(source: string, guard: SiteGuard): string[] {
  const out: string[] = [];
  for (const re of guard.forbidden) {
    if (re.test(source)) out.push(`${guard.file}: forbidden raw-url sink ${re}`);
  }
  for (const re of guard.required) {
    if (!re.test(source)) out.push(`${guard.file}: missing boundary coercion ${re}`);
  }
  return out;
}

const GUARDS: SiteGuard[] = [
  {
    file: "verify.ts",
    // The raw `rawUrl` parameter must NOT flow directly into the URL parser or
    // the canonical message; both must consume the opaqueUrl-coerced `raw`.
    forbidden: [/\bnew URL\(\s*rawUrl\s*\)/, /\bcanonicalMessage\(\s*rawUrl\s*\)/],
    required: [/\bopaqueUrl\(\s*rawUrl\s*\)/],
  },
  {
    file: "pop.ts",
    // The raw `input.url` must NOT flow directly into the signature base; the
    // boundary must pass the opaqueUrl-coerced local instead.
    forbidden: [/\bsignatureBase\(\s*[^,]+,\s*input\.url\b/],
    required: [/\bopaqueUrl\(\s*input\.url\s*\)/],
  },
];

describe("raw-URL runtime-shape structural guard", () => {
  for (const guard of GUARDS) {
    it(`${guard.file} coerces its URL input at the boundary`, () => {
      expect(evalSite(readSource(guard.file), guard)).toEqual([]);
    });
  }

  // --- meta-tests: exercise the detector against synthetic source ----------
  const popGuard = GUARDS.find((g) => g.file === "pop.ts")!;

  it("[meta positive] catches the raw input.url disease", () => {
    const bad = "const base = signatureBase(input.method, input.url, parsed.rawParams);";
    expect(evalSite(bad, popGuard).length).toBeGreaterThan(0);
  });

  it("[meta negative] passes the coerced-boundary form", () => {
    const good = [
      "const url = opaqueUrl(input.url);",
      "const base = signatureBase(input.method, url, parsed.rawParams);",
    ].join("\n");
    expect(evalSite(good, popGuard)).toEqual([]);
  });

  it("[meta would-be-missed] catches the reformatted (multiline / no-space) variant a substring guard would slip", () => {
    const reformatted = [
      "const base = signatureBase(",
      "  input.method,",
      "  input.url,",
      "  parsed.rawParams,",
      ");",
      "const url = opaqueUrl(input.url);", // required marker present so ONLY the forbidden fires
    ].join("\n");
    const violations = evalSite(reformatted, popGuard);
    expect(violations.length).toBe(1);
    expect(violations[0]).toContain("forbidden raw-url sink");
  });
});
