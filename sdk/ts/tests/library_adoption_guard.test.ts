import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the sdk/ts L1 relocation (ixs7u.5). This is the
// class-level counter-measure the sweep-verify atom requires: it pins that the
// canonical sdk/ts helpers keep composing the generated artifacts + the fixed
// byte contract, so a future edit cannot silently re-introduce the disease the
// port eliminated (hand-rolled wire-type mirrors instead of the generated
// gen/ts schemas, or a drifted canonical thumbprint JWK string).
//
// SCOPE — deliberately sdk/ts/src ONLY. A tree-wide ban on hand-rolled TS
// crypto would false-fire on the app's src/edge/src/{thumbprint,verify,pop}.ts,
// which MUST still exist until their deletion in the downstream adoption ticket
// (ixs7u.7). The tree-wide guard belongs to that ticket; here the guard is
// correctly scoped to the new canonical library.
//
// The behavioral guard for byte-parity is the parity suite
// (thumbprint/signedurl-pop/crossfield .parity.test.ts vs the Go oracle
// vectors); this file adds the source-level guard the sweep atom asks for.

const srcPath = (name: string): string =>
  fileURLToPath(new URL(`../src/${name}`, import.meta.url));

function readSource(name: string): string {
  return readFileSync(srcPath(name), "utf8");
}

// siteGuard mirrors the sdk/go guard's shape: forbidden substrings are disease
// instances that must be ABSENT; required substrings are the canonical
// composition markers that must be PRESENT.
interface SiteGuard {
  file: string;
  forbidden: string[];
  required: string[];
}

// evalSite is the pure predicate (extracted so the meta-tests can exercise the
// guard logic against synthetic source without touching the real files). It
// returns one message per violation.
export function evalSite(src: string, g: SiteGuard): string[] {
  const violations: string[] = [];
  for (const bad of g.forbidden) {
    if (src.includes(bad)) {
      violations.push(
        `${g.file} still contains disease instance ${JSON.stringify(bad)}; it must compose the generated artifact instead`,
      );
    }
  }
  for (const req of g.required) {
    if (!src.includes(req)) {
      violations.push(
        `${g.file} is missing the canonical marker ${JSON.stringify(req)}; the port's contract was broken`,
      );
    }
  }
  return violations;
}

describe("sdk/ts library-adoption guard", () => {
  it("thumbprint.ts preserves the fixed RFC 7638 canonical JWK byte contract", () => {
    // The exact member order / literal is the cross-language byte contract
    // (Go go-jose + Python emit the same string). A reorder or reformat here
    // silently breaks byte-parity with the oracle.
    const violations = evalSite(readSource("thumbprint.ts"), {
      file: "thumbprint.ts",
      forbidden: [],
      required: [`{"crv":"Ed25519","kty":"OKP","x":"`],
    });
    expect(violations).toEqual([]);
  });

  it("crossfield.ts composes the generated gen/ts schemas (does not fork them)", () => {
    // The cross-field layer must .refine() ONTO the generated <Message>Schema,
    // never hand-declare a parallel z.object() wire mirror.
    const violations = evalSite(readSource("crossfield.ts"), {
      file: "crossfield.ts",
      forbidden: [],
      required: [`../../gen/ts/wire/schemas.ts`],
    });
    expect(violations).toEqual([]);
  });

  // ---- Meta-tests: prove the guard both CATCHES a regression (positive) and
  // PASSES clean source (negative). Substring-based, so there is no regex-slip
  // case to cover. ----

  const synthetic: SiteGuard = {
    file: "synthetic.ts",
    forbidden: ["z.object({ crv: z.literal"],
    required: [`../../gen/ts/wire/schemas.ts`],
  };

  it("meta: catches a re-introduced wire-mirror + dropped generated import", () => {
    const bad = `const Jwk = z.object({ crv: z.literal("Ed25519") });\n`;
    // both a forbidden hand-rolled mirror AND the missing generated import
    expect(evalSite(bad, synthetic)).toHaveLength(2);
  });

  it("meta: passes clean composed source", () => {
    const good = `import { LicenseSchema } from "../../gen/ts/wire/schemas.ts";\n`;
    expect(evalSite(good, synthetic)).toHaveLength(0);
  });
});
