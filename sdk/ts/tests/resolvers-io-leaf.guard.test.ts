import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the resolver IO-leaf invariant (bsh8k).
//
// The resolver faces (sdk/ts/resolvers/) are the SDK's ONLY IO-bearing tree: they
// fetch JWKS / WBA directories / ramp.json over an injected transport. The pure
// L1/L2 tree (sdk/ts/core + sdk/ts/src) is transport-neutral by contract — it owns
// no keys, opens no sockets, and MUST NOT depend on the IO tree. Dependency flows
// one way only: resolvers/ -> {core,src} (it reuses thumbprint + base64url), never
// the reverse. A pure-tree file that imports from resolvers/ would drag IO into the
// transport-neutral core and is exactly the regression this guard bans.
//
// This complements the existing core transport-neutrality guard (which bans
// framework imports); here we ban the IO module from leaking UP into the pure tree.
//
// Whitespace-tolerant regex on purpose; the meta-tests exercise the detector.

const dirPath = (name: string): string =>
  fileURLToPath(new URL(`../${name}`, import.meta.url));

const PURE_DIRS = ["core", "src"];
const RESOLVERS_IMPORT = /from\s+["'][^"']*\/resolvers\//;

function tsFilesUnder(dir: string): string[] {
  return readdirSync(dirPath(dir), { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts"))
    .map((e) => `${dir}/${e.name}`);
}

// importsResolvers is the pure predicate (extracted so meta-tests can exercise it).
function importsResolvers(source: string): boolean {
  return RESOLVERS_IMPORT.test(source);
}

describe("resolver IO-leaf structural guard", () => {
  it("no file in the pure IO-free tree (core/src) imports the IO resolvers module", () => {
    const offenders: string[] = [];
    for (const dir of PURE_DIRS) {
      for (const rel of tsFilesUnder(dir)) {
        if (importsResolvers(readFileSync(dirPath(rel), "utf8"))) offenders.push(rel);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the resolvers reuse the pure-tree primitives (one-directional dependency)", () => {
    const wba = readFileSync(dirPath("resolvers/wba.ts"), "utf8");
    expect(/from\s+["'][^"']*\/src\/thumbprint/.test(wba)).toBe(true);
    const jwks = readFileSync(dirPath("resolvers/jwks.ts"), "utf8");
    expect(/from\s+["'][^"']*\/src\/base64url/.test(jwks)).toBe(true);
  });

  // --- meta-tests: exercise the detector against synthetic source ------------
  it("[meta positive] catches a pure-tree file importing resolvers", () => {
    expect(importsResolvers('import { newWBAKeyResolver } from "../resolvers/index.ts";')).toBe(true);
  });

  it("[meta negative] passes a pure-tree file importing only pure primitives", () => {
    expect(importsResolvers('import { thumbprint } from "../src/thumbprint.ts";')).toBe(false);
  });

  it("[meta would-be-missed] catches a reformatted import a naive substring would slip", () => {
    const reformatted = 'import {\n  newWBAKeyResolver,\n}\n  from   "../resolvers/wba.ts";';
    expect(importsResolvers(reformatted)).toBe(true);
  });
});
