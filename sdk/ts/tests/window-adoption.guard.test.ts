import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the injectable-Window adoption (djeue).
//
// DISEASE: a sign site that mints a signature's (created, expires) pair by inline
// now+ttl arithmetic (e.g. `const expires = nowSec + opts.ttlSec`) instead of
// sourcing it from the injectable Window (clockWindow / monotonicWindow). Inline
// mint cannot be swapped for a monotonic window (unique back-to-back expires) and
// re-derives the floor/ttl contract per-site, drifting from the Go .Unix()
// semantics. signInbound was migrated to the Window; this guard pins it stays.
//
// SCOPE — the sign-side mint site (core/sign.ts::signInbound). The verify side
// PARSES created/expires from the wire (not a mint) and is intentionally NOT
// guarded. Whitespace-tolerant regex; the "would-be-missed" meta-test feeds a
// reformatted inline mint.

const dirPath = (rel: string): string =>
  fileURLToPath(new URL(`../${rel}`, import.meta.url));

interface SiteGuard {
  file: string;
  forbidden: RegExp[];
  required: RegExp[];
}

function evalSite(source: string, guard: SiteGuard): string[] {
  const out: string[] = [];
  for (const re of guard.forbidden) {
    if (re.test(source)) out.push(`${guard.file}: forbidden inline now+ttl mint ${re}`);
  }
  for (const re of guard.required) {
    if (!re.test(source)) out.push(`${guard.file}: missing Window adoption ${re}`);
  }
  return out;
}

const SIGN_GUARD: SiteGuard = {
  file: "core/sign.ts",
  // The pre-migration inline form: nowSec + (opts.ttlSec ?? DEFAULT...).
  forbidden: [/nowSec\s*\+\s*\(?\s*opts\.ttlSec/],
  // The Window must be imported and invoked for (created, expires).
  required: [/from\s+["']\.\/window/, /window\(\)/],
};

describe("injectable-Window adoption structural guard", () => {
  it("signInbound sources (created, expires) from the Window, not an inline now+ttl mint", () => {
    expect(evalSite(readFileSync(dirPath("core/sign.ts"), "utf8"), SIGN_GUARD)).toEqual([]);
  });

  it("window.ts exports both clockWindow and monotonicWindow", () => {
    const src = readFileSync(dirPath("core/window.ts"), "utf8");
    expect(/export\s+function\s+clockWindow/.test(src)).toBe(true);
    expect(/export\s+function\s+monotonicWindow/.test(src)).toBe(true);
  });

  // --- meta-tests -----------------------------------------------------------
  it("[meta positive] catches an inline now+ttl mint", () => {
    const bad = "const expires = nowSec + (opts.ttlSec ?? DEFAULT_POP_TTL_SEC);\nconst window = null;";
    expect(evalSite(bad, SIGN_GUARD).length).toBeGreaterThan(0);
  });

  it("[meta negative] passes the Window-sourced form", () => {
    const good = [
      'import { clockWindow } from "./window.ts";',
      "const [created, expires] = window();",
    ].join("\n");
    expect(evalSite(good, SIGN_GUARD)).toEqual([]);
  });

  it("[meta would-be-missed] catches a reformatted inline mint a naive substring would slip", () => {
    const reformatted = [
      'import { clockWindow } from "./window.ts";',
      "const window2 = () => 0;",
      "const expires = nowSec  +  ( opts.ttlSec ?? D );", // extra spaces
      "window();",
    ].join("\n");
    const violations = evalSite(reformatted, SIGN_GUARD);
    expect(violations.length).toBe(1);
    expect(violations[0]).toContain("forbidden inline now+ttl mint");
  });
});
