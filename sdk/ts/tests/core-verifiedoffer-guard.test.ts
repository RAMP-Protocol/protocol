// sdk/ts/core VerifiedOffer forge/compile guard — TDD red for ixs7u.10.
//
// Mirror of the Go compile guard (sdk/go/core: VerifiedOffer has an UNEXPORTED
// field and no exported constructor, so Client.Execute(ctx, VerifiedOffer) is a
// real COMPILE guard). In TS the equivalent is a BRANDED/opaque type: VerifiedOffer
// carries a private module-level `Symbol` tag that only the core's verify path (or
// RejectedOffer.unsafe()) can stamp, so an application cannot forge one with an
// object literal and slip it into execute(offer: VerifiedOffer).
//
// The intended RED here is "sdk/ts/core does not exist yet" — NOT a TS compile
// error for the wrong reason. We therefore encode the guarantee as a RUNTIME test:
//   - a rejected offer is NOT directly executable; obtaining an executable
//     VerifiedOffer from it requires the explicit .unsafe() escape;
//   - the branding is unforgeable — a hand-built object shaped like a VerifiedOffer
//     is NOT accepted by the core as one (there is a runtime brand check).
// The compile-time half (an object literal will not typecheck as VerifiedOffer) is
// documented as a type-guard note below; it is enforced by `tsc --strict` in CI
// against the branded type once sdk/ts/core lands, and deliberately NOT written as
// a test that fails to COMPILE (that would be red for the wrong reason).
import { describe, it, expect } from "vitest";
// @ts-expect-error — sdk/ts/core does not exist yet (TDD red).
import { NewVerifier, isVerifiedOffer } from "../core/verifier.ts";

// TYPE-GUARD NOTE (documented, enforced by tsc --strict once core lands):
// `execute(offer: VerifiedOffer)` accepts ONLY the branded type. The following,
// were it uncommented, MUST be a compile error — an app cannot fabricate a
// VerifiedOffer, because the brand Symbol is module-private to sdk/ts/core:
//   const forged = { offer: {} } as VerifiedOffer;  // ← tsc error: missing brand
// We do NOT write that as a live compile-failure test (wrong-reason red); this note
// pins the intent and the CI `tsc --strict` job is the enforcer.

describe("sdk/ts/core VerifiedOffer is unforgeable and rejected offers need .unsafe()", () => {
  it("a hand-built VerifiedOffer-shaped object is NOT recognized as branded", () => {
    // The brand is a module-private Symbol; a plain object cannot carry it.
    const forged = { offer: { offerId: "forged" } };
    expect(isVerifiedOffer(forged)).toBe(false);
  });

  it("a rejected offer requires explicit .unsafe() to yield an executable VerifiedOffer", async () => {
    // A doctored offer (no resolvable key) lands in rejected under Strict. It is
    // visible but NOT directly executable; only .unsafe() mints a VerifiedOffer.
    const verifier = NewVerifier("strict", {
      resolve: async () => undefined, // no key → fail-closed reject
      now: () => Date.now(),
    });
    const result = await verifier.sort([{ offerId: "doctored", exchange: "x" }]);
    expect(result.rejected).toHaveLength(1);

    const rejected = result.rejected[0];
    // The mint that only the escape hatch performs:
    const forced = rejected.unsafe();
    expect(isVerifiedOffer(forced)).toBe(true);
    // And the rejected wrapper itself is NOT a VerifiedOffer.
    expect(isVerifiedOffer(rejected)).toBe(false);
  });
});
