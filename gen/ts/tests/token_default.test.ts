import { describe, it, expect } from "vitest";
import * as schemas from "../wire/schemas.ts";

// Delegation.token is a proto `bytes` field, rendered as a base64 string. Its proto3
// zero is "" (which the base64 pattern accepts), so a Delegation with token omitted
// MUST parse. Regression guard for the generated `.default(null)` bug (kb1s0.20):
// Zod re-validates the default value, and null is not a string, so an omitted token
// wrongly failed safeParse.
describe("Delegation.token (bytes) tolerates omission", () => {
  it("parses a Delegation with token omitted", () => {
    const res = schemas.DelegationSchema.safeParse({ principal_id: "user@acme.com" });
    expect(res.success).toBe(true);
  });
});
