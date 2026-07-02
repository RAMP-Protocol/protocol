// Direct behavioral regression for wire forward-compatibility (H2 / kb1s0.2),
// TypeScript / Zod side. Mirrors gen/python/tests/test_forward_compat.py.
//
// Core invariant: an UNKNOWN top-level field (one a newer protocol version adds
// that this older client has never seen) MUST be ACCEPTED and STRIPPED — never
// rejected, never retained. This matches Pydantic extra="ignore" (drop) and the
// Go typed-struct re-marshal (drop), so the three languages converge.
//
// It FAILS today: the generated schemas encode additionalProperties:false as a
// .catchall(z.union([..., z.never()])) + superRefine that flags unknown keys, so
// safeParse of an unknown top-level field returns success=false instead of
// stripping it.
import { describe, it, expect } from "vitest";
import * as schemas from "../wire/schemas.ts";

// A key no protocol version defines — stands in for "a field a newer version added".
const UNKNOWN_KEY = "__unknown_future_field__";

type SafeParse = (v: unknown) => { success: boolean; data?: Record<string, unknown> };
const schemaByName = (name: string): SafeParse => {
  const s = (schemas as Record<string, { safeParse: SafeParse } | undefined>)[name];
  expect(s, `no generated schema ${name}`).toBeDefined();
  return (s as { safeParse: SafeParse }).safeParse;
};

// (case_id, SchemaName, minimally-valid proto-JSON body)
const DROP_CASES: Array<[string, string, Record<string, unknown>]> = [
  ["Cost", "CostSchema", { amount: "19.99" }],
  // token is provided explicitly: the generated `token` field defaults to null and
  // re-validates it against z.string(), so omitting it fails for a reason unrelated to
  // forward-compat (tracked separately). "" satisfies the token base64 pattern.
  ["Delegation", "DelegationSchema", { principalId: "user@acme.com", token: "" }],
  ["Pricing", "PricingSchema", { model: "PRICING_MODEL_FREE" }],
];

describe("unknown top-level field is accepted and stripped", () => {
  for (const [name, schemaName, base] of DROP_CASES) {
    it(`${name} accepts and drops ${UNKNOWN_KEY}`, () => {
      const safeParse = schemaByName(schemaName);
      const res = safeParse({ ...base, [UNKNOWN_KEY]: "a value from the future" });

      // MUST parse: an unknown top-level field is accepted (forward-compat).
      expect(res.success).toBe(true);
      // MUST be stripped, not retained.
      expect(res.data).toBeDefined();
      expect(Object.keys(res.data as Record<string, unknown>)).not.toContain(UNKNOWN_KEY);
    });
  }
});

describe("closed enum still rejects a bogus value (fix must not over-open)", () => {
  it("PricingSchema.model rejects a bogus enum value", () => {
    const safeParse = schemaByName("PricingSchema");
    const res = safeParse({ model: "PRICING_MODEL_BOGUS" });
    expect(res.success).toBe(false);
  });
});
