// Direct behavioral regression for the proto-JSON STRING form of a bounded numeric field.
//
// proto-JSON accepts a number as a JSON number OR a string, so protoschema models every
// numeric field as anyOf[{integer|number}, {string, pattern}] — and puts minimum/maximum on
// the NUMERIC arm only. merge_schema.collapse_numeric_strings drops the string arm so the
// bound applies to the value the client actually validates (Zod's z.coerce.number() still
// accepts the wire string). Leave the string arm standing and Zod emits a
// z.union([z.coerce.number().gte(0).lte(1), z.string().regex(...)]) whose second arm ACCEPTS
// "1000" for a [0,1] double the Go server REJECTS.
//
// The corpus cannot cover this: corpusgen sets values through protoreflect and protojson
// always marshals a double as a JSON number, so no string-encoded double can appear in a
// case. This is the Zod half of gen/python/tests/test_numeric_wire_forms.py.
import { describe, it, expect } from "vitest";
import * as schemas from "../wire/schemas.ts";

type Case = [field: string, value: unknown, accepted: boolean];

// quantity_tolerance: optional double, gte 0 lte 1 — the first bounded double in the contract.
// window_seconds: optional int32, gt 0 lte 31536000 — pins the pre-existing integer collapse.
const CASES: Case[] = [
  ["quantity_tolerance", 0.5, true],
  ["quantity_tolerance", "0.5", true],
  ["quantity_tolerance", 0, true],
  ["quantity_tolerance", "0", true],
  ["quantity_tolerance", 1, true],
  ["quantity_tolerance", "1", true],
  ["quantity_tolerance", 1000, false],
  ["quantity_tolerance", "1000", false],
  ["quantity_tolerance", 1.5, false],
  ["quantity_tolerance", "1.5", false],
  ["quantity_tolerance", -1, false],
  ["quantity_tolerance", "-5", false],
  ["quantity_tolerance", "1e3", false],
  ["window_seconds", 1, true],
  ["window_seconds", "1", true],
  ["window_seconds", 0, false],
  ["window_seconds", "0", false],
  ["window_seconds", 31536001, false],
  ["window_seconds", "31536001", false],
];

describe("numeric bounds apply to the proto-JSON wire string form", () => {
  for (const message of ["SetReportingPolicyRequest", "SetReportingPolicyResponse"]) {
    const schema = (schemas as Record<string, { safeParse: (v: unknown) => { success: boolean } }>)[
      `${message}Schema`
    ];
    it(`${message} has a generated schema`, () => expect(schema).toBeDefined());

    for (const [field, value, accepted] of CASES) {
      it(`${message}.${field} = ${JSON.stringify(value)} -> ${accepted ? "accept" : "reject"}`, () => {
        expect(schema.safeParse({ tenant_id: "x", [field]: value }).success).toBe(accepted);
      });
    }
  }
});
