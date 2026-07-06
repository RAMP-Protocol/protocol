// Cross-language validation parity (TypeScript / Zod side).
//
// Every case in conformance/corpus/cases.json is a proto-JSON instance with the
// verdict Go protovalidate assigned it. This asserts the generated Zod schemas
// reach the SAME verdict — i.e. the proto -> JSON Schema -> Zod pipeline carries
// every field-level rule faithfully. The corpus is generated (no rule is restated
// here); the Go suite pins it to protovalidate and the Python suite asserts the
// identical corpus against Pydantic.
import { describe, it, expect } from "vitest";
import * as schemas from "../wire/schemas.ts";
import cases from "../../../conformance/corpus/cases.json";

type Case = { id: string; message: string; valid: boolean; rules?: string[]; json: unknown };

describe("Zod schemas match the Go protovalidate verdict", () => {
  const all = cases as Case[];
  it("corpus is non-empty", () => expect(all.length).toBeGreaterThan(0));

  for (const c of all) {
    it(c.id, () => {
      const schema = (schemas as Record<string, { safeParse: (v: unknown) => { success: boolean } }>)[
        `${c.message}Schema`
      ];
      expect(schema, `no generated schema ${c.message}Schema`).toBeDefined();
      expect(schema.safeParse(c.json).success).toBe(c.valid);
    });
  }
});
