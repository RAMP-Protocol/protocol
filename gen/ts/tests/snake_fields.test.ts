import { describe, it, expect } from "vitest";
import { z } from "zod";
import * as schemas from "../wire/schemas.ts";

// Every generated Zod object key must be snake_case — the wire is snake_case proto-JSON,
// no exceptions. Direct guard on the TS client layer (parallel to the Python
// test_snake_fields): a pipeline regression to the camelCase json-name schema variant
// fails loudly here instead of as a cryptic parity mismatch. Unwrap the wire() seam and
// recurse into nested object fields; non-object schemas (enums, strings) have no keys.
const SNAKE = /^[a-z][a-z0-9_]*$/;

function keysOf(schema: z.ZodTypeAny, seen: Set<unknown>, out: string[]): void {
  if (seen.has(schema)) return;
  seen.add(schema);
  const def = (schema as { _def?: { innerType?: z.ZodTypeAny; schema?: z.ZodTypeAny } })._def;
  const inner = def?.innerType ?? def?.schema; // unwrap default/optional/effects/etc.
  if (inner) return keysOf(inner, seen, out);
  if (schema instanceof z.ZodObject) {
    for (const [k, v] of Object.entries(schema.shape)) {
      out.push(k);
      keysOf(v as z.ZodTypeAny, seen, out);
    }
  } else if (schema instanceof z.ZodArray) {
    keysOf(schema.element, seen, out);
  }
}

describe("generated Zod field keys are snake_case", () => {
  it("every object key across all schemas is snake_case", () => {
    const offenders: string[] = [];
    for (const [name, schema] of Object.entries(schemas)) {
      if (!(schema instanceof z.ZodType)) continue;
      const keys: string[] = [];
      keysOf(schema as z.ZodTypeAny, new Set(), keys);
      for (const k of keys) if (!SNAKE.test(k)) offenders.push(`${name}.${k}`);
    }
    expect(offenders, `non-snake_case Zod field keys: ${offenders.join(", ")}`).toEqual([]);
  });
});
