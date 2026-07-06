// Hand-written extra-field policy seam for the generated Zod schemas — the TS
// parallel of the Python wire.base.WireModel. This is the ONE place the unknown-field
// policy is set for every message schema.
//
// Default: an object schema STRIPS unknown keys (Zod's default), so an unknown
// top-level field from a newer protocol version is ACCEPTED and dropped — matching
// Pydantic `extra="ignore"` and the Go typed-struct re-marshal (both drop). To change
// the policy repo-wide, swap `.strip()` here for `.strict()` (reject unknown) or
// `.passthrough()` (retain unknown). Map/`ext`/Struct fields keep their own
// `.catchall(...)` and are unaffected — they live on nested fields, not the message root.
import { z } from "zod";

export function wire<T extends z.ZodTypeAny>(schema: T): T {
  return schema instanceof z.ZodObject ? (schema.strip() as unknown as T) : schema;
}
