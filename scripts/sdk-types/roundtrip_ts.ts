// Canonical proto-JSON round-trip emitter (Zod side).
//
// For every VALID corpus case, parse it with the generated Zod schema and emit the
// parsed object. The output [{id, message, json}] is fed to the Go conformance test
// (TestCanonicalRoundTrip), which asserts the re-emitted JSON decodes — through Go
// protojson — to the same proto message as the original. Run via
// scripts/check-canonical.sh (which places this next to a copy of schemas.ts so the
// `zod` import resolves).
//
// argv: <schemas.ts path> <corpus cases.json path>
import * as schemas from "./schemas.ts";
import { readFileSync } from "node:fs";

const corpusPath = process.argv[3];
const cases = JSON.parse(readFileSync(corpusPath, "utf8")) as Array<{
  id: string;
  message: string;
  valid: boolean;
  json: unknown;
}>;

const out: Array<{ id: string; message: string; json: unknown }> = [];
for (const c of cases) {
  if (!c.valid) continue;
  const schema = (schemas as Record<string, { safeParse: (v: unknown) => { success: boolean; data?: unknown } }>)[
    `${c.message}Schema`
  ];
  if (!schema) throw new Error(`no generated schema ${c.message}Schema`);
  const r = schema.safeParse(c.json);
  if (!r.success) throw new Error(`valid corpus case rejected by Zod: ${c.id}`);
  out.push({ id: c.id, message: c.message, json: r.data });
}
process.stdout.write(JSON.stringify(out));
