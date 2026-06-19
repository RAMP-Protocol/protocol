// Generate one Zod module with a named export per message, from the merged JSON
// Schema ($defs keyed by message name). Constraints (regex/min/max/enum/strict) ride
// through — unlike a protobuf-es→ts-to-zod path, which strips them.
//
// json-schema-to-zod does not resolve internal $ref (it emits z.any()), so we INLINE
// each message's $defs references first (the message graph is acyclic; a cycle, if one
// is ever introduced, degrades that one edge to a loose object rather than looping).
//
//   node scripts/sdk-types/gen_zod.mjs <combined.json> <out.ts>   (run from the dir
//   whose node_modules has json-schema-to-zod — ESM ignores NODE_PATH)
import fs from "node:fs";
import { jsonSchemaToZod } from "json-schema-to-zod";

const [, , inFile, outFile] = process.argv;
const defs = JSON.parse(fs.readFileSync(inFile, "utf8"))["$defs"];

function inline(node, stack) {
  if (Array.isArray(node)) return node.map((n) => inline(n, stack));
  if (node && typeof node === "object") {
    if (typeof node.$ref === "string") {
      const m = node.$ref.match(/^#\/\$defs\/(.+)$/);
      if (m) {
        const name = m[1];
        const { $ref, ...siblings } = node;
        if (stack.includes(name)) return siblings; // cycle guard
        return { ...inline(defs[name], [...stack, name]), ...siblings };
      }
    }
    return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, inline(v, stack)]));
  }
  return node;
}

let out =
  "// Code generated from the RAMP proto (via JSON Schema). DO NOT EDIT.\n" +
  "// Regenerate: scripts/gen-sdk-types.sh\n" +
  'import { z } from "zod";\n\n';

for (const name of Object.keys(defs).sort()) {
  const root = inline(defs[name], [name]);
  root["$schema"] = "https://json-schema.org/draft/2020-12/schema";
  out += `export const ${name}Schema = ${String(jsonSchemaToZod(root, { module: "none" }))};\n\n`;
}

fs.writeFileSync(outFile, out);
console.log(`wrote ${Object.keys(defs).length} Zod schemas -> ${outFile}`);
