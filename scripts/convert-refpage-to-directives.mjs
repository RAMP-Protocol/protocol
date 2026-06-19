// Replace the hand-typed field/RPC tables on the reference page with the
// generated `::proto-message{name=X}` / `::proto-service{name=X}` directives —
// the data now lives in the descriptor (proto comments), so the tables are pure
// duplication. Section headings and intro prose are preserved; only the markdown
// table block under a known message/service heading is swapped for its directive.
//
// Usage: node scripts/convert-refpage-to-directives.mjs [--apply]
import { readFileSync, writeFileSync } from 'node:fs';
import { loadSchema } from '../website/plugins/proto-schema.mjs';

const REF = new URL('../website/src/content/docs/reference/proto-ramp.mdx', import.meta.url);
const apply = process.argv.includes('--apply');
const { messages, services } = loadSchema();

const MSG_HEADER = '| Field | Type | Number | Description |';
const SVC_HEADER = '| RPC | Request | Response | Description |';

const lines = readFileSync(REF, 'utf8').split('\n');
const out = [];
let section = null;
let replaced = 0;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const h = /^###\s+(\S+)/.exec(line);
  if (h) { section = h[1]; out.push(line); continue; }

  const isMsgTable = line.trim() === MSG_HEADER && section && messages[section];
  const isSvcTable = line.trim() === SVC_HEADER && section && services[section];
  if (isMsgTable || isSvcTable) {
    // consume the table: header + separator + consecutive `|...` rows
    let j = i + 1;
    if (j < lines.length && /^\s*\|[-\s|]+\|\s*$/.test(lines[j])) {
      j++;
      while (j < lines.length && lines[j].trimStart().startsWith('|')) j++;
      const directive = isMsgTable ? `::proto-message{name=${section}}` : `::proto-service{name=${section}}`;
      out.push(directive);
      replaced++;
      i = j - 1; // skip the consumed table; loop ++ moves past it
      continue;
    }
  }
  out.push(line);
}

console.log(`tables replaced: ${replaced} (messages+services)`);
if (apply) { writeFileSync(REF, out.join('\n')); console.log('proto-ramp.mdx updated.'); }
else console.log('(dry run — re-run with --apply)');
