// Deterministic backfill: for every reference-page field whose DESCRIPTION lives
// only in the hand-typed doc table (the proto field has no comment), port that
// description back into proto/ramp/v1/ramp.proto as a leading `//` comment — so
// the proto becomes the single source and the reference page can be generated
// from it with nothing lost.
//
// Usage:
//   node scripts/backfill-proto-comments.mjs           # dry run: print the plan
//   node scripts/backfill-proto-comments.mjs --apply   # edit ramp.proto in place
//
// Idempotent: it only fills fields the descriptor reports as comment-less, so a
// second run (after regenerating the descriptor) is a no-op.
import { readFileSync, writeFileSync } from 'node:fs';
import { loadSchema } from '../website/plugins/proto-schema.mjs';

const PROTO = new URL('../proto/ramp/v1/ramp.proto', import.meta.url);
const REF = new URL('../website/src/content/docs/reference/proto-ramp.mdx', import.meta.url);
const apply = process.argv.includes('--apply');

// 1. Which (message, field) pairs have NO proto comment, per the descriptor.
const { messages } = loadSchema();
const blank = new Set();
for (const [m, rows] of Object.entries(messages)) {
  for (const r of rows) if (!r.doc.trim()) blank.add(`${m}.${r.field}`);
}

// 2. Hand-typed descriptions from the reference page: `### Name` sections, then
//    rows `| `field` | type | number | description |`.
const mdx = readFileSync(REF, 'utf8');
const rowRe = /^\|\s*`([^`]+)`\s*\|\s*[^|]*?\s*\|\s*(\d+)\s*\|\s*(.*?)\s*\|\s*$/;
const docOf = {}; // "Message.field" -> description
let section = null;
for (const line of mdx.split('\n')) {
  const h = /^###\s+(\S+)/.exec(line);
  if (h) { section = h[1]; continue; }
  const m = rowRe.exec(line);
  if (section && m) {
    const desc = m[3].replace(/\\\|/g, '|').trim();
    if (desc) docOf[`${section}.${m[1]}`] = desc;
  }
}

// 3. Plan: a field that is comment-less AND has a doc description to port.
const plan = [];
for (const key of blank) if (docOf[key]) plan.push({ key, field: key.split('.').slice(1).join('.'), desc: docOf[key] });
plan.sort((a, b) => a.key.localeCompare(b.key));

console.log(`comment-less reference fields: ${blank.size}; portable from doc: ${plan.length}`);
const noDoc = [...blank].filter((k) => !docOf[k] && messages[k.split('.')[0]]); // genuinely blank both sides
if (noDoc.length) console.log(`(blank in BOTH proto and doc, left as-is: ${noDoc.length} — ${noDoc.slice(0,8).join(', ')}${noDoc.length>8?', …':''})`);

// 4. Insert into the proto. Scope each insert to its top-level message block and
//    match the field's declaration line; insert a `//` comment above it with the
//    same indentation. Only top-level messages are on the reference page.
let src = readFileSync(PROTO, 'utf8').split('\n');
const wrap = (text, indent) => {
  const words = text.split(/\s+/);
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (cur && (cur.length + 1 + w.length) > 96) { lines.push(cur); cur = ''; }
    cur = cur ? `${cur} ${w}` : w;
  }
  if (cur) lines.push(cur);
  return lines.map((l) => `${indent}// ${l}`);
};

const byMessage = {};
for (const p of plan) (byMessage[p.key.split('.')[0]] = byMessage[p.key.split('.')[0]] || []).push(p);

let inserted = 0;
const out = [];
let cur = null;        // current top-level message name
let depth = 0;
for (let i = 0; i < src.length; i++) {
  const line = src[i];
  const mh = /^message\s+(\w+)\s*\{/.exec(line);
  if (mh && depth === 0) cur = mh[1];
  // Field-declaration line: optional/repeated/map<>/Type  name = N [..];
  if (cur && byMessage[cur]) {
    // Field declaration head: `TYPE name = N` (the `;`/[...] option may continue on
    // following lines, so don't require a same-line terminator).
    const fm = /^(\s+)(?:repeated\s+|optional\s+)?(?:map<[^>]+>|[A-Za-z0-9_.]+)\s+(\w+)\s*=\s*\d+\b/.exec(line);
    if (fm) {
      const hit = byMessage[cur].find((p) => p.field === fm[2]);
      if (hit) {
        for (const c of wrap(hit.desc, fm[1])) out.push(c);
        inserted++;
        hit.matched = true;
      }
    }
  }
  out.push(line);
  for (const ch of line) { if (ch === '{') depth++; else if (ch === '}') { depth--; if (depth === 0) cur = null; } }
}

console.log(`\nplanned inserts: ${plan.length}, matched in proto: ${inserted}`);
const unmatched = plan.filter((p) => !p.matched);
if (unmatched.length) {
  console.log(`WARNING: ${unmatched.length} planned fields NOT located in the proto:`);
  for (const p of unmatched) console.log(`  ${p.key}  // ${p.desc.slice(0, 50)}`);
}
if (!apply) {
  console.log('\n--- sample of what will be inserted (first 20) ---');
  for (const p of plan.slice(0, 20)) console.log(`  ${p.key.padEnd(40)} // ${p.desc.slice(0, 70)}`);
  console.log('\n(dry run — re-run with --apply to write ramp.proto)');
} else {
  writeFileSync(PROTO, out.join('\n'));
  console.log('\nramp.proto updated.');
}
