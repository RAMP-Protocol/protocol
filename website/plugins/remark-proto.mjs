// remark-proto renders proto-derived content and links proto references in ONE
// mdast pass, so the same autolink that runs on prose also runs on the rendered
// tables:
//   ::proto-enum{name=ObligationKind numbers}  -> a value/description table from the
//                                                 descriptor (descriptions = proto comments)
//   ::proto-enum{name=ObligationKind label=Kind} -> guide-style (name + description)
//   ::proto-vocab{axis=function}               -> the registered token list for an axis
// Then every `Message.field` / `Service.Method` / `ENUM_VALUE` / `Type` inline-code
// reference (in prose and in the generated cells) is resolved against the descriptor:
// resolved + documented on the reference page -> a link; a high-confidence dotted ref
// whose proto type exists but member doesn't -> the build FAILS. Source of truth is
// the descriptor (see proto-schema.mjs); the slug is github-slugger (Starlight's).
import { visit, SKIP } from 'unist-util-visit';
import GithubSlugger from 'github-slugger';
import { fromMarkdown } from 'mdast-util-from-markdown';
import { gfmTable } from 'micromark-extension-gfm-table';
import { gfmTableFromMarkdown } from 'mdast-util-gfm-table';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadSchema } from './proto-schema.mjs';

const REF_PAGE = '/reference/proto-ramp/';
const refPageFile = new URL('../src/content/docs/reference/proto-ramp.mdx', import.meta.url);
const ignoreFile = new URL('../proto-symbols-ignore.json', import.meta.url);

const RE_MSG_FIELD = /^[A-Z][A-Za-z0-9]+\.[a-z][A-Za-z0-9_]+$/;
const RE_SVC_METHOD = /^[A-Z][A-Za-z0-9]+\.[A-Z][A-Za-z0-9]+$/;
const RE_ENUM_VALUE = /^[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+$/;
const RE_TYPE = /^[A-Z][A-Za-z0-9]+$/;

let state;
function setup() {
  if (state) return state;
  const { enums, symbols, vocab } = loadSchema();
  // Reference-page heading slugs decide which symbols are linkable (no dead anchors).
  const sl = new GithubSlugger();
  const headings = new Set();
  let fence = false;
  for (const ln of readFileSync(fileURLToPath(refPageFile), 'utf8').split('\n')) {
    if (ln.trimStart().startsWith('```')) { fence = !fence; continue; }
    if (fence) continue;
    const m = /^#{1,6}\s+(.+?)\s*$/.exec(ln);
    if (m) headings.add(sl.slug(m[1]));
  }
  const ignore = new Set(JSON.parse(readFileSync(fileURLToPath(ignoreFile), 'utf8')).ignore ?? []);
  const stale = [...ignore].filter((k) => symbols[k]); // self-cleaning
  if (stale.length) {
    throw new Error(`proto-symbols-ignore.json: entries now resolve in the descriptor — remove: ${stale.sort().join(', ')}`);
  }
  // SCREAMING_SNAKE_ prefix per enum (PricingModel -> PRICING_MODEL_). A token
  // carrying one of these prefixes is unambiguously a reference to that enum's
  // value, so it must resolve (a renamed/removed value fails the build) — unlike a
  // bare short form (PER_UNIT) or a non-proto ALL_CAPS token (RFC_9421).
  const enumPrefixes = Object.keys(enums).map((n) => screamingSnake(n) + '_');
  state = { enums, symbols, vocab, headings, ignore, enumPrefixes };
  return state;
}

const screamingSnake = (pascal) => pascal.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
const slug = (s) => new GithubSlugger().slug(s);
const text = (value) => ({ type: 'text', value });
const code = (value) => ({ type: 'inlineCode', value });

// Build the table by parsing a GFM markdown string — this yields exactly the mdast
// shape a hand-written table produces (which Astro renders), and lets a backticked
// symbol in a proto comment become inline code that the autolink pass then links.
const esc = (s) => (s || '').replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').trim();
function enumTableNodes(rows, { numbers, label, full }) {
  const nameOf = (r) => (full ? r.full : r.value); // full = fully-qualified DENIAL_REASON_X
  let md;
  if (numbers) {
    md = '| Value | Name | Description |\n| --- | --- | --- |\n' +
      rows.map((r) => `| ${r.number} | \`${nameOf(r)}\` | ${esc(r.doc)} |`).join('\n');
  } else {
    // Drop only the *_UNSPECIFIED sentinel zero — an enum whose 0 is a real value
    // (PricingMetering.ONLINE, CitationFormat.LINK) keeps it.
    md = `| ${label || 'Value'} | Description |\n| --- | --- |\n` +
      rows.filter((r) => !(r.number === 0 && /_UNSPECIFIED$/.test(r.full)))
        .map((r) => `| \`${nameOf(r)}\` | ${esc(r.doc)} |`).join('\n');
  }
  return fromMarkdown(md, { extensions: [gfmTable()], mdastExtensions: [gfmTableFromMarkdown()] }).children;
}

function vocabParagraph(tokens) {
  if (!tokens.length) return { type: 'paragraph', children: [{ type: 'emphasis', children: [text('(no registered tokens)')] }] };
  const kids = [];
  tokens.forEach((t, i) => { if (i) kids.push(text(' ')); kids.push(code(t)); });
  return { type: 'paragraph', children: kids };
}

function directiveText(node) {
  let s = '';
  visit(node, 'text', (t) => { s += t.value; });
  return s.trim();
}

export default function remarkProto() {
  return (tree, file) => {
    const { enums, symbols, vocab, headings, ignore, enumPrefixes } = setup();
    const where = file?.path ?? 'doc';

    // 1. expand directives into tables / token lists
    visit(tree, (n) => n.type === 'leafDirective' || n.type === 'containerDirective' || n.type === 'textDirective', (node, index, parent) => {
      if (!parent || index == null) return;
      const attrs = node.attributes ?? {};
      if (node.name === 'proto-enum') {
        const name = attrs.name || directiveText(node);
        if (!enums[name]) throw new Error(`${where}: proto-enum references unknown enum "${name}"`);
        const nodes = enumTableNodes(enums[name], { numbers: 'numbers' in attrs, label: attrs.label, full: 'full' in attrs });
        parent.children.splice(index, 1, ...nodes);
        return [SKIP, index + nodes.length];
      }
      if (node.name === 'proto-vocab') {
        const axis = attrs.axis || directiveText(node);
        if (!vocab[axis]) throw new Error(`${where}: proto-vocab references unknown axis "${axis}"`);
        parent.children[index] = vocabParagraph(vocab[axis]);
        return [SKIP, index + 1];
      }
    });

    // 2. autolink proto references across prose AND the generated cells
    const unresolved = new Set();
    visit(tree, 'inlineCode', (node, index, parent) => {
      if (!parent || index == null || parent.type === 'link') return;
      const t = node.value;
      // A token carrying a known enum prefix is unambiguously an enum-value
      // reference — resolve-or-fail, so a renamed value fails anywhere (manual
      // tables included). Bare short forms / unknown prefixes stay best-effort.
      const prefixedEnumValue = RE_ENUM_VALUE.test(t) && enumPrefixes.some((p) => t.startsWith(p));
      const hard = RE_MSG_FIELD.test(t) || RE_SVC_METHOD.test(t) || prefixedEnumValue;
      const soft = RE_ENUM_VALUE.test(t) || RE_TYPE.test(t);
      if (!hard && !soft) return;
      const sym = symbols[t];
      if (!sym) {
        if (hard && !ignore.has(t)) {
          if (prefixedEnumValue) {
            unresolved.add(t); // a known-enum-prefixed value that resolves to nothing = renamed/removed
          } else {
            // Message.field / Service.Method: drift only when the type before the
            // dot is a known proto symbol but the member is gone.
            const owner = symbols[t.slice(0, t.indexOf('.'))];
            if (owner && (owner.kind === 'message' || owner.kind === 'service' || owner.kind === 'enum')) unresolved.add(t);
          }
        }
        return;
      }
      const s = slug(sym.type);
      if (!headings.has(s)) return; // resolved but undocumented on the reference page → not linked
      parent.children[index] = { type: 'link', url: `${REF_PAGE}#${s}`, children: [node] };
      return [SKIP, index + 1];
    });
    if (unresolved.size) {
      throw new Error(`${where}: unknown proto reference(s) — ${[...unresolved].sort().join(', ')}. ` +
        `Fix the symbol name, or if it names a removed/renamed type, add it to website/proto-symbols-ignore.json.`);
    }
  };
}
