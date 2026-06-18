// rehype-proto-autolink turns bare inline-code references to proto symbols into
// validated links to the proto reference page — and FAILS THE BUILD on a
// high-confidence reference that resolves to no symbol. It is the deterministic
// half of the docs-drift guard: an out-of-date `Message.field` in prose can no
// longer ship.
//
// Source of truth is src/data/symbols.json, generated each build by
// cmd/symbolsjson from the proto descriptor (never hand-edited). Resolution is
// authoritative (descriptor membership); linking is best-effort (it targets a
// reference-page anchor, which starlight-links-validator verifies separately).
//
// Shape gate (the precision/recall calibration):
//   `Message.field`   resolve-or-FAIL   — exact, this is where prose drift lives
//   `Service.Method`  resolve-or-FAIL
//   `ENUM_VALUE`      link-if-resolves  — short forms/acronyms are ambiguous, never fail
//   `TypeName`        link-if-resolves
// Only inline code is processed; fenced code blocks (example payloads) are skipped.
//
// The resolve-or-FAIL shapes fire only when the TYPE before the dot is itself a
// known proto message/service — i.e. "you named a real proto type's member, but it
// doesn't exist" (true drift). A `Type.member` whose type is not in the descriptor
// (an SDK Go struct, a content-schema type, a format placeholder) is not a proto
// reference and is left untouched — so this needs no hand-maintained denylist.
import { visit, SKIP } from 'unist-util-visit';
import GithubSlugger from 'github-slugger';
import { readFileSync } from 'node:fs';

const slugger = new GithubSlugger();
function anchor(page, heading) {
  slugger.reset();
  return `${page}#${slugger.slug(heading)}`;
}

const symbolsURL = new URL('../src/data/symbols.json', import.meta.url);
const ignoreURL = new URL('../proto-symbols-ignore.json', import.meta.url);

let symbols;
let ignore;
function load() {
  if (symbols) return;
  try {
    symbols = JSON.parse(readFileSync(symbolsURL, 'utf8'));
  } catch (e) {
    throw new Error(
      `rehype-proto-autolink: cannot read ${symbolsURL.pathname}. Run \`npm run gen:symbols\` ` +
        `(requires the Go toolchain) before building. Original error: ${e.message}`,
    );
  }
  const raw = JSON.parse(readFileSync(ignoreURL, 'utf8'));
  ignore = new Set(raw.ignore ?? []);
  // Self-cleaning: an ignore entry that now resolves against the descriptor is
  // stale and must be removed, exactly like a stale conformance allowlist entry.
  const stale = [...ignore].filter((k) => symbols[k]);
  if (stale.length) {
    throw new Error(
      `rehype-proto-autolink: proto-symbols-ignore.json lists symbols that now resolve in the ` +
        `descriptor — remove these stale entries: ${stale.sort().join(', ')}`,
    );
  }
}

const RE_MSG_FIELD = /^[A-Z][A-Za-z0-9]+\.[a-z][A-Za-z0-9_]+$/;
const RE_SVC_METHOD = /^[A-Z][A-Za-z0-9]+\.[A-Z][A-Za-z0-9]+$/;
const RE_ENUM_VALUE = /^[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+$/;
const RE_TYPE = /^[A-Z][A-Za-z0-9]+$/;

export default function rehypeProtoAutolink() {
  return (tree, file) => {
    load();
    const unresolved = new Set();

    visit(tree, 'element', (node, index, parent) => {
      if (node.tagName !== 'code' || !parent || index == null) return;
      if (parent.type === 'element' && parent.tagName === 'pre') return; // fenced block
      if (parent.type === 'element' && parent.tagName === 'a') return; // already linked
      if (node.children.length !== 1 || node.children[0].type !== 'text') return;

      const text = node.children[0].value;
      const hard = RE_MSG_FIELD.test(text) || RE_SVC_METHOD.test(text);
      const soft = RE_ENUM_VALUE.test(text) || RE_TYPE.test(text);
      if (!hard && !soft) return;

      const sym = symbols[text];
      if (!sym) {
        // A dotted reference is drift only when its TYPE is a known proto
        // message/service but the member is gone. If the type itself isn't in the
        // descriptor, this isn't a proto reference at all — leave it alone (no
        // hand-maintained denylist). Lower-confidence shapes never fail.
        if (hard && !ignore.has(text)) {
          const owner = symbols[text.slice(0, text.indexOf('.'))];
          if (owner && (owner.kind === 'message' || owner.kind === 'service' || owner.kind === 'enum')) {
            unresolved.add(text);
          }
        }
        return;
      }
      if (!sym.heading) return; // resolved but ambiguous — valid, just not linked

      parent.children[index] = {
        type: 'element',
        tagName: 'a',
        properties: { href: anchor(sym.page, sym.heading), className: ['proto-ref'] },
        children: [node],
      };
      return [SKIP, index + 1];
    });

    if (unresolved.size) {
      throw new Error(
        `${file.path ?? 'doc'}: unknown proto reference(s) — ${[...unresolved].sort().join(', ')}. ` +
          `Fix the symbol name, or if it intentionally names a removed/renamed type, ` +
          `add it to website/proto-symbols-ignore.json.`,
      );
    }
  };
}
