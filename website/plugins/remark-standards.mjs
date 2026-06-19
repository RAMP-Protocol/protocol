// remark-standards links external standards references to their canonical sources at
// build time, from the single references registry (src/data/standards.mjs — which also
// renders the References page). It links the FIRST unlinked mention of each standard
// per page (no link-spam), skipping headings, code spans (inlineCode is not a text
// node), and text already inside a link at ANY depth. A standard already linked
// manually on the page is left alone (no redundant second link).
//
// Source of truth is the registry, so a standard cannot resolve to two different URLs
// here or on the References page — to change a URL, edit the one entry.
import { visitParents, SKIP } from 'unist-util-visit-parents';
import { STANDARDS } from '../src/data/standards.mjs';

// Word boundary that also rejects a LEADING hyphen, so a term inside a compound
// prefix isn't split (e.g. "C2PA" in "RAMP-C2PA" must not link), while still allowing
// a trailing hyphen so a compound head links (e.g. "biscuit" in "biscuit-v3"). The
// trailing alnum rejection keeps "JWK" out of "JWKS" and "JWT" out of "JWTs".
const boundary = (w) =>
  new RegExp(`(?<![A-Za-z0-9-])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9])`);
const ENTRIES = STANDARDS.map((e) => ({ id: e.id, url: e.url, aliases: e.aliases.map(boundary) }));

const textNode = (value) => ({ type: 'text', value });
const linkNode = (url, value) => ({ type: 'link', url, children: [textNode(value)] });

// earliest unlinked standard match in text (leftmost position wins — this is what
// resolves "Trace Context" vs "W3C Trace Context"; the word boundary keeps "JWK" out
// of "JWKS"). Returns { start, end, id, url, label } or null.
function earliest(text, linked) {
  let best = null;
  for (const e of ENTRIES) {
    if (linked.has(e.id)) continue;
    for (const re of e.aliases) {
      const m = re.exec(text);
      if (m && (!best || m.index < best.start)) {
        best = { start: m.index, end: m.index + m[0].length, id: e.id, url: e.url, label: m[0] };
      }
    }
  }
  return best;
}

function linkify(text, linked) {
  const best = earliest(text, linked);
  if (!best) return null;
  linked.add(best.id);
  const out = [];
  if (best.start > 0) out.push(textNode(text.slice(0, best.start)));
  out.push(linkNode(best.url, best.label));
  const after = text.slice(best.end);
  const rest = linkify(after, linked);
  if (rest) out.push(...rest);
  else if (after) out.push(textNode(after));
  return out;
}


export default function remarkStandards() {
  return (tree) => {
    const linked = new Set();

    // Seed: if a standard is already linked to its canonical source on the page,
    // don't add a redundant second link. Keyed on the URL (not the link text) so a
    // deep-link to a specific resource (a spec version, a trust list) or an in-page
    // anchor does NOT suppress the general reference — only an existing canonical
    // link does.
    visitParents(tree, 'link', (node) => {
      for (const e of ENTRIES) if (node.url === e.url) linked.add(e.id);
    });

    // Link the first unlinked mention of each standard in prose.
    visitParents(tree, 'text', (node, ancestors) => {
      if (ancestors.some((a) => a.type === 'link' || a.type === 'heading')) return;
      const parent = ancestors[ancestors.length - 1];
      const idx = parent?.children?.indexOf(node);
      if (idx == null || idx < 0) return;
      const replacement = linkify(node.value, linked);
      if (replacement) {
        parent.children.splice(idx, 1, ...replacement);
        return [SKIP, idx + replacement.length];
      }
    });
  };
}
