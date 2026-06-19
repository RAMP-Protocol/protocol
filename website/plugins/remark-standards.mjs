// remark-standards links external standards references to their canonical sources
// at build time — so a bare "RFC 9421" or "C2PA" in prose becomes an accurate link,
// with no hand-maintained links in the source and no drift. It links the FIRST
// unlinked mention of each standard per page (no link-spam), skipping headings,
// code spans (inlineCode is not a text node), and text already inside a link.
//
// RFCs are pattern-derived (rfc-editor.org is the authoritative published source).
// Named standards come from the registry below — keep it accurate and canonical.
import { visit, SKIP } from 'unist-util-visit';

const RFC_BASE = 'https://www.rfc-editor.org/rfc/rfc';

// Named standards (and standard acronyms that are themselves defined by an RFC).
// Listed longest-first so "W3C Trace Context" wins over "Trace Context".
const NAMED = [
  ['W3C Trace Context', 'https://www.w3.org/TR/trace-context/'],
  ['Trace Context', 'https://www.w3.org/TR/trace-context/'],
  ['ISO 3166', 'https://www.iso.org/iso-3166-country-codes.html'],
  ['EdDSA', `${RFC_BASE}8032`],
  ['ed25519', `${RFC_BASE}8032`],
  ['C2PA', 'https://c2pa.org/specifications/'],
  ['SPDX', 'https://spdx.org/licenses/'],
  ['JWT', `${RFC_BASE}7519`],
  ['JWK', `${RFC_BASE}7517`],
  ['JCS', `${RFC_BASE}8785`],
  ['COSE', `${RFC_BASE}9052`],
  ['RSL', 'https://rslstandard.org/'],
  ['biscuit', 'https://www.biscuitsec.org/'],
];

const RFC_RE = /\bRFC[\s ]?(\d{3,5})\b/;
const wordRe = (w) => new RegExp(`(?<![A-Za-z0-9])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9])`);
const NAMED_RE = NAMED.map(([name, url]) => [name, url, wordRe(name)]);

const textNode = (value) => ({ type: 'text', value });
const linkNode = (url, value) => ({ type: 'link', url, children: [textNode(value)] });

// linkify returns the replacement node list for a text value (first-occurrence of
// each not-yet-linked standard turned into a link), or null if nothing matched.
function linkify(text, linked) {
  let best = null; // { start, end, key, url, label }
  const consider = (start, end, key, url) => {
    if (start < 0 || linked.has(key)) return;
    if (!best || start < best.start) best = { start, end, key, url, label: text.slice(start, end) };
  };

  const rfc = RFC_RE.exec(text);
  if (rfc) consider(rfc.index, rfc.index + rfc[0].length, `RFC${rfc[1]}`, `${RFC_BASE}${rfc[1]}`);
  for (const [name, url, re] of NAMED_RE) {
    const m = re.exec(text);
    if (m) consider(m.index, m.index + name.length, name, url);
  }
  if (!best) return null;

  linked.add(best.key);
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
    const linked = new Set(); // one link per standard per page
    visit(tree, 'text', (node, index, parent) => {
      if (!parent || index == null) return;
      if (parent.type === 'heading' || parent.type === 'link') return;
      const replacement = linkify(node.value, linked);
      if (replacement) {
        parent.children.splice(index, 1, ...replacement);
        return [SKIP, index + replacement.length];
      }
    });
  };
}
