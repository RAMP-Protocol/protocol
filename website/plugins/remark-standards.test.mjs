import { test } from 'node:test';
import assert from 'node:assert/strict';
import { visit } from 'unist-util-visit';
import remarkStandards from './remark-standards.mjs';

const run = (tree) => { remarkStandards()(tree); return tree; };
const para = (...children) => ({ type: 'root', children: [{ type: 'paragraph', children }] });
const t = (value) => ({ type: 'text', value });
const links = (tree) => { const u = []; visit(tree, 'link', (n) => u.push(n.url)); return u; };

test('an RFC reference in prose links to the canonical rfc-editor URL', () => {
  assert.ok(links(run(para(t('Signed per RFC 9421 rules.')))).includes('https://www.rfc-editor.org/rfc/rfc9421'));
});

test('only the first mention of a standard is linked per page', () => {
  const got = links(run(para(t('RFC 9421 here, and RFC 9421 again.')))).filter((u) => u.endsWith('rfc9421'));
  assert.equal(got.length, 1);
});

test('a named standard links from the registry', () => {
  assert.ok(links(run(para(t('We follow C2PA for provenance.')))).includes('https://c2pa.org/specifications/'));
});

test('a standard acronym backed by an RFC links to that RFC', () => {
  assert.ok(links(run(para(t('Tokens are EdDSA-signed.')))).includes('https://www.rfc-editor.org/rfc/rfc8032'));
});

test('text already inside a link is not re-linked (no nesting)', () => {
  const tree = { type: 'root', children: [{ type: 'paragraph', children: [
    { type: 'link', url: 'https://example.com', children: [t('RFC 9421')] },
  ] }] };
  run(tree);
  assert.deepEqual(links(tree), ['https://example.com']);
});

test('headings are not linked', () => {
  const tree = { type: 'root', children: [{ type: 'heading', depth: 2, children: [t('RFC 9421 Signatures')] }] };
  run(tree);
  assert.equal(links(tree).length, 0);
});
