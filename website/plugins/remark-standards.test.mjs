import { test } from 'node:test';
import assert from 'node:assert/strict';
import { visit } from 'unist-util-visit';
import remarkStandards from './remark-standards.mjs';

const run = (tree) => { remarkStandards()(tree); return tree; };
const para = (...children) => ({ type: 'root', children: [{ type: 'paragraph', children }] });
const t = (value) => ({ type: 'text', value });
const links = (tree) => { const u = []; visit(tree, 'link', (n) => u.push(n.url)); return u; };

// Expected URLs are LITERAL here (not imported from the registry) so a typo in the
// registry fails a test — the self-referential assertion the prior tests had is gone.

test('an RFC reference links to the canonical rfc-editor URL', () => {
  assert.ok(links(run(para(t('Signed per RFC 9421 rules.')))).includes('https://www.rfc-editor.org/rfc/rfc9421'));
});

test('a named standard links to its canonical URL', () => {
  assert.ok(links(run(para(t('We use C2PA for provenance.')))).includes('https://c2pa.org/specifications/'));
});

test('a case variant (Ed25519) links — previously a dead alias', () => {
  assert.ok(links(run(para(t('Requests are Ed25519-signed.')))).includes('https://www.rfc-editor.org/rfc/rfc8032'));
});

test('only the first mention of a standard is linked per page', () => {
  const got = links(run(para(t('RFC 9421 here, and RFC 9421 again.')))).filter((u) => u.endsWith('rfc9421'));
  assert.equal(got.length, 1);
});

test('a term inside a compound prefix is not split-linked (RAMP-C2PA)', () => {
  assert.equal(links(run(para(t('the RAMP-C2PA profile')))).length, 0);
});

test('a standard already linked to its canonical URL is not re-linked', () => {
  const tree = { type: 'root', children: [{ type: 'paragraph', children: [
    { type: 'link', url: 'https://c2pa.org/specifications/', children: [t('C2PA')] },
    t(' — and C2PA again later'),
  ] }] };
  run(tree);
  assert.deepEqual(links(tree), ['https://c2pa.org/specifications/']); // no redundant second link
});

test('a deep-link to a different URL does NOT suppress the general reference', () => {
  const tree = { type: 'root', children: [{ type: 'paragraph', children: [
    { type: 'link', url: 'https://spec.c2pa.org/specifications/2.3/', children: [t('C2PA Specification 2.3')] },
    t(' — see the C2PA overview'),
  ] }] };
  run(tree);
  assert.ok(links(tree).includes('https://spec.c2pa.org/specifications/2.3/'), 'deep-link kept');
  assert.ok(links(tree).includes('https://c2pa.org/specifications/'), 'general C2PA still gets the canonical link');
});

test('no nested anchor: a standard inside emphasis inside a link is left alone', () => {
  const tree = { type: 'root', children: [{ type: 'paragraph', children: [
    { type: 'link', url: 'https://manual.example', children: [{ type: 'emphasis', children: [t('RFC 9421')] }] },
  ] }] };
  run(tree);
  assert.deepEqual(links(tree), ['https://manual.example']);
});

test('headings are not linked', () => {
  const tree = { type: 'root', children: [{ type: 'heading', depth: 2, children: [t('RFC 9421 details')] }] };
  run(tree);
  assert.equal(links(tree).length, 0);
});
