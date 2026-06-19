// Fail-path coverage for the build-gating doc guard. Without this, a refactor that
// silently stops the guard from biting (an over-broad allow, a regex that no longer
// matches, a swallowed throw) would pass CI. These tests assert it still bites.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { visit } from 'unist-util-visit';
import remarkProto from './remark-proto.mjs';

const run = (tree) => { remarkProto()(tree, { path: 'test.mdx' }); return tree; };
const para = (value) => ({ type: 'root', children: [{ type: 'paragraph', children: [{ type: 'inlineCode', value }] }] });
const directive = (name, attributes) => ({ type: 'root', children: [{ type: 'leafDirective', name, attributes, children: [] }] });
const has = (tree, pred) => { let f = false; visit(tree, (n) => { if (pred(n)) f = true; }); return f; };

test('resolved reference is autolinked to its anchor', () => {
  const tree = run(para('TransactionRequest.idempotency_key'));
  assert.ok(has(tree, (n) => n.type === 'link' && n.url.includes('#transactionrequest')),
    'a real Message.field should become a link to the message heading');
});

test('unknown member of a real proto type FAILS the build', () => {
  assert.throws(() => run(para('TransactionRequest.bogus_field_zzz')), /unknown proto reference/,
    'the guard must throw on a known type with a nonexistent member');
});

test('a Type.member whose type is not proto is left alone (no false positive)', () => {
  assert.doesNotThrow(() => run(para('TenantCatalog.Lookup')));
});

test('a renamed/removed enum value (known enum prefix) FAILS the build', () => {
  assert.throws(() => run(para('DENIAL_REASON_NONEXISTENT_XYZ')), /unknown proto reference/,
    'a token carrying a known enum prefix must resolve — rename-safety in manual tables too');
});

test('a real prefixed enum value resolves and links', () => {
  const tree = run(para('DELIVERY_METHOD_DIRECT'));
  assert.ok(has(tree, (n) => n.type === 'link' && n.url.includes('#deliverymethod')));
});

test('a bare short enum form does not fail (no known prefix)', () => {
  assert.doesNotThrow(() => run(para('PER_UNIT')));
});

test('a non-proto ALL_CAPS token is left alone (no false positive)', () => {
  assert.doesNotThrow(() => run(para('RFC_9421')));
});

test('ignore-listed historical reference does not fail', () => {
  assert.doesNotThrow(() => run(para('Offer.quality')));
});

test('proto-enum directive expands to a table', () => {
  const tree = run(directive('proto-enum', { name: 'ObligationKind' }));
  assert.ok(has(tree, (n) => n.type === 'table'), 'directive should inject a table');
  assert.ok(has(tree, (n) => n.type === 'inlineCode' && n.value === 'ATTRIBUTION'), 'table should carry the enum values');
});

test('proto-enum on an unknown enum fails the build', () => {
  assert.throws(() => run(directive('proto-enum', { name: 'NotARealEnum' })), /unknown enum/);
});

test('proto-vocab directive renders the axis tokens', () => {
  const tree = run(directive('proto-vocab', { axis: 'function' }));
  assert.ok(has(tree, (n) => n.type === 'inlineCode' && n.value === 'ai-train'), 'vocab tokens should render');
});
