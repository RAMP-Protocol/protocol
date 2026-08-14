// Direct behavioral regression for the base64 wire forms of a bytes-rule field.
//
// protoschema renders a bytes field too loose in both rule kinds, so
// merge_schema.tighten_bytes_len rewrites them from the bytesgen manifest:
//   - bytes.len=32 (the Ed25519 keys, signed_url_hash): protoschema's 43..44
//     CHARACTER window also admits a 33-byte value (44 unpadded chars) and a
//     31-byte padded value (44 chars with "=="). The rewrite pins the payload
//     to exactly 43 chars of ONE alphabet plus optional exact padding.
//   - bytes.min_len=1 (the canonical-bytes fields): protoschema's pattern counts
//     padding as content, so "==" (zero payload bytes, which Go protojson
//     refuses to decode) passed. The rewrite requires the encoded payload chars
//     of at least 1 byte BEFORE the padding tail.
//
// The rows live in conformance/testdata/bytes_wire_forms.json, shared with the
// Pydantic harness (gen/python/tests/test_bytes_wire_forms.py) and pinned
// against Go itself by conformance/bytes_wire_forms_test.go — Go protojson +
// protovalidate is the oracle the generated patterns mirror. See that file's
// $comment for why the generated corpus cannot cover this axis.
import { describe, it, expect } from "vitest";
import * as schemas from "../wire/schemas.ts";
import vectors from "../../../conformance/testdata/bytes_wire_forms.json";

type Form = { value: string; accepted: boolean; why: string };

const CASES: Array<[message: string, field: string, value: string, accepted: boolean]> =
  vectors.fields.flatMap((f) =>
    (vectors.form_sets as Record<string, { forms: Form[] }>)[f.form_set].forms.map(
      (form): [string, string, string, boolean] => [f.message, f.field, form.value, form.accepted],
    ),
  );

describe("bytes rules decide every base64 wire form", () => {
  // Guard against a renamed key or a moved file making the suite vacuous.
  it("vectors are non-empty", () => expect(CASES.length).toBeGreaterThan(0));

  for (const [message, field, value, accepted] of CASES) {
    const schema = (schemas as Record<string, { safeParse: (v: unknown) => { success: boolean } }>)[
      `${message}Schema`
    ];
    const base = (vectors.bases as Record<string, Record<string, unknown>>)[message];
    it(`${message}.${field} = ${JSON.stringify(value)} -> ${accepted ? "accept" : "reject"}`, () => {
      expect(schema).toBeDefined();
      expect(base).toBeDefined();
      expect(schema.safeParse({ ...base, [field]: value }).success).toBe(accepted);
    });
  }
});
