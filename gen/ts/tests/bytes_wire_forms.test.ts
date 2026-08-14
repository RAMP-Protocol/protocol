// Direct behavioral regression for the base64 wire forms of a bytes-rule field.
//
// protoschema renders a bytes field too loose in both rule kinds, so
// merge_schema.tighten_bytes_len rewrites them from the bytesgen manifest:
//   - bytes.len=32 (the Ed25519 keys, signed_url_hash): protoschema's 43..44
//     CHARACTER window also admits a 33-byte value (44 unpadded chars) and a
//     31-byte padded value (44 chars with "=="). The rewrite pins the payload
//     to exactly 43 chars plus optional exact padding.
//   - bytes.min_len=1 (the canonical-bytes fields): protoschema's pattern counts
//     padding as content, so "==" (zero payload bytes, which Go protojson
//     refuses to decode) passed. The rewrite requires the encoded payload chars
//     of at least 1 byte BEFORE the padding tail.
//
// The corpus cannot cover this: corpusgen sets values through protoreflect and
// protojson always re-encodes bytes into ONE canonical form — the padded,
// standard-alphabet encoding — so no unpadded, url-safe-alphabet, or
// malformed-base64 STRING can appear in a case; e.g. dropping the
// optional-padding tail from the pattern would keep every corpus gate green
// while the clients then reject the unpadded 43-char key Go accepts. This is
// the Zod half of gen/python/tests/test_bytes_wire_forms.py.
import { describe, it, expect } from "vitest";
import * as schemas from "../wire/schemas.ts";

// base64 of "k".repeat(32) as bytes — the corpus seed key value.
const K32_PADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=";
const K32_UNPADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s";
// base64 of [0xFB, 0xEF] * 16 — 32 bytes chosen so the two alphabets actually
// diverge ('+'/'/' vs '-'/'_'); protojson decodes EITHER.
const K32_STD_ALPHABET = "++/77/vv++/77/vv++/77/vv++/77/vv++/77/vv++8=";
const K32_URL_ALPHABET = "--_77_vv--_77_vv--_77_vv--_77_vv--_77_vv--8=";
// 33 bytes, unpadded: 44 chars — INSIDE protoschema's old character window.
const B33_UNPADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr";
// 31 bytes, padded: also 44 chars — the other side of the old window.
const B31_PADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2traw==";

// Valid corpus baselines (proto-JSON, snake_case), one per message under test.
const BASES: Record<string, Record<string, unknown>> = {
  TransactionEvidence: {
    agent_acceptance_canonical_bytes: "eyJyZXF1ZXN0ZXJfaWQiOiJhZ2VudC1zZWVkIn0=",
    agent_acceptance_signature: "ab".repeat(64),
    agent_acceptance_signature_algorithm: "EdDSA",
    agent_public_key: K32_PADDED,
    created_at: "2026-01-02T03:04:05Z",
    exchange_signing_public_key: K32_PADDED,
    offer_canonical_bytes: "eyJvZmZlcl9pZCI6Im9mZmVyLXNlZWQifQ==",
    offer_id: "offer-seed",
    offer_json: '{"offer_id":"offer-seed"}',
    offer_sig: "ab".repeat(64),
    offer_sig_algorithm: "EdDSA",
    request_idempotency_key: "idem-tx",
    tenant_id: "tenant-seed",
    transaction_id: "tx-seed",
  },
  TransactionState: {
    expiry: "2026-01-02T03:04:05Z",
    idempotency_key: "idem-tx:offer-seed",
    signed_url_hash: "aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg=",
  },
};

type Form = [value: string, accepted: boolean];

// The base64 forms every EXACT-length (len=32) field must decide the same way.
const EXACT32_FORMS: Form[] = [
  [K32_PADDED, true], // padded canonical form (what protojson emits)
  [K32_UNPADDED, true], // unpadded form (protojson decodes it; the corpus never shows it)
  [K32_STD_ALPHABET, true], // standard alphabet with real +/
  [K32_URL_ALPHABET, true], // url-safe alphabet (a JWK "x" value pasted verbatim)
  [B33_UNPADDED, false], // 33 bytes — inside the old 43..44 char window
  [B31_PADDED, false], // 31 bytes padded — 44 chars, also inside the old window
  [K32_UNPADDED + "==", false], // wrong padding length for a 32-byte payload
  ["", false], // zero bytes
];

// The forms every MINIMUM-length (min_len=1) field must decide the same way.
const MIN1_FORMS: Form[] = [
  ["eyJvZmZlcl9pZCI6Im9mZmVyLXNlZWQifQ==", true], // padded canonical form
  ["eyJvZmZlcl9pZCI6Im9mZmVyLXNlZWQifQ", true], // same value, unpadded
  ["AA", true], // exactly 1 byte, unpadded
  ["AA==", true], // exactly 1 byte, padded
  ["-_", true], // url-safe alphabet
  ["==", false], // pure padding: ZERO payload bytes; Go protojson refuses to decode it
  ["=", false],
  ["A=", false], // one payload char never decodes
  ["", false], // zero bytes (min_len 1)
];

const CASES: Array<[message: string, field: string, value: string, accepted: boolean]> = [
  ...EXACT32_FORMS.map((f): [string, string, string, boolean] =>
    ["TransactionEvidence", "exchange_signing_public_key", ...f]),
  ...EXACT32_FORMS.map((f): [string, string, string, boolean] =>
    ["TransactionEvidence", "agent_public_key", ...f]),
  ...EXACT32_FORMS.map((f): [string, string, string, boolean] =>
    ["TransactionState", "signed_url_hash", ...f]),
  ...MIN1_FORMS.map((f): [string, string, string, boolean] =>
    ["TransactionEvidence", "offer_canonical_bytes", ...f]),
  ...MIN1_FORMS.map((f): [string, string, string, boolean] =>
    ["TransactionEvidence", "agent_acceptance_canonical_bytes", ...f]),
];

describe("bytes rules decide every base64 wire form", () => {
  for (const [message, field, value, accepted] of CASES) {
    const schema = (schemas as Record<string, { safeParse: (v: unknown) => { success: boolean } }>)[
      `${message}Schema`
    ];
    it(`${message}.${field} = ${JSON.stringify(value)} -> ${accepted ? "accept" : "reject"}`, () => {
      expect(schema).toBeDefined();
      expect(schema.safeParse({ ...BASES[message], [field]: value }).success).toBe(accepted);
    });
  }
});
