// The wire policy the generated schemas are parsed under — gen/ts/wire/base.ts.
// Mirrors gen/python/tests/test_wire_policy.py.
//
// Two rules, both applied at every depth: an unset message field arrives as `null` (proto3
// JSON with EmitUnpopulated renders it rather than omitting it), and a lowerCamelCase
// answer is refused rather than silently parsed into a message with every multiword field
// missing.
import { describe, it, expect } from "vitest";

import { parseWire, WireNamingError } from "../wire/base.ts";
import {
  OfferSchema,
  ResourceResponseSchema,
  TransactionResponseSchema,
  UsageReportResponseSchema,
} from "../wire/schemas.ts";

// Captured from connectserver.EmitUnpopulatedJSONCodec() — the codec a RAMP deployment
// registers. Every unset message field is `null`, which is what the schemas alone reject.
const CODEC_BODIES: Array<[string, { safeParse: (v: unknown) => { success: boolean } }, string]> = [
  ["ResourceResponse", ResourceResponseSchema,
    '{"ver":"", "exchange":"exchange.test", "offers":[], "offer_groups":[], "ext":null, "ext_critical":[]}'],
  ["TransactionResponse", TransactionResponseSchema,
    '{"ver":"1.0", "agent_identity_hash":"", "items":[], "subscription_quota":[], "ext":null, "ext_critical":[]}'],
  ["UsageReportResponse", UsageReportResponseSchema,
    '{"ver":"", "report_id":"", "ext":null, "ext_critical":[]}'],
];

describe("an unset message field arrives as null", () => {
  for (const [name, schema, body] of CODEC_BODIES) {
    it(`${name} as the platform codec emits it`, () => {
      expect(parseWire(schema, JSON.parse(body)).success, name).toBe(true);
    });
  }

  it("a nested message field too", () => {
    expect(parseWire(OfferSchema, { offer_id: "o", exchange: "e.test", pricing: null }).success)
      .toBe(true);
  });

  it("and one inside a repeated message", () => {
    const r = parseWire<{ items: Array<Record<string, unknown>> }>(TransactionResponseSchema, {
      ver: "1.0",
      items: [{ transaction_id: "t", cost: null }],
    });
    expect(r.success).toBe(true);
    // The null is gone rather than carried: absent and null are the same state here.
    expect(r.success && "cost" in r.data.items[0]!).toBe(false);
  });

  it("a null inside an open map is a VALUE, and survives", () => {
    // Struct carries NullValue, so a null there is data the caller sent, not an absence.
    const r = parseWire<{ ext?: Record<string, unknown> }>(OfferSchema, {
      offer_id: "o", exchange: "e.test", ext: { nested: null },
    });
    expect(r.success).toBe(true);
    expect(r.success && r.data.ext).toEqual({ nested: null });
  });

  it("the caller's own object is not mutated", () => {
    const raw = { offer_id: "o", exchange: "e.test", pricing: null };
    parseWire(OfferSchema, raw);
    expect(raw.pricing).toBeNull();
  });
});

describe("a lowerCamelCase answer is refused", () => {
  it("at the message root", () => {
    expect(() =>
      parseWire(ResourceResponseSchema, { ver: "1.0", exchange: "e.test", offerGroups: [] }),
    ).toThrow(WireNamingError);
  });

  // The root-only version of this check could not see the case that matters. A stock
  // connect-go server omits unset fields, so TransactionResponse arrives as {ver, items} —
  // every root key a single word, identical in both spellings — while transaction_id sits
  // one level down and is dropped, reading as a purchase that succeeded with no
  // transaction id and no delivery URL.
  it("and one level down, where the dispute chain starts", () => {
    let err: unknown;
    try {
      parseWire(TransactionResponseSchema, {
        ver: "1.0",
        items: [{ transactionId: "t", offerId: "o", retrievalEndpoint: "https://edge/x" }],
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WireNamingError);
    expect((err as WireNamingError).key).toBe("transactionId");
    expect((err as WireNamingError).path).toBe("items[0]");
  });

  it("but an open map's keys are data, not field names", () => {
    const r = parseWire(OfferSchema, {
      offer_id: "o", exchange: "e.test", ext: { someCamelKey: 1, offerId: 2 },
    });
    expect(r.success).toBe(true);
  });

  it("and a field a newer version added is still accepted and dropped", () => {
    const r = parseWire<Record<string, unknown>>(OfferSchema, {
      offer_id: "o", exchange: "e.test", __unknown_future_field__: 1,
    });
    expect(r.success).toBe(true);
    expect(r.success && Object.keys(r.data)).not.toContain("__unknown_future_field__");
  });

  it("a key naming an inherited object member is not a declared field", () => {
    // shape["__proto__"] resolves to Object.prototype unless the lookup uses hasOwn, which
    // would hand the walk something that is not a schema.
    const raw = JSON.parse(
      '{"offer_id":"o","exchange":"e.test","__proto__":{"x":1},"constructor":{"y":2}}',
    );
    expect(parseWire(OfferSchema, raw).success).toBe(true);
  });

  // And it cannot smuggle a message past the depth check. Writing that key with a plain
  // assignment set the walk's own output prototype instead of creating a member: the value
  // was never walked, and Zod then read the declared keys back THROUGH the prototype chain
  // — so a camelCase items[] inside it parsed, with transaction_id empty, which is the
  // outcome the depth check exists to prevent.
  it("and cannot carry a message the walk never inspected", () => {
    const raw = JSON.parse('{"ver":"1.0","__proto__":{"items":[{"transactionId":"txn-1"}]}}');
    const parsed = parseWire<{ items?: unknown[] }>(TransactionResponseSchema, raw);
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.items).toBeUndefined();
  });
});
