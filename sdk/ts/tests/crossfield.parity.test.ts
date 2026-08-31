// Cross-field Zod parity (TypeScript side): mirrors the Go cross-field CEL oracle
// — each invalid instance is rejected and the expected rule-id appears in the
// SDK's reported cross-field rule-ids.
//
// Mirrors the sdk/go oracle test TestValidate_enforcesCrossFieldCEL
// (sdk/go/helpers/validate_corpus_test.go) against the SHARED corpus
// conformance/corpus/crossfield.json. Which messages and how many cases is read
// from the corpus itself rather than written down here: the counts in this comment
// went stale one commit after the last expansion, and a number nothing checks is a
// number that drifts.
//
// The Go oracle asserts TWO things per mutant, not pass/fail only:
//   (1) the invalid instance is REJECTED, and
//   (2) each recorded message-CEL RULE ID (case.rules[]) appears in
//       ValidationRuleIDs(err).
// A pass/fail-only TS mirror is strictly weaker (a refinement could fire for the
// WRONG reason), so this test asserts the matching rule-id string is present in
// the SDK's reported cross-field rule-ids — the direct analogue of the Go
// `contains(got, want)` check.
//
// The Go corpus is negatives-only. To catch OVER-rejection (a refinement that
// fires on a legitimately-valid instance), this test also drives >=1 VALID
// instance per message and asserts it passes with NO cross-field rule-ids.
//
// The corpus is negatives-only, so the valid instances below are the only guard
// against a refinement that fires on a legitimately-valid message. A rule
// registered without one can have its predicate inverted while every test here
// stays green, which is why the instance list is pinned to the registered rule
// set rather than merely being long enough.
import { describe, it, expect } from "vitest";
import { crossFieldRuleIds } from "../src/crossfield.ts";
import * as crossfieldModule from "../src/crossfield.ts";
import * as baseSchemas from "../../../gen/ts/wire/schemas.ts";
import { parseWire, underWirePolicy, WireNamingError } from "../../../gen/ts/wire/base.ts";
import crossfield from "../../../conformance/corpus/crossfield.json";
// Reference generated vocabulary tokens rather than string literals for the
// axis-value fields (restriction terms use the FUNCTION token vocabulary).
import { AiTrain, AiInput } from "../../../gen/ts/vocab/functiontokens.ts";

// Contract mirrored from the Go oracle's ValidationRuleIDs(err): given a message
// name and a proto-JSON instance, return the cross-field rule-ids the SDK's
// refinement layer raised (empty array => the instance passed cross-field
// validation). The implement step provides this over the composed Zod schemas.
type CrossFieldRuleIds = (message: string, json: unknown) => string[];

type CorpusCase = {
  id: string;
  message: string;
  valid: boolean;
  rules: string[];
  json: unknown;
};

const check = crossFieldRuleIds as CrossFieldRuleIds;

// The registered cross-field rule set, named once. The corpus shape assertion and
// the valid-instance coverage pin both read it, so a message can never be added to
// one and forgotten in the other.
const expectedMessages = new Set([
  "GetAccountStatusResponse",
  "License",
  "LicenseTerm",
  "Obligation",
  "Pricing",
  "RegistrationFailure",
  "Restriction",
  "WellKnownManifest",
]);

describe("sdk/ts cross-field refinements reject the Go crossfield mutants with matching rule-ids", () => {
  const cases = crossfield as CorpusCase[];

  it("crossfield corpus has the expected shape (>=8 mutants / every cross-field message)", () => {
    expect(cases.length).toBeGreaterThanOrEqual(8);
    const messages = new Set(cases.map((c) => c.message));
    expect(messages).toEqual(expectedMessages);
  });

  for (const c of cases) {
    it(`${c.id} rejected with rule-ids ${JSON.stringify(c.rules)}`, () => {
      expect(c.valid, `corpus case ${c.id} must be invalid`).toBe(false);
      const got = check(c.message, c.json);
      // rejected at all
      expect(got.length, `${c.id} was accepted (no cross-field rule fired)`).toBeGreaterThan(0);
      // the message-CEL rule id(s) recorded by the oracle must be present
      for (const want of c.rules) {
        // "required" is a presence rule protovalidate co-emits with
        // reference_only.requires_uri; the cross-field layer must surface the
        // cross-field rule id at minimum, so only assert the message-CEL ids.
        if (want === "required") continue;
        expect(got, `${c.id}: expected rule ${want} in ${JSON.stringify(got)}`).toContain(want);
      }
    });
  }
});

// VALID instances (one per message) — invert each mutant's single violated
// predicate so the instance is legitimately cross-field-clean. These catch
// OVER-rejection: the SDK must report NO cross-field rule-ids for them.
const validInstances: { name: string; message: string; json: unknown }[] = [
  {
    // License.digest_required_with_uri: a uri present WITH a digest satisfies it.
    name: "License with uri+digest",
    message: "License",
    json: {
      id: "CC-BY-4.0",
      uri: "https://example.com/license",
      digest: {
        algorithm: "DIGEST_ALGORITHM_SHA256",
        value: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
      },
    },
  },
  {
    // LicenseTerm.one_restriction_per_kind: one restriction per kind is fine.
    name: "LicenseTerm with one restriction per kind",
    message: "LicenseTerm",
    json: {
      pricing: { model: "PRICING_MODEL_FREE", rate: "0" },
      restrictions: [
        { kind: "RESTRICTION_KIND_FUNCTION", permitted: [AiTrain] },
      ],
      semantics: "TERM_SEMANTICS_ENUMERATED",
    },
  },
  {
    // Obligation.share_alike.requires_scope_license: SHARE_ALIKE WITH a
    // scope_license satisfies the implication.
    name: "Obligation SHARE_ALIKE with scope_license",
    message: "Obligation",
    json: {
      kind: "OBLIGATION_KIND_SHARE_ALIKE",
      trigger: "OBLIGATION_TRIGGER_ON_USE",
      scope_license: "CC-BY-SA-4.0",
    },
  },
  {
    // Pricing.free.zero_rate: FREE with rate "0" satisfies it.
    name: "Pricing FREE with zero rate",
    message: "Pricing",
    json: { model: "PRICING_MODEL_FREE", rate: "0" },
  },
  {
    // Restriction.permitted_prohibited_disjoint: disjoint permitted/prohibited
    // sets satisfy it.
    name: "Restriction with disjoint permitted/prohibited",
    message: "Restriction",
    json: {
      kind: "RESTRICTION_KIND_FUNCTION",
      permitted: [AiTrain],
      prohibited: [AiInput],
    },
  },
  {
    // field_errors_scoped_to_invalid_data: the member list WITH the one reason
    // it belongs to.
    name: "RegistrationFailure INVALID_REGISTRATION_DATA with field_errors",
    message: "RegistrationFailure",
    json: {
      reason: "REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA",
      field_errors: [{ path: "/vat_id", error: "required" }],
    },
  },
  {
    // The other side: any other reason, carrying no member list.
    name: "RegistrationFailure TERMS_DIGEST_STALE without field_errors",
    message: "RegistrationFailure",
    json: { reason: "REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE" },
  },
  {
    // terms_digest_requires_billing_ref: a digest WITH the account it hangs on.
    name: "GetAccountStatusResponse with billing_ref+terms_digest",
    message: "GetAccountStatusResponse",
    json: {
      ver: "1.0",
      billing_ref: "acct-1",
      active: true,
      terms_digest: "sha256:" + "ab".repeat(32),
    },
  },
  {
    // An account whose Exchange publishes no terms digest, so none was recorded.
    // This is the instance that catches a predicate inverted to fire on a MISSING
    // terms_digest rather than on an accountless one.
    name: "GetAccountStatusResponse with an account and no digest",
    message: "GetAccountStatusResponse",
    json: { ver: "1.0", billing_ref: "acct-1", active: true },
  },
  {
    // The answer to an agent that has not registered: no account, so no digest
    // either. Catches a predicate that fires on a missing billing_ref alone.
    name: "GetAccountStatusResponse with no account at all",
    message: "GetAccountStatusResponse",
    json: { ver: "1.0", billing_ref: "", active: false },
  },
  {
    // terms_digest_requires_terms_uri: a digest WITH the address it pins.
    name: "WellKnownManifest with terms_uri+terms_digest",
    message: "WellKnownManifest",
    json: {
      ver: "1.0",
      role: "ROLE_EXCHANGE",
      domain: "exchange.example",
      terms_uri: "https://exchange.example/terms",
      terms_digest: `sha256:${"ab".repeat(32)}`,
    },
  },
  {
    // The common case the rule must NOT reject: no terms document at all. Both
    // members are optional, so a manifest publishing neither is clean — this is
    // the instance that catches a predicate inverted to fire on a missing
    // terms_uri rather than on an unpinned digest.
    name: "WellKnownManifest with neither terms member",
    message: "WellKnownManifest",
    json: { ver: "1.0", role: "ROLE_EXCHANGE", domain: "exchange.example" },
  },
];

// Pins the two lists together. A cross-field rule registered without a valid
// instance is a rule whose predicate can be inverted while the suite stays
// green: the corpus mutants only prove OVER-acceptance is caught, never
// over-rejection.
describe("sdk/ts every registered cross-field message has a valid instance", () => {
  it("valid-instance coverage matches the registered rule set", () => {
    const covered = new Set(validInstances.map((v) => v.message));
    expect(covered).toEqual(expectedMessages);
  });
});

describe("sdk/ts cross-field refinements do not over-reject valid instances", () => {
  for (const v of validInstances) {
    it(`${v.name} passes cross-field with no rule-ids`, () => {
      const got = check(v.message, v.json);
      expect(got, `${v.name}: unexpected cross-field rule-ids ${JSON.stringify(got)}`).toEqual([]);
    });
  }
});

// Pins the REGISTRY to the COMPOSED EXPORTS. These are two hand-maintained lists that
// must agree, and nothing made them agree before: a rule was added to the registry and
// the matching composed schema was not, so crossFieldRuleIds answered correctly while
// the composed schema — the surface a consumer is told to use — accepted the payload
// the rule forbids, and the Go oracle refused it.
//
// Compared by NAME rather than by asking each schema what it validates, because the
// failure being guarded is a MISSING schema: a check that iterates over the schemas
// that exist can never see the one that was never created.
describe("sdk/ts every registered cross-field rule has a composed schema", () => {
  it("composed schema exports match the registered rule set", () => {
    const composed = new Set(
      Object.keys(crossfieldModule)
        .filter((n) => n.endsWith("CrossFieldSchema"))
        .map((n) => n.slice(0, -"CrossFieldSchema".length)),
    );
    expect(composed).toEqual(expectedMessages);
  });
});

// The set-equality test above proves a schema EXISTS, not that it is wired up. A schema
// attached with the wrong message name, or one whose refinement never runs, still passes
// it. So drive the real corpus mutants through the composed schemas and require the
// refusal, which is the behaviour a consumer depends on.
//
// Only the mutants the BASE schema accepts can prove anything: the corpus carries
// minimal JSON, so a mutant that also misses a field-level requirement is refused before
// the refinement ever runs — a refusal that would pass this test while proving nothing
// about the layer under test. Those are skipped, and the count is asserted so the skip
// cannot quietly become "all of them".
describe("sdk/ts composed schemas actually run the cross-field layer", () => {
  it("every field-valid mutant is refused, naming its rule", () => {
    let checked = 0;
    for (const c of crossfield as CorpusCase[]) {
      if (c.valid) continue;
      const composed = (crossfieldModule as Record<string, unknown>)[
        `${c.message}CrossFieldSchema`
      ] as { safeParse: (v: unknown) => { success: boolean; error?: { issues: unknown[] } } };
      expect(composed, `no composed schema for ${c.message}`).toBeDefined();

      const base = (baseSchemas as Record<string, unknown>)[`${c.message}Schema`] as {
        safeParse: (v: unknown) => { success: boolean };
      };
      if (!base.safeParse(c.json).success) continue; // field-level refuses it first

      const got = composed.safeParse(c.json);
      expect(got.success, `${c.id}: composed schema accepted a mutant`).toBe(false);
      const rendered = JSON.stringify(got.error?.issues ?? []);
      for (const ruleId of c.rules) {
        expect(rendered, `${c.id}: refused, but not for ${ruleId}`).toContain(ruleId);
      }
      checked += 1;
    }
    expect(
      checked,
      "every crossfield mutant was already refused at field level, so this test exercised no composed schema at all",
    ).toBeGreaterThan(0);
  });
});

// Pins the composed schemas to the WIRE POLICY. A composed export is what a consumer is
// told to parse with, and it is a refinement wrapped around the generated object rather
// than the object itself. gen/ts/wire/base.ts drives its policy by INSPECTING the schema —
// unknown keys, a lowerCamelCase alias, a null that means unset — so a wrapper it cannot
// see through turns the whole policy off for that message while every direct safeParse
// test stays green. That is what happened: a camelCase answer parsed successfully into a
// message with every multiword field missing, and the cross-field rule that needed one of
// those fields could not fire.
//
// Driven through parseWire and underWirePolicy on purpose. A direct composed.safeParse —
// which the block above does, for the rule ids — never reaches the policy at all.
describe("sdk/ts composed schemas parse under the same wire policy as their base", () => {
  const camel = (k: string): string => k.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase());

  it("a lowerCamelCase alias is refused on the composed schema", () => {
    const composed = crossfieldModule.GetAccountStatusResponseCrossFieldSchema;
    expect(() =>
      parseWire(composed, {
        ver: "1.0",
        billingRef: "acct-1",
        termsDigest: "sha256:abababababababababababababababababababababababababababababababab",
      }),
    ).toThrow(WireNamingError);
  });

  it("a null still means unset, so a valid message is accepted", () => {
    const composed = crossfieldModule.GetAccountStatusResponseCrossFieldSchema;
    const got = parseWire(composed, {
      ver: "1.0",
      billing_ref: "acct-1",
      active: true,
      terms_digest: null,
    });
    expect(got.success, "a null on an unset field must not be a refusal").toBe(true);
  });

  it("a field-valid snake_case mutant is refused", () => {
    // The rule id is NOT asserted here: parseWire answers { success: false } and discards
    // the issues. The block above owns rule-id coverage, through a direct safeParse.
    const composed = crossfieldModule.GetAccountStatusResponseCrossFieldSchema;
    const got = parseWire(composed, {
      ver: "1.0",
      terms_digest: "sha256:abababababababababababababababababababababababababababababababab",
    });
    expect(got.success, "the composed schema accepted a payload its own rule forbids").toBe(false);
  });

  // Every composed export, not only the one the branch added: the defect was in the seam,
  // so it applied to all of them at once and a fix that closes one closes all.
  it("every composed export applies the policy its base applies", () => {
    let aliased = 0;
    for (const c of crossfield as CorpusCase[]) {
      const composed = (crossfieldModule as Record<string, unknown>)[
        `${c.message}CrossFieldSchema`
      ];
      const base = (baseSchemas as Record<string, unknown>)[`${c.message}Schema`];
      expect(composed, `no composed schema for ${c.message}`).toBeDefined();

      expect(
        underWirePolicy(composed, c.json, ""),
        `${c.id}: composed schema saw a different policy than its base`,
      ).toEqual(underWirePolicy(base, c.json, ""));

      // The alias probe is derived from the SCHEMA, not from the corpus payload: only three
      // of the ten corpus cases happen to carry a multiword key, and a probe built from
      // them would leave five of the eight messages untested for the half of the policy
      // that refuses. Every message with a multiword field on it is probed here.
      const shape = (base as { shape: Record<string, unknown> }).shape;
      const multiword = Object.keys(shape).find((k) => k.includes("_"));
      if (multiword === undefined) continue;
      aliased += 1;
      const alias = { ...(c.json as Record<string, unknown>), [camel(multiword)]: "x" };
      expect(
        () => underWirePolicy(composed, alias, ""),
        `${c.id}: composed schema accepted a lowerCamelCase alias its base refuses`,
      ).toThrow(WireNamingError);
    }
    expect(
      aliased,
      "no message carried a multiword field, so the alias half of the policy was never probed",
    ).toBeGreaterThan(0);
  });
});
