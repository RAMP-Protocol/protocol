// Cross-field Zod parity (TypeScript side): mirrors the Go cross-field CEL oracle
// — each invalid instance is rejected and the expected rule-id appears in the
// SDK's reported cross-field rule-ids.
//
// Mirrors the sdk/go oracle test TestValidate_enforcesCrossFieldCEL
// (sdk/go/helpers/validate_corpus_test.go) against the SHARED corpus
// conformance/corpus/crossfield.json (9 cases / 7 messages: License,
// LicenseTerm, Obligation, Pricing, RegistrationFailure, Restriction,
// WellKnownManifest).
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

  it("crossfield corpus has the expected shape (>=8 mutants / 6 messages)", () => {
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
