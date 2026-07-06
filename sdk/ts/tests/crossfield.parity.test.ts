// Cross-field Zod parity (TypeScript side) — TDD red for ixs7u.5.
//
// Mirrors the sdk/go oracle test TestValidate_enforcesCrossFieldCEL
// (sdk/go/helpers/validate_corpus_test.go) against the SHARED corpus
// conformance/corpus/crossfield.json (7 cases / 5 messages: License,
// LicenseTerm, Obligation, Pricing, Restriction).
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
// RED now purely because sdk/ts/src/crossfield.ts does not exist yet. The
// implement step authors the cross-field refinements (each emitting a stable
// rule-id) composed onto the generated <Message>Schema, at which point this goes
// green with no change to the assertions.
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

describe("sdk/ts cross-field refinements reject the Go crossfield mutants with matching rule-ids", () => {
  const cases = crossfield as CorpusCase[];

  it("crossfield corpus has the expected shape (>=7 mutants / 5 messages)", () => {
    expect(cases.length).toBeGreaterThanOrEqual(7);
    const messages = new Set(cases.map((c) => c.message));
    expect(messages).toEqual(
      new Set(["License", "LicenseTerm", "Obligation", "Pricing", "Restriction"]),
    );
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
];

describe("sdk/ts cross-field refinements do not over-reject valid instances", () => {
  for (const v of validInstances) {
    it(`${v.name} passes cross-field with no rule-ids`, () => {
      const got = check(v.message, v.json);
      expect(got, `${v.name}: unexpected cross-field rule-ids ${JSON.stringify(got)}`).toEqual([]);
    });
  }
});
