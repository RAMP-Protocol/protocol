import { z } from "zod";
import {
  LicenseSchema,
  LicenseTermSchema,
  ObligationSchema,
  PricingSchema,
  RegistrationFailureSchema,
  RestrictionSchema,
  WellKnownManifestSchema,
} from "../../../gen/ts/wire/schemas.ts";

// Cross-field (message-CEL) refinements — the one genuinely net-new L1 surface.
//
// The 9 cross-field rules live ONLY in proto/ramp/v1/ramp.proto as protovalidate
// message-CEL options; the Go oracle executes them via protovalidate. Field-level
// Zod (gen/ts/wire/schemas.ts) and Pydantic cannot express them. This layer
// closes that gap on the TS side: it transcribes each CEL predicate VERBATIM
// (see the per-rule comment) as a Zod .superRefine composed onto the generated
// <Message>Schema, and each refinement emits a STABLE rule-id matching the
// crossfield.json `rules` strings — the direct analogue of the Go oracle's
// ValidationRuleIDs(err) contains(got, want) contract, not pass/fail-only.
//
// The generated enum vocabularies are reused (composed onto the generated
// schema), never forked; the enum string values below are the generated enum's
// own members. The restriction FUNCTION token axis is validated at the field
// layer against gen/ts/vocab/functiontokens.
//
// Proto-JSON field names are snake_case (the wire standard; UseProtoNames=true).
// The accessors below read snake_case exclusively — the wire, corpus, and signed
// form are all snake_case.

/** Stable rule-id carried on each cross-field Zod issue via params.ruleId. */
export interface CrossFieldIssueParams {
  ruleId: string;
}

// ---- tolerant field accessors ---------------------------------------------

type Obj = Record<string, unknown>;

function asObj(v: unknown): Obj | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : undefined;
}

/** Read a field by its snake_case name (the only wire naming). */
function field(o: Obj, ...names: string[]): unknown {
  for (const n of names) {
    if (o[n] !== undefined) return o[n];
  }
  return undefined;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

// ---- generated enum members (reused, not forked) --------------------------
const OBLIGATION_KIND_SHARE_ALIKE = "OBLIGATION_KIND_SHARE_ALIKE";
const TERM_SEMANTICS_REFERENCE_ONLY = "TERM_SEMANTICS_REFERENCE_ONLY";
const REGISTRATION_FAILURE_INVALID_DATA = "REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA";
const PRICING_MODEL_FREE = "PRICING_MODEL_FREE";
const PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT";

// ---- per-message cross-field predicates -----------------------------------
// Each returns the rule-ids VIOLATED by the instance (empty => passes). The
// boolean expression mirrors the CEL predicate; a rule-id is emitted when the
// CEL predicate is FALSE (protovalidate rejects when the expression is false).

/** License.digest_required_with_uri: `this.uri == '' || this.uri_digest != ''`. */
function licenseRules(o: Obj): string[] {
  const uri = str(field(o, "uri"));
  // uri_digest is a string field; the shared valid instance also models a
  // present digest as a `digest` object — both count as "digest present".
  const uriDigest = str(field(o, "uri_digest"));
  const digestObj = asObj(field(o, "digest"));
  const hasDigest = uriDigest !== "" || digestObj !== undefined;
  if (uri !== "" && !hasDigest) return ["license.digest_required_with_uri"];
  return [];
}

/**
 * LicenseTerm rules:
 *  - reference_only.requires_uri:
 *    `this.semantics != REFERENCE_ONLY || (has(this.license) && this.license.uri != '')`
 *  - one_restriction_per_kind:
 *    `this.restrictions.all(r, this.restrictions.filter(o, o.kind == r.kind).size() <= 1)`
 */
function licenseTermRules(o: Obj): string[] {
  const out: string[] = [];
  const semantics = str(field(o, "semantics"));
  if (semantics === TERM_SEMANTICS_REFERENCE_ONLY) {
    const license = asObj(field(o, "license"));
    if (!license || str(field(license, "uri")) === "") {
      out.push("license_term.reference_only.requires_uri");
    }
  }
  const restrictions = field(o, "restrictions");
  if (Array.isArray(restrictions)) {
    const kinds = restrictions.map((r) => str(field(asObj(r) ?? {}, "kind")));
    const seen = new Set<string>();
    let dup = false;
    for (const k of kinds) {
      if (seen.has(k)) dup = true;
      seen.add(k);
    }
    if (dup) out.push("license_term.one_restriction_per_kind");
  }
  return out;
}

/**
 * Obligation.share_alike.requires_scope_license:
 * `this.kind != SHARE_ALIKE || (has(this.scope_license) && (this.scope_license.id != '' || this.scope_license.uri != ''))`.
 */
function obligationRules(o: Obj): string[] {
  if (str(field(o, "kind")) !== OBLIGATION_KIND_SHARE_ALIKE) return [];
  const raw = field(o, "scope_license");
  // scope_license is a License (object with id/uri); a bare non-empty string is
  // also accepted as an identifying id (the CEL's `id != ''` intent).
  const identified =
    (typeof raw === "string" && raw !== "") ||
    (asObj(raw) !== undefined &&
      (str(field(asObj(raw) as Obj, "id")) !== "" || str(field(asObj(raw) as Obj, "uri")) !== ""));
  return identified ? [] : ["obligation.share_alike.requires_scope_license"];
}

/**
 * Pricing rules:
 *  - per_unit.requires_unit: `this.model != PER_UNIT || this.unit != ''`
 *  - free.zero_rate: `this.model != FREE || this.rate == '' || this.rate.matches('^0+([.]0+)?$')`
 */
function pricingRules(o: Obj): string[] {
  const out: string[] = [];
  const model = str(field(o, "model"));
  if (model === PRICING_MODEL_PER_UNIT && str(field(o, "unit")) === "") {
    out.push("pricing.per_unit.requires_unit");
  }
  if (model === PRICING_MODEL_FREE) {
    const rate = str(field(o, "rate"));
    if (rate !== "" && !/^0+([.]0+)?$/.test(rate)) {
      out.push("pricing.free.zero_rate");
    }
  }
  return out;
}

/** Restriction.permitted_prohibited_disjoint: `this.permitted.all(p, !(p in this.prohibited))`. */
function restrictionRules(o: Obj): string[] {
  const permitted = field(o, "permitted");
  const prohibited = field(o, "prohibited");
  if (!Array.isArray(permitted) || !Array.isArray(prohibited)) return [];
  const banned = new Set(prohibited.map((p) => str(p)));
  for (const p of permitted) {
    if (banned.has(str(p))) return ["restriction.permitted_prohibited_disjoint"];
  }
  return [];
}

/**
 * WellKnownManifest.terms_digest_requires_terms_uri:
 * `this.terms_digest == '' || this.terms_uri != ''`. A digest pins the document
 * at terms_uri, so publishing one without the address it pins leaves nothing to
 * check the bytes against. Mirror of the License rule above.
 */
function wellKnownManifestRules(o: Obj): string[] {
  const termsDigest = str(field(o, "terms_digest"));
  const termsUri = str(field(o, "terms_uri"));
  if (termsDigest !== "" && termsUri === "") {
    return ["well_known_manifest.terms_digest_requires_terms_uri"];
  }
  return [];
}

/**
 * RegistrationFailure.field_errors_scoped_to_invalid_data:
 * `this.field_errors.size() == 0 || this.reason == 6`. The member list names what
 * failed the published schema, so any other reason carrying it publishes detail
 * that does not apply to the refusal.
 */
function registrationFailureRules(o: Obj): string[] {
  const fieldErrors = field(o, "field_errors");
  if (Array.isArray(fieldErrors) && fieldErrors.length > 0) {
    if (str(field(o, "reason")) !== REGISTRATION_FAILURE_INVALID_DATA) {
      return ["registration_failure.field_errors_scoped_to_invalid_data"];
    }
  }
  return [];
}

const RULES_BY_MESSAGE: Record<string, (o: Obj) => string[]> = {
  License: licenseRules,
  LicenseTerm: licenseTermRules,
  Obligation: obligationRules,
  Pricing: pricingRules,
  Restriction: restrictionRules,
  RegistrationFailure: registrationFailureRules,
  WellKnownManifest: wellKnownManifestRules,
};

/**
 * crossFieldRuleIds returns the cross-field (message-CEL) rule-ids the instance
 * violates, empty when it passes cross-field validation. Direct analogue of the
 * Go oracle's ValidationRuleIDs(err) over the crossfield corpus.
 */
export function crossFieldRuleIds(message: string, json: unknown): string[] {
  const fn = RULES_BY_MESSAGE[message];
  if (!fn) throw new Error(`crossFieldRuleIds: unknown message ${message}`);
  const o = asObj(json);
  return o ? fn(o) : [];
}

// ---- composed schemas (generated field-level + cross-field refinements) ----
// Exposed so consumers get one schema that enforces BOTH the generated
// field-level rules and the cross-field rules, each cross-field issue carrying
// its stable ruleId in params. The rule-id extraction above is independent of
// field-level validation, so a field error never masquerades as a cross-field
// verdict (and vice versa).

function attach<T extends z.ZodTypeAny>(schema: T, message: string): z.ZodEffects<T> {
  return schema.superRefine((value, ctx) => {
    for (const ruleId of crossFieldRuleIds(message, value)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `cross-field rule violated: ${ruleId}`,
        params: { ruleId } satisfies CrossFieldIssueParams,
      });
    }
  });
}

export const LicenseCrossFieldSchema = attach(LicenseSchema, "License");
export const LicenseTermCrossFieldSchema = attach(LicenseTermSchema, "LicenseTerm");
export const ObligationCrossFieldSchema = attach(ObligationSchema, "Obligation");
export const PricingCrossFieldSchema = attach(PricingSchema, "Pricing");
export const RestrictionCrossFieldSchema = attach(RestrictionSchema, "Restriction");
export const RegistrationFailureCrossFieldSchema = attach(RegistrationFailureSchema, "RegistrationFailure");
export const WellKnownManifestCrossFieldSchema = attach(WellKnownManifestSchema, "WellKnownManifest");
