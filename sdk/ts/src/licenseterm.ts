// License-term canonicalisation and the ingest-tier checks — TS port of the
// sdk/go oracle (helpers/licenseterm.go), pinned to the shared
// licenseterm-vectors.json.
//
// A pushed entry passes two tiers at the Exchange. The wire tier is the
// generated field-level schema plus the cross-field (message-CEL) rules,
// applied to the entry as received. The ingest tier runs over the CANONICALISED
// terms: restriction tokens are folded and alias-resolved to their registered
// form, then a bare Pricing.unit or Quota.metric that is not a registered token
// is rejected, while an unregistered restriction token and an
// OBLIGATION_KIND_OTHER obligation without detail are accepted with a warning
// that reaches PushResourcesResponse.warnings. The Exchange's own run is the
// deciding one; a client-side verdict is advice about what that run will say.
//
// Folding is ASCII-only and only RFC 8259 whitespace is trimmed — a platform
// Unicode fold turns U+212A KELVIN SIGN into "k" and a homograph into a
// registered token. Messages are the exact strings the Go oracle emits, which
// are the strings an Exchange puts on the wire.

import {
	JSON_NAME_ALIAS_ERROR,
	WireNamingError,
	underWirePolicy,
} from "../../../gen/ts/wire/base.ts";
import { ResourceEntrySchema } from "../../../gen/ts/wire/schemas.ts";
import * as functiontokens from "../../../gen/ts/vocab/functiontokens.ts";
import * as geographytokens from "../../../gen/ts/vocab/geographytokens.ts";
import * as pricingunits from "../../../gen/ts/vocab/pricingunits.ts";
import * as quotametrics from "../../../gen/ts/vocab/quotametrics.ts";
import * as usertypes from "../../../gen/ts/vocab/usertypes.ts";
import { crossFieldRuleIds } from "./crossfield.ts";

/** Rejects a bare (non-namespaced) Pricing.unit that is not a registered metering token. */
export const RULE_PRICING_UNIT_REGISTERED = "pricing.unit.registered";
/** Rejects a bare Quota.metric that is not a registered quota token. */
export const RULE_QUOTA_METRIC_REGISTERED = "quota.metric.registered";
/**
 * Rejects a restriction whose permitted and prohibited lists name the same token
 * once both are canonicalised. The wire tier's rule compares the tokens AS
 * WRITTEN, so two accepted spellings of one token — an alias beside its
 * registered form, or two spellings differing only in ASCII case — pass it and
 * collide only after the fold.
 */
export const RULE_RESTRICTION_CANONICAL_DISJOINT = "restriction.canonical_disjoint";
/** Warns about a bare restriction token not registered on its axis; the term is accepted. */
export const RULE_RESTRICTION_TOKEN_REGISTERED = "restriction.token.registered";
/** Warns about an OBLIGATION_KIND_OTHER obligation carrying no detail. */
export const RULE_OBLIGATION_OTHER_REQUIRES_DETAIL = "obligation.other.requires_detail";

/**
 * One reason an entry or a term would be refused. `rule` is the rule id (an
 * ingest-tier id above, a cross-field CEL id, or `field.<zod issue code>` for a
 * field-level refusal — the field-level ids are language-local); `path` is the
 * snake_case proto-JSON field path relative to the checked message; `token` is
 * the offending value when the rule is about one token, else "".
 */
export interface RuleViolation {
	rule: string;
	path: string;
	token: string;
	message: string;
}

/** One non-fatal finding; `message` is the exact wire string of the warning. */
export interface RuleWarning {
	rule: string;
	path: string;
	token: string;
	message: string;
}

/** What validateLicenseTerm reports for one already-canonical term. */
export interface TermVerdict {
	violation: RuleViolation | null;
	warnings: RuleWarning[];
}

/** What validateResourceEntry reports: both tiers, wire tier first. */
export interface EntryVerdict {
	ok: boolean;
	violations: RuleViolation[];
	warnings: RuleWarning[];
}

type Obj = Record<string, unknown>;

const KIND_FUNCTION = "RESTRICTION_KIND_FUNCTION";
const KIND_GEOGRAPHY = "RESTRICTION_KIND_GEOGRAPHY";
const KIND_USER_TYPE = "RESTRICTION_KIND_USER_TYPE";
// The enum's zero, as the oracle spells it when a restriction carries no kind.
const KIND_UNSPECIFIED = "RESTRICTION_KIND_UNSPECIFIED";
const OBLIGATION_KIND_OTHER = "OBLIGATION_KIND_OTHER";

function asObj(v: unknown): Obj | undefined {
	return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : undefined;
}

function asArr(v: unknown): unknown[] {
	return Array.isArray(v) ? v : [];
}

function str(v: unknown): string {
	return typeof v === "string" ? v : "";
}

function isJSONWhitespace(c: string): boolean {
	return c === " " || c === "\t" || c === "\n" || c === "\r";
}

// The four RFC 8259 whitespace characters and nothing else, so a token padded
// with a non-breaking space stays padded, in every language.
function trimJSONWhitespace(s: string): string {
	let start = 0;
	let end = s.length;
	while (start < end && isJSONWhitespace(s.charAt(start))) start++;
	while (end > start && isJSONWhitespace(s.charAt(end - 1))) end--;
	return s.slice(start, end);
}

// ASCII letters only — no flag on the class, so no Unicode case folding.
function asciiLower(s: string): string {
	return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

function asciiUpper(s: string): string {
	return s.replace(/[a-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 32));
}

function hasCanonicalRule(kind: string): boolean {
	return kind === KIND_FUNCTION || kind === KIND_USER_TYPE || kind === KIND_GEOGRAPHY;
}

function isNamespacedToken(token: string): boolean {
	return token.includes(":");
}

// Two uppercase ASCII letters — the structural shape of an ISO 3166-1 alpha-2
// code, which the geography registry deliberately does not enumerate.
function isISOAlpha2(token: string): boolean {
	if (token.length !== 2) return false;
	const a = token.charCodeAt(0);
	const b = token.charCodeAt(1);
	return a >= 65 && a <= 90 && b >= 65 && b <= 90;
}

/**
 * canonicalRestrictionToken returns the canonical form of a restriction token
 * on an axis (`kind` is the RestrictionKind enum NAME): RFC 8259 whitespace
 * trimmed, ASCII case folded (lower for FUNCTION and USER_TYPE, upper for
 * GEOGRAPHY) and, where the axis authors aliases, the alias resolved to its
 * registered token. OTHER and any unknown axis are returned unchanged.
 * Applying it twice is a fixed point.
 */
export function canonicalRestrictionToken(kind: string, token: string): string {
	switch (kind) {
		case KIND_FUNCTION:
			return functiontokens.canonical(asciiLower(trimJSONWhitespace(token)));
		case KIND_USER_TYPE:
			return usertypes.canonical(asciiLower(trimJSONWhitespace(token)));
		case KIND_GEOGRAPHY:
			return geographytokens.canonical(asciiUpper(trimJSONWhitespace(token)));
		default:
			return token;
	}
}

/**
 * knownRestrictionToken reports whether an already-canonical token is
 * registered on its axis. GEOGRAPHY admits the registered specials and any
 * two-uppercase-letter ISO 3166-1 alpha-2 code; OTHER and unknown axes never.
 */
export function knownRestrictionToken(kind: string, token: string): boolean {
	switch (kind) {
		case KIND_FUNCTION:
			return functiontokens.isRegistered(token);
		case KIND_USER_TYPE:
			return usertypes.isRegistered(token);
		case KIND_GEOGRAPHY:
			return geographytokens.isRegistered(token) || isISOAlpha2(token);
		default:
			return false;
	}
}

function canonicalizeTokens(kind: string, tokens: unknown): unknown {
	if (!Array.isArray(tokens)) return tokens;
	return tokens.map((t) => (typeof t === "string" ? canonicalRestrictionToken(kind, t) : t));
}

/**
 * normalizeLicenseTerm returns a deep copy of the term (proto-JSON, snake_case)
 * with its restriction tokens rewritten to canonical form on every axis that
 * carries a canonicalisation rule. Nothing else moves. The input is untouched;
 * the Go oracle rewrites in place, and the corpus pins the output either way.
 */
export function normalizeLicenseTerm(term: Obj): Obj {
	const out = structuredClone(term);
	for (const r of asArr(out["restrictions"])) {
		const restriction = asObj(r);
		if (!restriction) continue;
		const kind = str(restriction["kind"]);
		if (!hasCanonicalRule(kind)) continue;
		if (restriction["permitted"] !== undefined) {
			restriction["permitted"] = canonicalizeTokens(kind, restriction["permitted"]);
		}
		if (restriction["prohibited"] !== undefined) {
			restriction["prohibited"] = canonicalizeTokens(kind, restriction["prohibited"]);
		}
	}
	return out;
}

/** normalizeResourceEntry returns a deep copy with every term normalised. */
export function normalizeResourceEntry(entry: Obj): Obj {
	const out = structuredClone(entry);
	const terms = asArr(out["terms"]);
	if (terms.length) {
		out["terms"] = terms.map((t) => {
			const term = asObj(t);
			return term ? normalizeLicenseTerm(term) : t;
		});
	}
	return out;
}

function bareUnregistered(token: string, registered: (s: string) => boolean): boolean {
	if (token === "" || isNamespacedToken(token)) return false;
	return !registered(token);
}

function restrictionTokenWarning(kind: string, tok: string, path: string): RuleWarning | undefined {
	if (tok === "" || isNamespacedToken(tok) || knownRestrictionToken(kind, tok)) return undefined;
	return {
		rule: RULE_RESTRICTION_TOKEN_REGISTERED,
		path,
		token: tok,
		// An absent kind is the enum's zero, and the oracle names it: Go formats the
		// enum, which spells the unset value rather than leaving a gap. These strings
		// are the exact bytes an Exchange puts in warnings[], so a doubled space here
		// is a real difference in what a publisher is told, not a rendering detail.
		message: `unregistered ${kind || KIND_UNSPECIFIED} restriction token "${tok}" (term accepted)`,
	};
}

/**
 * canonicalDisjointViolation returns the violation for the first permitted token
 * of r whose canonical form is also the canonical form of one of its prohibited
 * tokens, or undefined when the two lists name no token in common. It
 * canonicalises what it compares rather than trusting the term to have been
 * normalised, and it runs on every axis — where the fold is a no-op the check is
 * plain equality, which is what a server that never asked for the wire tier
 * needs. The finding names the canonical token, not the spellings that produced
 * it, so the message does not depend on whether the caller folded first.
 *
 * An element that is not a string is SKIPPED rather than coerced. Coercing it to ""
 * would report two ill-typed elements as a collision on the empty token, which names
 * the wrong fault; the wire tier already refuses a non-string where the schema says
 * string, the same division this file applies to an empty or namespaced token. Two
 * genuinely empty strings still collide, which is what the Go oracle answers.
 */
function canonicalDisjointViolation(i: number, r: Obj): RuleViolation | undefined {
	const permitted = asArr(r["permitted"]);
	const prohibited = asArr(r["prohibited"]);
	if (permitted.length === 0 || prohibited.length === 0) return undefined;
	const kind = str(r["kind"]);
	const banned = new Set(
		prohibited.filter((t) => typeof t === "string").map((t) => canonicalRestrictionToken(kind, t)),
	);
	for (let j = 0; j < permitted.length; j++) {
		const tok = permitted[j];
		if (typeof tok !== "string") continue;
		const canon = canonicalRestrictionToken(kind, tok);
		if (!banned.has(canon)) continue;
		return {
			rule: RULE_RESTRICTION_CANONICAL_DISJOINT,
			path: `restrictions[${i}].permitted[${j}]`,
			token: canon,
			message: `restriction token "${canon}" is both permitted and prohibited after canonicalisation`,
		};
	}
	return undefined;
}

/**
 * validateLicenseTerm runs the ingest-tier checks over one term, in a fixed
 * order: a bare Pricing.unit that is not registered, then the first offending
 * quota metric, then the first restriction whose permitted and prohibited lists
 * name one token once canonicalised. An accepted term carries one warning per
 * unregistered bare restriction token — restriction order, permitted before
 * prohibited — then one per OBLIGATION_KIND_OTHER obligation without detail.
 *
 * Every check but the disjointness one reads the term as already canonical. The
 * wire tier is not re-run here; disjointness is the one property both tiers
 * assert, over different values, so a term the boundary clears can still fail
 * here.
 */
export function validateLicenseTerm(term: Obj): TermVerdict {
	const unit = str(asObj(term["pricing"])?.["unit"]);
	if (bareUnregistered(unit, pricingunits.isRegistered)) {
		return {
			violation: {
				rule: RULE_PRICING_UNIT_REGISTERED,
				path: "pricing.unit",
				token: unit,
				message: `pricing unit "${unit}" is not a registered metering token`,
			},
			warnings: [],
		};
	}
	const quotas = asArr(term["quotas"]);
	for (let i = 0; i < quotas.length; i++) {
		const metric = str(asObj(quotas[i])?.["metric"]);
		if (bareUnregistered(metric, quotametrics.isRegistered)) {
			return {
				violation: {
					rule: RULE_QUOTA_METRIC_REGISTERED,
					path: `quotas[${i}].metric`,
					token: metric,
					message: `quota metric "${metric}" is not a registered quota token`,
				},
				warnings: [],
			};
		}
	}
	const restrictions = asArr(term["restrictions"]);
	for (let i = 0; i < restrictions.length; i++) {
		const r = asObj(restrictions[i]);
		if (!r) continue;
		const violation = canonicalDisjointViolation(i, r);
		if (violation) return { violation, warnings: [] };
	}
	const warnings: RuleWarning[] = [];
	for (let i = 0; i < restrictions.length; i++) {
		const r = asObj(restrictions[i]);
		if (!r) continue;
		const kind = str(r["kind"]);
		const permitted = asArr(r["permitted"]);
		for (let j = 0; j < permitted.length; j++) {
			const w = restrictionTokenWarning(kind, str(permitted[j]), `restrictions[${i}].permitted[${j}]`);
			if (w) warnings.push(w);
		}
		const prohibited = asArr(r["prohibited"]);
		for (let j = 0; j < prohibited.length; j++) {
			const w = restrictionTokenWarning(kind, str(prohibited[j]), `restrictions[${i}].prohibited[${j}]`);
			if (w) warnings.push(w);
		}
	}
	const obligations = asArr(term["obligations"]);
	for (let i = 0; i < obligations.length; i++) {
		const o = asObj(obligations[i]);
		if (!o) continue;
		if (str(o["kind"]) === OBLIGATION_KIND_OTHER && str(o["detail"]) === "") {
			warnings.push({
				rule: RULE_OBLIGATION_OTHER_REQUIRES_DETAIL,
				path: `obligations[${i}].detail`,
				token: "",
				message: "obligation of kind OTHER has no detail (term accepted)",
			});
		}
	}
	return { violation: null, warnings };
}

function zodPath(path: (string | number)[]): string {
	let out = "";
	for (const seg of path) {
		if (typeof seg === "number") out += `[${seg}]`;
		else out = out === "" ? seg : `${out}.${seg}`;
	}
	return out;
}

// Every message instance reachable from an entry that carries a cross-field
// rule, with its entry-relative path. The generated schema is field-level and
// the composed cross-field schemas attach per message, so the walk is explicit.
function crossFieldSites(entry: Obj): Array<{ path: string; message: string; value: unknown }> {
	const sites: Array<{ path: string; message: string; value: unknown }> = [];
	const terms = asArr(entry["terms"]);
	for (let i = 0; i < terms.length; i++) {
		const term = asObj(terms[i]);
		if (!term) continue;
		const base = `terms[${i}]`;
		sites.push({ path: base, message: "LicenseTerm", value: term });
		if (term["license"] !== undefined) sites.push({ path: `${base}.license`, message: "License", value: term["license"] });
		if (term["pricing"] !== undefined) sites.push({ path: `${base}.pricing`, message: "Pricing", value: term["pricing"] });
		const restrictions = asArr(term["restrictions"]);
		for (let j = 0; j < restrictions.length; j++) {
			sites.push({ path: `${base}.restrictions[${j}]`, message: "Restriction", value: restrictions[j] });
		}
		const obligations = asArr(term["obligations"]);
		for (let k = 0; k < obligations.length; k++) {
			const o = asObj(obligations[k]);
			sites.push({ path: `${base}.obligations[${k}]`, message: "Obligation", value: obligations[k] });
			if (o?.["scope_license"] !== undefined) {
				sites.push({ path: `${base}.obligations[${k}].scope_license`, message: "License", value: o["scope_license"] });
			}
		}
	}
	return sites;
}

/**
 * validateResourceEntry reports the verdict the Exchange reaches for one entry
 * (proto-JSON, snake_case), both tiers in the Exchange's order: the wire tier —
 * the generated field-level schema over the entry as given, plus every
 * cross-field rule reachable from it — then the ingest tier over a normalised
 * copy of the terms. The entry passed in is never modified. The Exchange stops
 * at the first tier that fails; this face reports both so a publisher fixes
 * everything in one round. Paths are relative to the entry.
 *
 * The wire tier runs UNDER THE WIRE POLICY, the same seam every other parse of a
 * generated schema in this SDK goes through. A generated schema describes the
 * message and cannot describe the two things that are true of the wire: a `null`
 * is how proto-JSON spells "no value" for any field, and a lowerCamelCase
 * json_name alias is out of contract. A bare safeParse would answer wrongly in
 * both directions on bodies a publisher really produces — an Exchange serving
 * EmitUnpopulated renders an unset message field as null, and stock
 * protojson.Marshal emits camelCase, which the schemas STRIP, so an entry whose
 * every multiword field was silently dropped would come back accepted. This
 * face exists to predict the Exchange's verdict, so it applies the Exchange's
 * reading of the bytes.
 */
export function validateResourceEntry(entry: Obj): EntryVerdict {
	const violations: RuleViolation[] = [];
	try {
		const parsed = ResourceEntrySchema.safeParse(underWirePolicy(ResourceEntrySchema, entry, ""));
		if (!parsed.success) {
			for (const issue of parsed.error.issues) {
				violations.push({ rule: `field.${issue.code}`, path: zodPath(issue.path), token: "", message: issue.message });
			}
		}
	} catch (cause) {
		// The naming refusal is the one policy failure that throws rather than
		// returning an issue, so it is mapped to a violation here. Same id as the
		// Python port reports it under, so a consumer branches on one string.
		if (!(cause instanceof WireNamingError)) throw cause;
		violations.push({
			rule: `field.${JSON_NAME_ALIAS_ERROR}`,
			path: cause.path,
			token: "",
			message: cause.message,
		});
	}
	// Everything below reads members off the entry, so a value that is not an object
	// has nothing to walk. The parse above has already said so — a non-object yields
	// the schema's own type violation — and continuing would throw instead of
	// returning that verdict. A publisher feeding this a parsed JSONL line reaches
	// it with whatever the line held, so a malformed row must get a verdict like any
	// other refusal rather than an exception the Python port does not raise either.
	if (!asObj(entry)) return { ok: violations.length === 0, violations, warnings: [] };
	for (const site of crossFieldSites(entry)) {
		for (const id of crossFieldRuleIds(site.message, site.value)) {
			violations.push({ rule: id, path: site.path, token: "", message: `cross-field rule violated: ${id}` });
		}
	}
	const warnings: RuleWarning[] = [];
	const normalized = normalizeResourceEntry(entry);
	const terms = asArr(normalized["terms"]);
	for (let i = 0; i < terms.length; i++) {
		const term = asObj(terms[i]);
		if (!term) continue;
		const prefix = `terms[${i}].`;
		const verdict = validateLicenseTerm(term);
		if (verdict.violation) {
			violations.push({ ...verdict.violation, path: prefix + verdict.violation.path });
			continue;
		}
		for (const w of verdict.warnings) warnings.push({ ...w, path: prefix + w.path });
	}
	return { ok: violations.length === 0, violations, warnings };
}
