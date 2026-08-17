// Safe validation of a published registration schema — TS port of the sdk/go
// oracle (helpers/regschema.go).
//
// An Exchange MAY publish AccountRegistration.data_schema in its ramp.json: a JSON
// Schema describing the RegisterRequest.registration_data it expects. Two parties
// read that schema and MUST agree — the Exchange enforcing it on the way in, and a
// client pre-checking a payload before it signs and sends one. A payload that
// passes one and fails the other is the failure this module exists to remove, so
// the rules live in the SDK once rather than in each consumer's choice of library.
//
// The client's copy is the harder half: it arrives out of a THIRD PARTY's
// manifest, which makes a schema an attacker-influenced input reached before any
// signature is checked. Hence: no reference is resolved outside the document, the
// dialect is pinned to draft 2020-12, and size, depth and the `pattern` alphabet
// are bounded. The pattern rule is not only about backtracking — see
// isSafeSchemaPattern.
//
// Pure: bytes in, verdict out, no IO and no state. Byte-parity-guarded against the
// Go oracle by the shared vectors at
// sdk/go/helpers/testdata/registration-schema-vectors.json.

import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020";

/**
 * maxRegistrationSchemaBytes is the published schema's size cap, measured as the
 * UTF-8 bytes of the data_schema member AS SERVED in ramp.json — which is why the
 * compile face takes raw bytes rather than a decoded document. A re-encoding is a
 * different length than what the origin sent, and the cap is defined over what the
 * origin sent.
 */
export const maxRegistrationSchemaBytes = 16384;

/**
 * maxRegistrationSchemaDepth bounds how deeply the schema document may nest. It
 * counts JSON containers, so a bare `{}` is depth 1. Deep allOf/$ref chains are
 * the cheapest way to make a compile expensive, and a real registration schema is
 * three to five levels deep.
 */
export const maxRegistrationSchemaDepth = 32;

/**
 * maxRegistrationFieldErrors is the number of member failures a refusal may carry
 * — the wire's own bound (RegistrationFailure.field_errors declares
 * repeated.max_items = 64), restated so the validator never builds a list the
 * contract would reject.
 */
export const maxRegistrationFieldErrors = 64;

/** The wire bounds on RegistrationFieldError.path and .error. */
export const maxRegistrationFieldErrorPathLen = 255;
export const maxRegistrationFieldErrorTextLen = 255;

/**
 * registrationSchemaDialect is the only $schema value a published data_schema may
 * name. A document that names none is read as this dialect; one that names another
 * is refused rather than validated under semantics its author did not intend.
 */
export const registrationSchemaDialect = "https://json-schema.org/draft/2020-12/schema";

/**
 * SchemaVerdict is the outcome of compiling a published data_schema. The tokens
 * are the Go `SchemaVerdict.String()` vocabulary verbatim, which is what the
 * shared vectors record — a union of string literals rather than a numeric enum,
 * matching the sibling AudienceVerdict.
 *
 * "no_verdict" is Go's zero value and is never returned here; it is in the
 * vocabulary because the corpus carries the whole vocabulary.
 */
export type SchemaVerdict =
	| "no_verdict"
	| "accepted"
	| "malformed"
	| "wrong_dialect"
	| "remote_ref"
	| "too_large"
	| "too_deep"
	| "unsafe_pattern"
	| "uncompilable";

/** One member failure, in the wire's RegistrationFieldError shape. */
export interface RegistrationFieldError {
	/**
	 * RFC 6901 JSON Pointer relative to registration_data; "" addresses
	 * registration_data itself, for whole-object failures.
	 */
	path: string;
	/** The violated CONSTRAINT — never the submitted value. */
	error: string;
}

/** One failure before it is narrowed to the wire's two-field shape. */
export interface SchemaViolation extends RegistrationFieldError {
	/**
	 * The failed keyword. The shared corpus pins THIS rather than the prose:
	 * `error` wording is validator-defined by contract, while the keyword is the
	 * same word in every JSON Schema library.
	 */
	keyword: string;
}

// Escape letters whose meaning is not shared by all three SDK engines. Each would
// otherwise let one SDK accept a schema another refuses, or — worse, because it is
// silent — let two SDKs accept the same schema and disagree about which payloads
// match it. See isSafeSchemaPattern for the full argument.
const divergentEscapes = new Set("123456789kpPAzZQECGK".split(""));

// Keywords whose value is arbitrary JSON DATA rather than a subschema. Their
// contents are never read as keywords, so a `const` carrying a "$ref" member is
// data. Their nesting is still bounded, by the lexical depth scan over the raw bytes.
const nonSchemaKeywords = new Set(["const", "default", "enum", "examples"]);

// Keywords that map NAMES to subschemas. Their child keys are property or
// definition names rather than keywords: {"properties": {"$ref": {...}}} declares
// a property called "$ref", not a reference.
const schemaMapKeywords = new Set([
	"properties",
	"patternProperties",
	"$defs",
	"definitions",
	"dependentSchemas",
]);

const referenceKeywords = ["$ref", "$dynamicRef", "$recursiveRef"] as const;

/**
 * isSafeSchemaPattern reports whether a `pattern` uses only constructs all three
 * SDK languages express identically.
 *
 * Draft 2020-12 patterns are ECMA-262, and the three SDKs run three different
 * engines over them: Go's RE2, JavaScript's RegExp and Python's `re`. The three
 * intersect on far less than any one of them accepts, and BOTH directions of the
 * gap are a bug. Lookaround, atomic groups and backreferences are legal ECMA and
 * refused by RE2, so a schema using them compiles in two SDKs and fails in the
 * third. Inline flags, Unicode property classes, text anchors and POSIX bracket
 * names run the other way — taken by RE2 or Python and either refused or read
 * DIFFERENTLY here. The second kind is the more dangerous, because nothing
 * errors: two SDKs both compile the pattern and then disagree about which
 * payloads match it.
 *
 * So the admitted alphabet is the intersection: a group opens with `(` or `(?:`
 * and nothing else, an escape names a character or one of the shared classes, and
 * `[[:` never appears. Refusing catastrophic backtracking falls out of the first
 * rule rather than being aimed at separately.
 */
export function isSafeSchemaPattern(pattern: string): boolean {
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "\\") {
			if (i + 1 >= pattern.length) {
				// A trailing backslash is not a pattern any engine compiles.
				return false;
			}
			if (divergentEscapes.has(pattern[i + 1]!)) return false;
			i++; // the escaped character is consumed, never re-read as syntax
			continue;
		}
		if (ch === "(" && pattern[i + 1] === "?") {
			// Everything spelled "(?..." is refused except the non-capturing group,
			// the only one all three engines write the same way. That covers
			// lookaround, the atomic group "(?>", inline flags "(?i)", and the named
			// group whose spelling differs by engine.
			if (pattern[i + 2] !== ":") return false;
			i += 2;
			continue;
		}
		if (ch === "[" && pattern.startsWith("[[:", i)) {
			// A POSIX class to RE2 and a bracket expression matching the literal
			// characters ":alph" here — the same pattern, two different languages of
			// matching strings, with no error on either side.
			return false;
		}
	}
	return true;
}

/** The 2020-12 identifier in the two spellings that name the same dialect. */
function isDialect(value: string): boolean {
	return value === registrationSchemaDialect || value === `${registrationSchemaDialect}#`;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Per-object rules, in the fixed order a document breaking two must answer. */
function checkKeywords(obj: Record<string, unknown>): SchemaVerdict {
	const dialect = obj["$schema"];
	if (typeof dialect === "string" && !isDialect(dialect)) return "wrong_dialect";
	for (const keyword of referenceKeywords) {
		const ref = obj[keyword];
		// A same-document reference starts at the document root ("#/$defs/x") or at
		// an anchor in it ("#name"). Anything else names a resource this document
		// does not carry, and resolving it is the fetch the contract forbids.
		if (typeof ref === "string" && !ref.startsWith("#")) return "remote_ref";
	}
	const pattern = obj["pattern"];
	if (typeof pattern === "string" && !isSafeSchemaPattern(pattern)) return "unsafe_pattern";
	// patternProperties states its regexes as KEYS, so they are checked here rather
	// than by the generic pattern branch above.
	const patternProperties = obj["patternProperties"];
	if (isPlainObject(patternProperties)) {
		for (const key of Object.keys(patternProperties).sort()) {
			if (!isSafeSchemaPattern(key)) return "unsafe_pattern";
		}
	}
	return "accepted";
}

/**
 * rawNestingDepth returns the deepest JSON container nesting in `raw`, counted
 * lexically — no parse, no recursion, one pass over the bytes.
 *
 * It is string-aware, so a brace inside a string literal is text rather than a
 * container, and escape-aware so a literal quote does not end the string early. It
 * does NOT check that the brackets balance: an unbalanced document is the parser's
 * to reject, and this only has to produce an upper bound on how deep a parser would
 * have to descend.
 *
 * Byte-wise rather than character-wise on purpose. Every delimiter it looks for is
 * ASCII, and no continuation byte of a multi-byte UTF-8 sequence can collide with
 * one, so decoding first would cost a pass and change nothing.
 */
function rawNestingDepth(raw: Uint8Array): number {
	let depth = 0;
	let deepest = 0;
	let inString = false;
	let escaped = false;
	for (const byte of raw) {
		if (inString) {
			if (escaped) escaped = false;
			else if (byte === 0x5c) escaped = true; // backslash
			else if (byte === 0x22) inString = false; // quote
			continue;
		}
		if (byte === 0x22) inString = true;
		else if (byte === 0x7b || byte === 0x5b) {
			// { [
			depth++;
			if (depth > deepest) deepest = depth;
		} else if (byte === 0x7d || byte === 0x5d) depth--; // } ]
	}
	return deepest;
}

/**
 * Walk a keyword whose child object maps NAMES to subschemas. The child's keys are
 * property or definition names, never keywords, so only its values are read as
 * schemas.
 */
function scanSchemaMap(child: unknown): SchemaVerdict {
	if (!isPlainObject(child)) {
		// Not the shape the keyword takes; walk it generically rather than guess. An
		// invalid schema is the compiler's to reject.
		return scan(child);
	}
	for (const name of Object.keys(child).sort()) {
		const verdict = scan(child[name]);
		if (verdict !== "accepted") return verdict;
	}
	return "accepted";
}

/**
 * Walk the decoded document once, enforcing the dialect, reference and pattern
 * rules. Depth is NOT its business — rawNestingDepth owns that bound and has
 * already run, which is what lets this walk recurse freely. The first failure
 * decides.
 */
function scan(node: unknown): SchemaVerdict {
	if (Array.isArray(node)) {
		for (const item of node) {
			const verdict = scan(item);
			if (verdict !== "accepted") return verdict;
		}
		return "accepted";
	}
	if (!isPlainObject(node)) return "accepted";

	const own = checkKeywords(node);
	if (own !== "accepted") return own;
	// Sorted so a document with two faults answers the same way on every run and in
	// every language.
	for (const key of Object.keys(node).sort()) {
		// A non-schema keyword's value is DATA. Its contents are not read as keywords
		// at all, so a `const` carrying a "$ref" member is a value a payload may equal
		// rather than a reference to resolve.
		if (nonSchemaKeywords.has(key)) continue;
		const child = node[key];
		const verdict = schemaMapKeywords.has(key) ? scanSchemaMap(child) : scan(child);
		if (verdict !== "accepted") return verdict;
	}
	return "accepted";
}

/**
 * clampPointer keeps a pointer inside the wire's length bound WITHOUT truncating
 * it. A pointer cut mid-token addresses a different member — or none — so an
 * over-long one degrades to the longest ANCESTOR that fits.
 */
function clampPointer(pointer: string): string {
	if (pointer.length <= maxRegistrationFieldErrorPathLen) return pointer;
	for (let i = pointer.length - 1; i > 0; i--) {
		if (pointer[i] === "/" && i <= maxRegistrationFieldErrorPathLen) return pointer.slice(0, i);
	}
	return "";
}

/**
 * clampText keeps the constraint text inside the wire's bound. The field also has
 * a minimum of one character, so an empty description becomes a generic one rather
 * than a message the contract would reject.
 */
function clampText(text: string): string {
	if (!text) return "does not conform to the published schema";
	return text.slice(0, maxRegistrationFieldErrorTextLen);
}

// Keywords whose constraint is a single schema-side bound worth stating verbatim.
const boundKeywords = new Set([
	"exclusiveMaximum",
	"exclusiveMinimum",
	"maxContains",
	"maxItems",
	"maxLength",
	"maxProperties",
	"maximum",
	"minContains",
	"minItems",
	"minLength",
	"minProperties",
	"minimum",
	"multipleOf",
	"pattern",
]);

// Keywords whose constraint has no short value-free rendering, so the text names
// the rule instead. `enum` and `const` omit the allowed values: they come off the
// schema and would be safe, but they can be long and are not needed to act.
// `additionalProperties` omits the offending member NAMES, which come off the
// PAYLOAD — a member name an operator chose is as much their data as its value.
const fixedText: Record<string, string> = {
	additionalProperties: "additional properties are not allowed",
	allOf: "must match every branch of allOf",
	anyOf: "must match at least one branch of anyOf",
	const: "must equal the value the schema fixes",
	contains: "must contain a matching item",
	dependentRequired: "dependentRequired",
	enum: "must be one of the values the schema enumerates",
	not: "must not match the schema under not",
	oneOf: "must match exactly one branch of oneOf",
	propertyNames: "property name does not match propertyNames",
	uniqueItems: "items must be unique",
};

/**
 * describe turns a failure into (keyword, constraint text).
 *
 * It reads ONLY the constraint side. Ajv's own `error.message` is never used,
 * because it quotes the offending value for several keywords, and the wire
 * contract forbids a refusal from carrying the submitted value back out.
 */
function describe(error: ErrorObject): { keyword: string; text: string } {
	const keyword = error.keyword || "schema";
	const params = error.params as Record<string, unknown>;
	if (keyword === "required") {
		// The name comes off the SCHEMA's required list, not off the payload — the
		// value that failed is precisely the value that is absent.
		const missing = params["missingProperty"];
		return {
			keyword,
			text: typeof missing === "string" ? `required: ${missing}` : "required",
		};
	}
	if (keyword === "type") {
		const want = params["type"];
		const wanted = Array.isArray(want) ? want : [want];
		return { keyword, text: `must be of type ${wanted.join(" or ")}` };
	}
	if (boundKeywords.has(keyword)) {
		// The bound comes off the schema, so naming it leaks nothing and is the one
		// piece of detail that makes a refusal actionable.
		const want = params["limit"] ?? params["pattern"] ?? params["multipleOf"];
		return { keyword, text: `${keyword}: ${String(want)}` };
	}
	const fixed = fixedText[keyword];
	if (fixed !== undefined) return { keyword, text: fixed };
	// Anything the table does not name still reports the keyword that failed, which
	// is enough to act on and carries nothing off the payload by construction.
	return { keyword, text: `does not satisfy ${keyword}` };
}

/**
 * A compiled, accepted data_schema. Immutable and safe to share, so a server
 * compiles the operator's schema once at start-up and a client caches one per
 * Exchange.
 */
export class RegistrationSchema {
	readonly #validate: ValidateFunction;

	constructor(validate: ValidateFunction) {
		this.#validate = validate;
	}

	/**
	 * Check a registration_data payload and name what failed. An empty array means
	 * the payload conforms.
	 *
	 * The result is ready for the refusal builder: `path` an RFC 6901 pointer
	 * relative to registration_data ("" addresses the whole object), `error` the
	 * violated CONSTRAINT and never the submitted value.
	 *
	 * The order is deterministic — entries are deduplicated by pointer and keyword,
	 * then sorted by both, before the list is capped. Three validators walk a
	 * failing document in three different orders, so an unsorted list is one no
	 * shared corpus could pin.
	 */
	validate(data: unknown): RegistrationFieldError[] {
		return this.violations(data).map(({ path, error }) => ({ path, error }));
	}

	/**
	 * The whole answer, keyword included. `validate` narrows it to the wire's
	 * two-field shape; the parity suite reads it whole, because the corpus pins the
	 * keyword while `error` wording is validator-defined by contract.
	 */
	violations(data: unknown): SchemaViolation[] {
		const instance = data === null || data === undefined ? {} : data;
		if (this.#validate(instance)) return [];
		const errors = this.#validate.errors ?? [];

		// Drop any error that has descendants: a composite keyword (oneOf, anyOf,
		// if) reports itself AND the branch failures underneath it, while Go's
		// oracle reports only the leaves. Ajv's schemaPath makes the relationship
		// explicit, so the filter is exact rather than a keyword denylist — and a
		// composite that failed with NO branch errors (oneOf matching two branches)
		// is a leaf and survives, which is what Go does too.
		const leaves = errors.filter(
			(e) => !errors.some((o) => o !== e && o.schemaPath.startsWith(`${e.schemaPath}/`)),
		);

		const flat: SchemaViolation[] = [];
		const seen = new Map<string, number>();
		for (const error of leaves) {
			const { keyword, text } = describe(error);
			const path = clampPointer(error.instancePath);
			const key = `${path} ${keyword}`;
			const at = seen.get(key);
			if (at !== undefined) {
				// Where a key repeats, the lexicographically smallest text wins, so the
				// prose does not depend on which duplicate was walked first.
				if (text < flat[at]!.error) flat[at]!.error = clampText(text);
				continue;
			}
			seen.set(key, flat.length);
			flat.push({ path, keyword, error: clampText(text) });
		}
		flat.sort((a, b) => (a.path === b.path ? cmp(a.keyword, b.keyword) : cmp(a.path, b.path)));
		return flat.slice(0, maxRegistrationFieldErrors);
	}
}

// Byte-order comparison, matching Go's string ordering and Python's — JavaScript's
// default Array#sort compares UTF-16 code units too, but only via string coercion
// on the whole element, so the comparator is written out.
function cmp(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * compileRegistrationSchema checks a published data_schema against every rule and
 * compiles it.
 *
 * `raw` is the schema AS SERVED — the exact UTF-8 bytes of the data_schema member
 * in ramp.json — because maxRegistrationSchemaBytes is defined over those bytes.
 *
 * The schema is null unless the verdict is "accepted". Nothing throws: every way
 * this can fail is a property of the schema, and both callers need to know WHICH.
 * They read the same refusal differently, and that difference is the contract. A
 * CLIENT pre-checking a payload treats any non-accepted verdict as "do not
 * pre-check" and sends anyway — the Exchange's enforcement is the deciding one, and
 * a client that refused here would block a payload the Exchange would have taken.
 * An EXCHANGE compiling its OWN configured schema treats the same verdict as an
 * operator misconfiguration, and must not advertise a schema it cannot enforce.
 */
export function compileRegistrationSchema(raw: Uint8Array | string): {
	schema: RegistrationSchema | null;
	verdict: SchemaVerdict;
} {
	const bytes = typeof raw === "string" ? new TextEncoder().encode(raw) : raw;
	// Size first, on the bytes as served and before any parse: an oversized document
	// must not be decoded to find out that it was oversized.
	if (bytes.length > maxRegistrationSchemaBytes) return { schema: null, verdict: "too_large" };
	// Depth SECOND, and still on the raw bytes — before the document is handed to a
	// JSON parser rather than after. Every parser across the three SDKs descends
	// recursively, and two of them abort on a deeply nested document in a way this
	// face cannot map onto a verdict (Python raises RecursionError, which is not the
	// exception a malformed document raises), so a check placed after the parse is
	// reached only for documents harmless enough to parse. Lexical counting needs no
	// recursion at all.
	if (rawNestingDepth(bytes) > maxRegistrationSchemaDepth) {
		return { schema: null, verdict: "too_deep" };
	}

	let doc: unknown;
	try {
		doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
	} catch {
		return { schema: null, verdict: "malformed" };
	}
	// 2020-12 admits an object or a boolean at the top level, nothing else.
	if (!isPlainObject(doc) && typeof doc !== "boolean") {
		return { schema: null, verdict: "malformed" };
	}
	const verdict = scan(doc);
	if (verdict !== "accepted") return { schema: null, verdict };

	// strict:false because a published schema may legitimately carry keywords this
	// version of Ajv does not know, and the robustness principle applies to those
	// exactly as it does elsewhere in RAMP. allErrors because a refusal names EVERY
	// offending member, not the first. validateFormats:false because format,
	// contentEncoding and contentMediaType stay ANNOTATIONS — the three languages'
	// libraries default differently, so leaving this to a default would make the
	// same document conform in one SDK and not in another.
	//
	// No loadSchema and no external resource is registered, deliberately: with none,
	// a reference this module's scan did not recognise fails closed at compile
	// instead of being fetched.
	const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });
	try {
		return { schema: new RegistrationSchema(ajv.compile(doc as object)), verdict: "accepted" };
	} catch {
		return { schema: null, verdict: "uncompilable" };
	}
}
