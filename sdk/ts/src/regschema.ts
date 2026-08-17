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

import type { RegistrationFieldError as RegistrationFieldErrorShape } from "./errordetail";

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
 * maxRegistrationSchemaEvaluations bounds the WORK of checking a payload, which the
 * size and depth caps do not: `anyOf` branches multiply along a reference chain, so a
 * schema can be small and shallow and still cost an unbounded amount to evaluate.
 * Cost is linear in this count, so the bound is really a time bound expressed as a
 * number a static walk can compute and a shared corpus can pin, which a stopwatch
 * cannot.
 */
export const maxRegistrationSchemaEvaluations = 10000;

// NOTE on wall-clock bounds. The Go oracle carries a compile timeout, which it can
// enforce because its runtime preempts. This port carries none, deliberately: a
// CPU-bound spin blocks the event loop, so a timer never runs until the work it was
// meant to interrupt has finished. A control that cannot preempt the work it names is
// not a control. What bounds this port is entirely static and identical in all three
// languages: the size, depth and evaluation caps, and the pattern alphabet, which
// refuses the nested quantifiers that make backtracking catastrophic in the first
// place.

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
	| "too_complex"
	| "ref_cycle"
	| "compile_timeout"
	| "uncompilable"
	| "not_published";

// The wire shape is declared once, next to the refusal builder that consumes it, and
// re-exported here so a caller importing only this module still names one type.
// Re-declaring it would be a third copy of an L0 shape that gen/ts already generates,
// against ADR-020's "L0 is consumed, never rebuilt".
export type { RegistrationFieldError } from "./errordetail";

/** One failure before it is narrowed to the wire's two-field shape. */
export interface SchemaViolation extends RegistrationFieldErrorShape {
	/**
	 * The failed keyword. The shared corpus pins THIS rather than the prose:
	 * `error` wording is validator-defined by contract, while the keyword is the
	 * same word in every JSON Schema library.
	 */
	keyword: string;
}

// Escape letters every engine spells the same way AND reads the same way. This is an
// ALLOWLIST, and that is the point: the set of escapes the three engines disagree
// about is open-ended, so enumerating it means adding an entry every time somebody
// finds another one. See isSafeSchemaPattern for the full argument.
const portableEscapes = new Set("dDwWnrtfv".split(""));

// The regex metacharacters an author escapes to mean the character itself. Every
// engine accepts these — they are the characters that NEED escaping, so no dialect can
// refuse them. Escaping anything else is an "identity escape", and this port is the
// one that refuses those: ajv compiles every pattern with the `u` flag
// (`unicodeRegExp` defaults to true), under which ECMA-262 rejects `\-`, `\a` and the
// rest outright while RE2 and Python accept them.
const portableSyntaxEscapes = new Set("$()*+./?[\\]^{|}".split(""));

// The escapes standing for a SET of characters rather than one. A set cannot be the
// endpoint of a range, and the engines disagree about whether saying so ("[\w-x]") is
// an error or a reinterpretation.
const shorthandClassEscapes = new Set("dDwW".split(""));

/**
 * isJsonBlank reports whether `bytes` carries nothing but JSON whitespace, which is
 * what "this Exchange publishes no data_schema" looks like in bytes.
 *
 * The definition is RFC 8259's and nothing wider: space, tab, carriage return and line
 * feed. It is deliberately NOT each language's idea of whitespace, because that is
 * three different sets — Go's `unicode.IsSpace` takes U+00A0 and U+3000, a Python
 * `bytes.strip()` takes neither, and this runtime's `String.trim` takes both. This gate
 * decides the ENFORCEMENT SWITCH: reading a document as blank means reading it as "no
 * schema published", which turns validation off.
 *
 * It asks the question over the BYTES rather than a decoded string, which matters most
 * here: `TextDecoder` strips a leading byte order mark, so decoding first made "mark
 * followed by a space" look blank and returned `not_published` — silently bypassing the
 * rule below that exists to refuse a mark, and turning enforcement off for a document
 * the other two SDKs call malformed.
 */
function isJsonBlank(bytes: Uint8Array): boolean {
	for (const b of bytes) {
		if (b !== 0x20 && b !== 0x09 && b !== 0x0d && b !== 0x0a) return false;
	}
	return true;
}

/**
 * hexEscapeLen reports the length of a `\xHH` escape at `i`, or 0 if there is not one
 * there. Exactly two hex digits: `\x41` is read the same by all three engines, while
 * the brace form `\x{41}` is an RE2 spelling the other two refuse and a short `\x4` is
 * refused by all three.
 */
function hexEscapeLen(pattern: string, i: number): number {
	if (pattern[i] !== "\\" || pattern[i + 1] !== "x" || i + 3 >= pattern.length) return 0;
	if (!/^[0-9a-fA-F]{2}$/.test(pattern.slice(i + 2, i + 4))) return 0;
	return 4;
}

/**
 * isRangeHyphenAt reports whether the character at `i` is a "-" acting as a range
 * operator inside a bracket expression, rather than the literal hyphen a class may
 * end with ("[a-z-]").
 */
function isRangeHyphenAt(pattern: string, i: number): boolean {
	return pattern[i] === "-" && i + 1 < pattern.length && pattern[i + 1] !== "]";
}

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
 * The largest {n,m} bound admitted. RE2 refuses a repeat count over 1000 outright
 * while the other two engines expand it, so a larger bound is a pattern one SDK
 * compiles and another does not.
 */
const maxPortableRepeat = 1000;

/**
 * Whether the `{...}` starting at s is a counted repeat every engine reads the same
 * way. A `{` that opens no valid quantifier is refused rather than treated as a
 * literal, because whether it IS a literal is precisely what the engines disagree
 * about.
 */
function isPortableQuantifier(s: string): boolean {
	const end = s.indexOf("}");
	if (end < 0) return false;
	const body = s.slice(1, end);
	if (body === "") return false;
	for (const part of body.split(",", 2)) {
		if (part === "") continue; // "{n,}" is well formed
		if (!/^[0-9]+$/.test(part)) return false;
		if (Number(part) > maxPortableRepeat) return false;
	}
	return true;
}

/** The text between the parenthesis at `open` and its match, plus the index past it. */
function groupBody(p: string, open: number): { body: string; after: number } | null {
	let depth = 0;
	let inClass = false;
	for (let i = open; i < p.length; i++) {
		const ch = p[i];
		if (ch === "\\") {
			i++;
			continue;
		}
		if (ch === "[") inClass = true;
		else if (ch === "]") inClass = false;
		else if (ch === "(" && !inClass) depth++;
		else if (ch === ")" && !inClass) {
			depth--;
			if (depth === 0) return { body: p.slice(open + 1, i), after: i + 1 };
		}
	}
	return null;
}

/** Remove escaped characters so an escaped metacharacter is not read as a quantifier. */
function stripEscapes(s: string): string {
	let out = "";
	for (let i = 0; i < s.length; i++) {
		if (s[i] === "\\") {
			i++;
			continue;
		}
		out += s[i];
	}
	return out;
}

/**
 * Whether the pattern quantifies a group whose body can itself repeat or branch — the
 * shape that makes a backtracking engine explore exponentially many ways to match one
 * input.
 *
 * This is the half of the catastrophic-backtracking answer that excluding lookaround
 * and backreferences does not cover: nested quantifiers need neither, and every
 * classic form — `(a+)+`, `(a|a)*`, `([a-z]+)*`, `(?:a*)*` — sits comfortably inside
 * the rest of the alphabet. It has to be STATIC: a regex spin blocks this runtime's
 * event loop, so no timer here could stop one.
 *
 * Deliberately coarse — a quantified group whose body contains any of `* + ? { |`.
 * Deciding whether a particular body is genuinely ambiguous is not decidable in
 * general, and the conservative answer costs an author a rewrite while the permissive
 * one costs a service its availability.
 */
function hasNestedQuantifier(p: string): boolean {
	let inClass = false;
	for (let i = 0; i < p.length; i++) {
		const ch = p[i];
		if (ch === "\\") {
			i++;
			continue;
		}
		if (ch === "[") inClass = true;
		else if (ch === "]") inClass = false;
		else if (ch === "(" && !inClass) {
			const found = groupBody(p, i);
			if (found === null) continue;
			// A non-capturing group's "?:" is syntax, not content.
			const body = found.body.startsWith("?:") ? found.body.slice(2) : found.body;
			const next = p[found.after];
			if (
				(next === "*" || next === "+" || next === "?" || next === "{") &&
				/[*+?{|]/.test(stripEscapes(body))
			) {
				return true;
			}
		}
	}
	return false;
}

/**
 * isSafeSchemaPattern reports whether a `pattern` uses only constructs all three SDK
 * languages express identically, and none that make a backtracking engine explode.
 *
 * Draft 2020-12 patterns are ECMA-262, and the three SDKs run three different engines
 * over them. Two distinct failures follow, and this function answers only the first.
 *
 * Some constructs one engine cannot express at all — RE2 has no lookaround, this
 * runtime has no inline flags — so no care at the call site reconciles them and they
 * are refused here. Others every engine compiles and then reads DIFFERENTLY: `\d` is
 * Unicode-aware in Python and ASCII here and in RE2, and Python's `$` also matches
 * before a trailing newline. Those are not refused — they appear in almost every real
 * pattern — they are corrected in the port that diverges, which is Python.
 *
 * The escape rule is an ALLOWLIST rather than a list of the divergent escapes, because
 * the divergent set is open-ended: two successive reviews found new counterexamples by
 * trying, which is the signature of a rule stated from the wrong side. The portable set
 * is small, closed and checkable, and the corpus carries it as data.
 *
 * The last rule is about availability rather than agreement: a quantified group whose
 * body can repeat or branch is refused, because that is what makes backtracking
 * catastrophic and no timer here could stop one.
 */
export function isSafeSchemaPattern(pattern: string): boolean {
	let inClass = false;
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "\\") {
			if (i + 1 >= pattern.length) {
				// A trailing backslash is not a pattern any engine compiles.
				return false;
			}
			if (hexEscapeLen(pattern, i) > 0) {
				i += 3; // the whole \xHH is consumed, never re-read as syntax
				continue;
			}
			const next = pattern[i + 1]!;
			if (!portableEscapes.has(next) && !portableSyntaxEscapes.has(next)) return false;
			// A range whose endpoint is a shorthand CLASS rather than a character —
			// "[\w-x]". RE2 reads it as a range and compiles; Python and this runtime
			// under the `u` flag both refuse it. Only the adjacency is refused.
			if (inClass && shorthandClassEscapes.has(next) && isRangeHyphenAt(pattern, i + 2)) {
				return false;
			}
			i++; // the escaped character is consumed, never re-read as syntax
			continue;
		}
		// The mirror of the case above: "[a-\w]".
		if (
			ch === "-" &&
			inClass &&
			isRangeHyphenAt(pattern, i) &&
			pattern[i + 1] === "\\" &&
			shorthandClassEscapes.has(pattern[i + 2] ?? "")
		) {
			return false;
		}
		if (ch === "[") {
			if (inClass) {
				// A literal "[" inside a class — EXCEPT when it opens a POSIX name.
				// "[:alpha:]" is a character class to RE2 and the literal characters
				// ":alph" here: both compile, then match different strings.
				if (pattern.startsWith("[:", i)) return false;
				continue;
			}
			inClass = true;
			let rest = pattern.slice(i + 1);
			if (rest.startsWith("^")) rest = rest.slice(1);
			// "]" straight after the opening bracket is a literal in POSIX and an
			// empty class in ECMA; the engines disagree about whether it compiles.
			if (rest.startsWith("]") || rest === "") return false;
			if (pattern.startsWith("[[:", i)) return false;
		} else if (ch === "]") {
			// An unmatched "]" is a literal to RE2 and a syntax error here.
			if (!inClass) return false;
			inClass = false;
		} else if (ch === "(" && !inClass) {
			if (pattern[i + 1] === "?") {
				// Everything spelled "(?..." is refused except the non-capturing
				// group, the only one all three engines write the same way.
				if (pattern[i + 2] !== ":") return false;
				i += 2;
			}
		} else if (ch === "{" && !inClass) {
			if (!isPortableQuantifier(pattern.slice(i))) return false;
		}
	}
	// An unclosed class is a literal "[" to RE2 and a syntax error here.
	if (inClass) return false;
	return !hasNestedQuantifier(pattern);
}

/** The 2020-12 identifier in the two spellings that name the same dialect. */
function isDialect(value: string): boolean {
	return value === registrationSchemaDialect || value === `${registrationSchemaDialect}#`;
}

/**
 * Object keys in CODE POINT order.
 *
 * JavaScript's default sort compares UTF-16 code units, which orders an astral
 * character BEFORE U+FFFF where Go and Python order it after. Because the scan
 * answers with the FIRST fault it finds, that difference changed the compile verdict:
 * a document with two faults under two keys answered `remote_ref` here and
 * `wrong_dialect` in the other two.
 */
function sortedKeys(o: Record<string, unknown>): string[] {
	return Object.keys(o).sort(cmp);
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
		for (const key of sortedKeys(patternProperties)) {
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
	for (const name of sortedKeys(child)) {
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
	for (const key of sortedKeys(node)) {
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

// --- work bound -----------------------------------------------------------------

// Keywords holding a LIST of subschemas, each of which may be evaluated against the
// same instance. They are what makes cost multiply along a reference chain.
const branchKeywords = new Set(["anyOf", "oneOf", "allOf", "prefixItems"]);

// Keywords holding exactly one subschema.
const singleSubschemaKeywords = new Set([
	"not", "if", "then", "else", "items", "contains", "propertyNames",
	"additionalProperties", "unevaluatedProperties", "unevaluatedItems", "contentSchema",
]);

// Saturation point: past the cap the exact value carries no information.
const costCeiling = maxRegistrationSchemaEvaluations + 1;

function addCost(a: number, b: number): number {
	if (a >= costCeiling || b >= costCeiling || a + b >= costCeiling) return costCeiling;
	return a + b;
}

/** Index every `$anchor` so a "#name" reference resolves without a second walk. */
function collectAnchors(node: unknown, out: Map<string, unknown>): void {
	if (Array.isArray(node)) {
		for (const item of node) collectAnchors(item, out);
		return;
	}
	if (!isPlainObject(node)) return;
	const anchor = node["$anchor"];
	if (typeof anchor === "string" && !out.has(anchor)) out.set(anchor, node);
	for (const key of sortedKeys(node)) collectAnchors(node[key], out);
}

/**
 * Counts the worst-case number of subschema evaluations, and — because counting means
 * following every reference to its target — also decides whether a reference cycle is
 * present and whether a same-document reference resolves at all.
 */
class CostWalker {
	readonly #root: unknown;
	readonly #anchors = new Map<string, unknown>();
	readonly #memo = new Map<string, number>();
	readonly #onStack = new Set<string>();
	verdict: SchemaVerdict = "accepted";

	constructor(root: unknown) {
		this.#root = root;
		collectAnchors(root, this.#anchors);
	}

	fail(v: SchemaVerdict): number {
		if (this.verdict === "accepted") this.verdict = v;
		return costCeiling;
	}

	/**
	 * The worst-case evaluations `node` can require against one instance: a boolean
	 * schema is one, an object schema is itself plus everything it can delegate to.
	 *
	 * `$defs` and `definitions` are deliberately NOT counted — they are reachable only
	 * through a reference, and counting them here as well would charge a shared
	 * definition once per declaration plus once per use.
	 */
	cost(node: unknown): number {
		if (this.verdict !== "accepted") return costCeiling;
		if (!isPlainObject(node)) return 1;
		let total = 1;
		for (const key of sortedKeys(node)) {
			const value = node[key];
			if (nonSchemaKeywords.has(key) || key === "$defs" || key === "definitions") continue;
			if ((referenceKeywords as readonly string[]).includes(key)) {
				if (typeof value === "string") total = addCost(total, this.refCost(value));
			} else if (branchKeywords.has(key)) {
				if (Array.isArray(value)) {
					for (const item of value) total = addCost(total, this.cost(item));
				} else {
					total = addCost(total, this.cost(value));
				}
			} else if (singleSubschemaKeywords.has(key)) {
				total = addCost(total, this.cost(value));
			} else if (schemaMapKeywords.has(key)) {
				if (isPlainObject(value)) {
					for (const name of sortedKeys(value)) total = addCost(total, this.cost(value[name]));
				} else {
					total = addCost(total, this.cost(value));
				}
			}
			if (total >= costCeiling) return costCeiling;
		}
		return total;
	}

	/**
	 * Count a reference's target once and remember it. A location already being
	 * counted is a cycle: its cost is not finite, and it is what makes this port abort
	 * rather than answer.
	 */
	refCost(ref: string): number {
		const memo = this.#memo.get(ref);
		if (memo !== undefined) return memo;
		if (this.#onStack.has(ref)) return this.fail("ref_cycle");
		const target = this.resolve(ref);
		if (!target.ok) return this.fail("uncompilable");
		this.#onStack.add(ref);
		const c = this.cost(target.node);
		this.#onStack.delete(ref);
		this.#memo.set(ref, c);
		return c;
	}

	/**
	 * Follow a same-document reference. The scan has already refused anything not
	 * beginning with "#", so only three forms reach here: the whole document, an RFC
	 * 6901 pointer into it, and a `$anchor` name.
	 */
	resolve(ref: string): { node: unknown; ok: boolean } {
		const frag = ref.startsWith("#") ? ref.slice(1) : ref;
		if (frag === "") return { node: this.#root, ok: true };
		if (!frag.startsWith("/")) {
			const target = this.#anchors.get(frag);
			return { node: target, ok: this.#anchors.has(frag) };
		}
		let node: unknown = this.#root;
		for (const raw of frag.slice(1).split("/")) {
			const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
			if (isPlainObject(node)) {
				if (!(token in node)) return { node: undefined, ok: false };
				node = node[token];
			} else if (Array.isArray(node)) {
				if (!/^[0-9]+$/.test(token) || Number(token) >= node.length) {
					return { node: undefined, ok: false };
				}
				node = node[Number(token)];
			} else {
				return { node: undefined, ok: false };
			}
		}
		return { node, ok: true };
	}
}

/**
 * Bound how much work validating a payload can cost. The size and depth caps bound
 * the DOCUMENT and say nothing about this.
 */
function checkEvaluationCost(doc: unknown): SchemaVerdict {
	const walker = new CostWalker(doc);
	const cost = walker.cost(doc);
	if (walker.verdict !== "accepted") return walker.verdict;
	return cost > maxRegistrationSchemaEvaluations ? "too_complex" : "accepted";
}

/**
 * clampPointer keeps a pointer inside the wire's length bound WITHOUT truncating
 * it. A pointer cut mid-token addresses a different member — or none — so an
 * over-long one degrades to the longest ANCESTOR that fits.
 */
function clampPointer(pointer: string): string {
	// CODE POINTS, not UTF-16 code units. protovalidate's string.max_len counts
	// characters, and Go and Python both count them — so measuring `.length` here made
	// this port clamp a pointer the other two left whole, and a pointer of 201 astral
	// characters degraded all the way to the empty string, naming the root object where
	// the others named the failing member.
	const chars = [...pointer];
	if (chars.length <= maxRegistrationFieldErrorPathLen) return pointer;
	for (let i = chars.length - 1; i > 0; i--) {
		if (chars[i] === "/" && i <= maxRegistrationFieldErrorPathLen) return chars.slice(0, i).join("");
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
	// CODE POINTS, for the same reason as clampPointer — and here a UTF-16 slice could
	// also cut through a surrogate pair, emitting a lone surrogate where Go emits valid
	// UTF-8. The wire counts characters; so does this.
	const chars = [...text];
	if (chars.length <= maxRegistrationFieldErrorTextLen) return text;
	return chars.slice(0, maxRegistrationFieldErrorTextLen).join("");
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
	validate(data: unknown): RegistrationFieldErrorShape[] {
		return this.violations(data).map(({ path, error }) => ({ path, error: clampText(error) }));
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

		// Drop any error that has descendants AT THE SAME INSTANCE: a composite
		// keyword (oneOf, anyOf, if) reports itself AND the branch failures underneath
		// it, while Go's oracle reports only the leaves.
		//
		// Both halves of the key are load-bearing. Keying on schemaPath alone — the
		// first version of this — dropped a composite failure at one member because an
		// UNRELATED error at a DIFFERENT member happened to sit under the same shared
		// subschema, so a genuinely failing member vanished from the refusal and the
		// operator was never told to fix it. A composite that failed with no branch
		// errors (oneOf matching two branches) is still a leaf and survives.
		// A composite is a leaf only when nothing beneath it failed. Nesting is read off
		// the schema path, and a $ref BREAKS that nesting: the branch's own failure is
		// reported under "#/$defs/..." rather than under the anyOf, so an anyOf whose
		// branches are ALL $refs looked childless and survived beside the real error.
		// "one of several defined formats" is an ordinary registration shape, so the
		// hop is recognised rather than assumed away.
		const leaves = errors.filter((e) => !errors.some((o) => o !== e && isBeneath(o, e)));

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
				if (cmp(text, flat[at]!.error) < 0) flat[at]!.error = text;
				continue;
			}
			seen.set(key, flat.length);
			flat.push({ path, keyword, error: text });
		}
		flat.sort((a, b) => (a.path === b.path ? cmp(a.keyword, b.keyword) : cmp(a.path, b.path)));
		return flat.slice(0, maxRegistrationFieldErrors);
	}
}

// The keywords that fail as a WHOLE because every branch under them failed. Their own
// error adds nothing an operator can act on once the branch failures are reported, so
// it survives only when nothing beneath it did.
const branchComposites = new Set(["anyOf", "oneOf"]);

/**
 * isBeneath reports whether error `o` sits under error `e`, so that `e` is a composite
 * whose real cause is already reported and not a leaf.
 *
 * The schema-path test is the ordinary one. The composite test exists because a `$ref`
 * relocates the branch's failure out from under the composite — it is reported at the
 * definition it points to — leaving a nesting test nothing to match on.
 */
function isBeneath(o: ErrorObject, e: ErrorObject): boolean {
	if (o.instancePath !== e.instancePath) return false;
	if (o.schemaPath.startsWith(`${e.schemaPath}/`)) return true;
	return branchComposites.has(e.keyword) && !branchComposites.has(o.keyword);
}

/**
 * CODE POINT comparison, matching Go's byte order over UTF-8 and Python's ordering
 * over str.
 *
 * `a < b` compares UTF-16 code units, which is NOT the same order: a surrogate pair
 * (U+10000 and above) begins with 0xD800-0xDBFF and therefore sorts before U+E000-
 * U+FFFF, where the other two languages sort it after. That difference is not
 * cosmetic here — the scan answers with the first fault it finds, so key order
 * decides the verdict.
 */
function cmp(a: string, b: string): number {
	const ac = [...a];
	const bc = [...b];
	const n = Math.min(ac.length, bc.length);
	for (let i = 0; i < n; i++) {
		const x = ac[i]!.codePointAt(0)!;
		const y = bc[i]!.codePointAt(0)!;
		if (x !== y) return x < y ? -1 : 1;
	}
	return ac.length - bc.length;
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
	// Nothing to compile is its own answer, not a malformed document: an Exchange that
	// publishes no data_schema is the contract's ordinary case.
	if (isJsonBlank(bytes)) {
		return { schema: null, verdict: "not_published" };
	}
	// Size first, on the bytes as served and before any parse: an oversized document
	// must not be decoded to find out that it was oversized.
	if (bytes.length > maxRegistrationSchemaBytes) return { schema: null, verdict: "too_large" };
	// A byte order mark is refused. RFC 8259 forbids adding one and lets a parser ignore
	// one, so both policies conform and the choice had to be made once for all three
	// SDKs: TextDecoder strips it by default and Python's json.loads strips it from
	// bytes, while Go's parser does not — so the same document compiled in two SDKs and
	// was malformed in the third. Refusing is the side that keeps the size cap above
	// honest, since a stripped mark would make it count three bytes the schema does not
	// contain, and a mark is only valid at the start of a JSON text, never inside the
	// ramp.json member this schema lives in.
	if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
		return { schema: null, verdict: "malformed" };
	}
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
	// A JSON OBJECT and nothing else. 2020-12 admits a bare boolean as a schema, but
	// data_schema is a google.protobuf.Struct, which carries an object — so a boolean
	// cannot reach this face over the wire at all, and admitting one would pin
	// behaviour for a document the contract has no way to transport.
	if (!isPlainObject(doc)) {
		return { schema: null, verdict: "malformed" };
	}
	const verdict = scan(doc);
	if (verdict !== "accepted") return { schema: null, verdict };
	// The work bound, still before the library is involved. This is also where a
	// reference cycle and a same-document reference that resolves to nothing are
	// found, because counting the cost means following every reference to its target.
	const costVerdict = checkEvaluationCost(doc);
	if (costVerdict !== "accepted") return { schema: null, verdict: costVerdict };

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
