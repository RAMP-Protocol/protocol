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
import canonicalize from "canonicalize";

import type { RegistrationFieldError as RegistrationFieldErrorShape } from "./errordetail";
import { rawNestingDepth } from "./jsondepth";

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

/**
 * maxRegistrationSchemaRefHops bounds how long a `$ref` chain may be, measured as the
 * longest path of reference hops rather than as the number of references a document
 * contains.
 *
 * A SEPARATE axis from maxRegistrationSchemaDepth, and the shape that forced it shows
 * why: a chain of five hundred definitions, each referring to the next, is three JSON
 * containers deep however long it is, so the depth cap never sees it. The evaluation cap
 * does not see it either — a flat chain costs one evaluation per link.
 *
 * What it bounds is the RECURSION a validator does while resolving that chain. The cost
 * walk here does not care, but the libraries the three SDKs hand an accepted schema to
 * do, and one of them exhausted its interpreter stack at 495 links — raising out of a
 * face documented as returning a verdict, on a document every SDK had just called valid.
 */
export const maxRegistrationSchemaRefHops = 100;

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
export const schemaVerdicts = [
	"no_verdict",
	"accepted",
	"malformed",
	"wrong_dialect",
	"remote_ref",
	"too_large",
	"too_deep",
	"unsafe_pattern",
	"too_complex",
	"ref_cycle",
	"ref_chain_too_long",
	"compile_timeout",
	"uncompilable",
	"not_published",
] as const;

export type SchemaVerdict = (typeof schemaVerdicts)[number];

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
 * correctedPatternSource rewrites one author-written regex into a source that means the
 * SAME thing here as it does in RE2 and in Python's `re`.
 *
 * One correction, and it is this port's turn to make one: `.` excludes only `\n` in RE2
 * and in Python, and excludes all four line terminators in ECMA-262, so `^.$` against a
 * carriage return conformed in the other two SDKs and violated here. Refusing `.` would
 * gut a construct that appears in most real patterns, so the odd one out is corrected
 * instead — exactly what the Python port already does for `$`, which matches before a
 * trailing newline there and nowhere else.
 *
 * The scan is bracket- and escape-aware: a `.` inside a character class is already a
 * literal dot, and an escaped `\.` is a literal everywhere.
 */
function correctedPatternSource(pattern: string): string {
	const out: string[] = [];
	let inClass = false;
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i]!;
		if (ch === "\\") {
			out.push(pattern.slice(i, i + 2));
			i++;
			continue;
		}
		if (ch === "[") inClass = true;
		else if (ch === "]") inClass = false;
		else if (ch === "." && !inClass) {
			out.push("[^\n]");
			continue;
		}
		out.push(ch);
	}
	return out.join("");
}

/**
 * authoredPatternSource recovers the author's own text from a corrected source, for a
 * refusal an operator reads.
 *
 * The rewrite is reversed rather than tracked alongside, which is exact in the direction
 * that matters: an author who wrote `.` sees `.` back. It is not a round trip in the
 * other direction — an author who wrote `[^\n]` also sees `.` — but the two are the same
 * set of characters once corrected, and `.` is overwhelmingly the form people write. The
 * refusal prose is validator-defined by contract and deliberately not pinned by the
 * shared corpus, so an equivalent spelling is within what that contract allows.
 */
function authoredPatternSource(pattern: string): string {
	return pattern.split("[^\n]").join(".");
}

/**
 * correctRegexes returns a copy of the document with every regex-valued position
 * corrected.
 *
 * The walk mirrors the safety scan exactly, and for the same reasons: a `const` holds
 * DATA whose contents are never read as keywords, and `properties`/`$defs` map NAMES to
 * subschemas, so a property literally called "pattern" is a property name and not a
 * regex. Correcting the SOURCE rather than the matcher reaches every place ajv compiles
 * a regex — the `pattern` keyword, the `patternProperties` keys, and the matched-key
 * scans behind `additionalProperties` and `unevaluatedProperties` — including any a
 * later release adds.
 */
function correctRegexes(node: unknown): unknown {
	if (Array.isArray(node)) return node.map(correctRegexes);
	if (node === null || typeof node !== "object") return node;
	const out: Record<string, unknown> = {};
	for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
		if (nonSchemaKeywords.has(key)) {
			out[key] = child;
		} else if (key === "pattern" && typeof child === "string") {
			out[key] = correctedPatternSource(child);
		} else if (key === "patternProperties" && child !== null && typeof child === "object") {
			// The regexes are the KEYS here, which is why correcting the matcher for the
			// `pattern` keyword alone would never reach them.
			out[key] = Object.fromEntries(
				Object.entries(child as Record<string, unknown>).map(([k, v]) => [
					correctedPatternSource(k),
					correctRegexes(v),
				]),
			);
		} else if (schemaMapKeywords.has(key) && child !== null && typeof child === "object") {
			out[key] = Object.fromEntries(
				Object.entries(child as Record<string, unknown>).map(([n, sub]) => [n, correctRegexes(sub)]),
			);
		} else {
			out[key] = correctRegexes(child);
		}
	}
	return out;
}

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
/**
 * The largest {n,m} bound admitted. RE2 refuses a repeat count over 1000 outright while
 * the other two engines expand it, so a larger bound is a pattern one SDK compiles and
 * another does not. Exported so the parity suite can hold it against the corpus header:
 * it and the escape alphabet are the two values that decide which patterns this port
 * admits, and they were the two the suite did not check.
 */
export const maxPortableRepeat = 1000;

/**
 * The length of the counted repeat starting at `s`, including its closing brace, or 0
 * if `s` opens none that every engine reads the same way. A `{` that opens no valid
 * quantifier is refused rather than treated as a literal, because whether it IS a
 * literal is precisely what the engines disagree about.
 *
 * It returns a LENGTH rather than a boolean so the caller can consume the whole
 * `{n,m}`. That is what lets an unmatched `}` be refused: once every well-formed
 * quantifier is stepped over, a `}` the scan still reaches closes nothing.
 *
 * The first bound must be present. `a{,5}` is the shape that forced this: RE2 reads it
 * as the five literal characters and Python reads it as a repeat of zero to five, so
 * both compile the pattern and then disagree about which payloads match it, with
 * nothing logged. The empty part is still allowed AFTER the comma, because `{n,}` is
 * the ordinary open-ended repeat and every engine agrees on it.
 *
 * The body is split on EVERY comma, not with a limit. `String.split`'s second argument
 * caps the result array and DISCARDS the remainder, where Go's SplitN and Python's
 * maxsplit keep it in the last element — so `"1,2,3".split(",", 2)` was `["1","2"]`
 * here and `["1", "2,3"]` there, and this port alone admitted `a{1,2,3}`.
 */
function quantifierLen(s: string): number {
	const end = s.indexOf("}");
	if (end < 0) return 0;
	const body = s.slice(1, end);
	if (body === "") return 0;
	const parts = body.split(",");
	if (parts.length > 2) return 0;
	for (const [i, part] of parts.entries()) {
		if (part === "") {
			if (i === 0) return 0; // "{,5}" — two engines, two readings
			continue; // "{n,}" is well formed
		}
		if (!/^[0-9]+$/.test(part)) return 0;
		if (Number(part) > maxPortableRepeat) return 0;
	}
	return end + 1;
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
			const consumed = quantifierLen(pattern.slice(i));
			if (consumed === 0) return false;
			i += consumed - 1; // consume through the closing brace
		} else if (ch === "}" && !inClass) {
			// Every well-formed quantifier was stepped over above, so a "}" reached here
			// closes nothing. RE2 and Python read it as a literal and ECMA-262 under the
			// `u` flag refuses it outright — the same split the unmatched "]" rule exists
			// for, so it gets the same answer. A literal brace is written "\}", which the
			// alphabet admits.
			return false;
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
/**
 * What a resolved reference location is worth, remembered once.
 *
 * Both fields are properties of the LOCATION rather than of the walk that reached it.
 * That is what makes them safe to memoise, and it is what the chain bound needs: cost is
 * the same by whichever route a target is reached, and chain length is not, so a memo
 * holding cost alone answers a later, longer route with a number that says nothing about
 * how much chain remains beneath it.
 */
interface RefFacts {
	/** Worst-case subschema evaluations at the target. */
	readonly cost: number;
	/** Longest chain of further $ref hops starting at the target. */
	readonly below: number;
}

class CostWalker {
	readonly #root: unknown;
	readonly #anchors = new Map<string, unknown>();
	readonly #memo = new Map<string, RefFacts>();
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
	 * The worst-case evaluations `node` can require against one instance, and the longest
	 * chain of `$ref` hops starting anywhere inside it.
	 *
	 * A boolean schema is one evaluation; an object schema is itself plus everything it
	 * can delegate to. The second number rides along because the reference bound is over
	 * the longest PATH, so something has to compute it, and this walk already follows
	 * every reference to its target — counting the two together is what keeps them
	 * consistent.
	 *
	 * `$defs` and `definitions` are deliberately NOT counted — they are reachable only
	 * through a reference, and counting them here as well would charge a shared
	 * definition once per declaration plus once per use.
	 */
	cost(node: unknown, hops: number): RefFacts {
		if (this.verdict !== "accepted") return { cost: costCeiling, below: 0 };
		if (!isPlainObject(node)) return { cost: 1, below: 0 };
		let total = 1;
		let below = 0;
		for (const key of sortedKeys(node)) {
			const value = node[key];
			if (nonSchemaKeywords.has(key) || key === "$defs" || key === "definitions") continue;
			if ((referenceKeywords as readonly string[]).includes(key)) {
				if (typeof value === "string") {
					const r = this.refCost(value, hops + 1);
					total = addCost(total, r.cost);
					// The reference is itself a hop, so the chain through it is one longer
					// than whatever chain remains below its target.
					below = Math.max(below, 1 + r.below);
				}
			} else if (branchKeywords.has(key)) {
				if (Array.isArray(value)) {
					for (const item of value) {
						const r = this.cost(item, hops);
						total = addCost(total, r.cost);
						below = Math.max(below, r.below);
					}
				} else {
					const r = this.cost(value, hops);
					total = addCost(total, r.cost);
					below = Math.max(below, r.below);
				}
			} else if (singleSubschemaKeywords.has(key)) {
				const r = this.cost(value, hops);
				total = addCost(total, r.cost);
				below = Math.max(below, r.below);
			} else if (schemaMapKeywords.has(key)) {
				if (isPlainObject(value)) {
					for (const name of sortedKeys(value)) {
						const r = this.cost(value[name], hops);
						total = addCost(total, r.cost);
						below = Math.max(below, r.below);
					}
				} else {
					const r = this.cost(value, hops);
					total = addCost(total, r.cost);
					below = Math.max(below, r.below);
				}
			}
			if (total >= costCeiling) return { cost: costCeiling, below };
		}
		return { cost: total, below };
	}

	/**
	 * Count a reference's target once and remember it, and enforce the chain bound at
	 * this reference. A location already being counted is a cycle: its cost is not
	 * finite, and it is what makes this port abort rather than answer.
	 *
	 * The chain through this reference is `hops + below`: what it took to arrive, plus
	 * what remains beneath the target. Both halves are needed. A count that watches only
	 * the first half measures the walk instead of the document — it passes a chain split
	 * into short segments that are each entered from the root, and it answers the same
	 * graph differently depending on the order that document happens to list its
	 * references in.
	 */
	refCost(ref: string, hops: number): RefFacts {
		const { facts, judge } = this.#refFacts(ref, hops);
		if (!judge) return facts;
		// ONE check, at the reference site, so it is applied identically whether the
		// target was just walked or was already known. Splitting it — once where a target
		// is counted and again where the memo answers — states the same condition twice,
		// and a condition stated twice is a condition neither statement is responsible
		// for.
		if (hops + facts.below > maxRegistrationSchemaRefHops) {
			return { cost: this.fail("ref_chain_too_long"), below: facts.below };
		}
		return facts;
	}

	/**
	 * A reference target's facts, from the memo when the target has been counted before
	 * and by walking it otherwise.
	 *
	 * `judge` is false when the walk has already reached a verdict of its own — a cycle,
	 * an unresolvable reference, a chain past the recursion guard — and the caller should
	 * propagate that rather than measure a chain that no longer means anything.
	 */
	#refFacts(ref: string, hops: number): { facts: RefFacts; judge: boolean } {
		const memo = this.#memo.get(ref);
		if (memo !== undefined) return { facts: memo, judge: true };
		if (this.#onStack.has(ref)) {
			return { facts: { cost: this.fail("ref_cycle"), below: 0 }, judge: false };
		}
		// After the cycle check, so a chain that closes on itself still reports the more
		// specific diagnosis. `hops` is tracked explicitly rather than read off the size
		// of #onStack: the two agree here, where the walk recurses and the set mirrors the
		// path, and they do NOT agree in a port whose walk is iterative and whose
		// equivalent set is a search frontier. The bound is a number in the contract, so
		// the three SDKs compute the same quantity by construction, not by coincidence.
		//
		// This is NOT the bound — the bound is the hops+below check above, which is
		// exact. It is a recursion guard: cost and refCost call each other, so without it
		// a chain as long as the size cap admits would be walked as deep as it is long
		// before anything refused it.
		if (hops > maxRegistrationSchemaRefHops) {
			return { facts: { cost: this.fail("ref_chain_too_long"), below: 0 }, judge: false };
		}
		const target = this.resolve(ref);
		if (!target.ok) {
			return { facts: { cost: this.fail("uncompilable"), below: 0 }, judge: false };
		}
		this.#onStack.add(ref);
		const facts = this.cost(target.node, hops);
		this.#onStack.delete(ref);
		// A walk cut short by the cost ceiling memoises a partial `below`, which cannot
		// produce a wrong accept: a saturated cost is maxRegistrationSchemaEvaluations+1,
		// so the document is refused as too complex whatever its chain length.
		this.#memo.set(ref, facts);
		return { facts, judge: true };
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
	const { cost } = walker.cost(doc, 0);
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
	if (keyword === "pattern") {
		// The AUTHOR's pattern, not this port's corrected copy: an operator reading a
		// refusal should see the regex their Exchange published.
		return { keyword, text: `pattern: ${authoredPatternSource(String(params["pattern"]))}` };
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
		// Every regex in the document, rewritten to mean here what it means in the other
		// two SDKs. This happens after every rule above, so what is scanned and bounded
		// as a schema is always the published document; only the copy handed to the
		// matcher carries the correction.
		const corrected = correctRegexes(doc);
		return {
			schema: new RegistrationSchema(ajv.compile(corrected as object)),
			verdict: "accepted",
		};
	} catch {
		return { schema: null, verdict: "uncompilable" };
	}
}

/**
 * maxRegistrationDataBytes bounds a submitted registration_data payload, measured as
 * its RFC 8785 canonical JSON encoding.
 *
 * The UNIT has to be named, and that is the whole point of this constant. Every other
 * cap in this module is over bytes a party actually served; registration_data is not
 * served as bytes at all — it arrives as a decoded google.protobuf.Struct — so "16KB"
 * means nothing until an encoding is chosen, and two implementations choosing privately
 * is the disagreement this module exists to remove. JCS is the choice because all three
 * SDKs already compute it for the signing primitive, and because it pins number
 * formatting: a payload carrying 1e300 is seven bytes to one renderer and three hundred
 * to another.
 *
 * It bounds WORK, not storage. The schema's own caps bound the schema; nothing bounded
 * the payload the schema is applied to, and validation cost is roughly the schema's cost
 * multiplied by the elements in the payload — a subschema under `items` is counted once
 * by maxRegistrationSchemaEvaluations and evaluated once per element.
 */
export const maxRegistrationDataBytes = 16384;

/**
 * maxRegistrationDataMembers bounds the number of members at the TOP LEVEL of a
 * payload. Top level rather than recursive, deliberately: nested bulk is already bounded
 * by the byte cap, and a recursive count would refuse a small document that merely
 * nests, which a business entity legitimately does (an address is an object).
 */
export const maxRegistrationDataMembers = 64;

/**
 * maxRegistrationDataDepth bounds how deeply a submitted registration_data payload may
 * nest, counting JSON containers so a bare `{}` is depth 1. Same number and same counting
 * rule as maxRegistrationSchemaDepth, because it is the same question asked of the other
 * document.
 *
 * It exists because without it the ANSWER depended on the reader's runtime rather than on
 * the payload. Canonicalising walks the payload recursively, and where that walk runs out
 * of stack differs by language and even by interpreter version — one port refused a
 * payload past about five hundred containers on one Python and accepted nine hundred on
 * the next, while this one and Go accepted every depth tried. A static bound checked
 * first turns that into one verdict every implementation reaches.
 */
export const maxRegistrationDataDepth = 32;

/**
 * RegistrationDataVerdict is the outcome of checking a submitted registration_data
 * payload. The tokens are the Go oracle's vocabulary verbatim.
 *
 * "no_verdict" is Go's zero value and is never returned here; it is in the vocabulary
 * because the corpus carries the whole vocabulary.
 */
export const registrationDataVerdicts = [
	"no_verdict",
	"accepted",
	"too_large",
	"too_many_members",
	"too_deep",
	"uncanonicalizable",
] as const;

export type RegistrationDataVerdict = (typeof registrationDataVerdicts)[number];

/**
 * registrationDataDepth returns how many JSON containers the payload nests, counting the
 * payload object itself as the first. A scalar is a value, not a container, so
 * `{"a":"x"}` nests one — the same rule the schema side applies, where the count is of a
 * document's opening braces and brackets and nothing else.
 *
 * Only containers are pushed, so every frame on the stack is one and the count needs no
 * test at the far end. The walk is ITERATIVE: it runs before the depth bound is known to
 * hold, so it is the one walk that must survive any input.
 */
function registrationDataDepth(data: Record<string, unknown>): number {
	const isContainer = (v: unknown): boolean =>
		Array.isArray(v) || (v !== null && typeof v === "object");
	let deepest = 0;
	const stack: Array<{ node: unknown; depth: number }> = [{ node: data, depth: 1 }];
	while (stack.length > 0) {
		const { node, depth } = stack.pop()!;
		if (depth > deepest) deepest = depth;
		// No need to walk past the bound: the answer is already decided, and a payload
		// deep enough to matter is also deep enough to be expensive to finish walking.
		if (depth > maxRegistrationDataDepth) return depth;
		let children: readonly unknown[] = [];
		if (Array.isArray(node)) children = node;
		else if (node !== null && typeof node === "object") children = Object.values(node);
		for (const child of children) {
			if (isContainer(child)) stack.push({ node: child, depth: depth + 1 });
		}
	}
	return deepest;
}

/**
 * checkRegistrationData bounds a submitted registration_data payload.
 *
 * `data` is the decoded object. A null/undefined or empty payload is accepted: sending
 * no business data is a matter for the published schema's `required` list, not for a
 * size bound.
 *
 * This runs BEFORE RegistrationSchema.validate, for the same reason the schema's own
 * size cap runs before the schema is parsed: the bound exists to stop work, so it has to
 * precede the work. An Exchange refuses an over-bound payload outright — a malformed
 * request rather than a schema failure, so NOT
 * REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA, which names non-conformance to
 * a published schema and applies only when one is published.
 */
export function checkRegistrationData(
	data: Record<string, unknown> | null | undefined,
): RegistrationDataVerdict {
	const obj = data ?? {};
	// Members first: it is a length check, and it bounds the document the canonical
	// encoding below then has to walk.
	if (Object.keys(obj).length > maxRegistrationDataMembers) return "too_many_members";
	// Depth SECOND, and before anything walks the payload recursively. The check is
	// iterative for that reason: a recursive one would hit the very limit it exists to
	// keep the caller away from, throwing while discovering that the payload is too deep.
	if (registrationDataDepth(obj) > maxRegistrationDataDepth) return "too_deep";
	let jcs: string | undefined;
	try {
		jcs = canonicalize(obj);
	} catch {
		// The reachable case is a non-finite number, which JSON cannot represent and
		// this canonicalizer throws on. It is a verdict rather than an exception because
		// this face, like the rest of the registration surface, does not throw.
		return "uncanonicalizable";
	}
	if (jcs === undefined) return "uncanonicalizable";
	// BYTES, not UTF-16 code units: the cap is over the canonical encoding, and a
	// non-ASCII member name costs more than one unit per character.
	if (new TextEncoder().encode(jcs).length > maxRegistrationDataBytes) return "too_large";
	return "accepted";
}
