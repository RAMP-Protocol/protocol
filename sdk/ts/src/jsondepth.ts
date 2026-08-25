// How deep a JSON document nests, counted without parsing it.
//
// Shared, because several readers need the same answer for the same reason and a second
// transcription of a security rule is how the three languages drifted apart elsewhere.
// TS mirror of sdk/python/ramp_sdk/_jsondepth.py.
//
// Every JSON parser across the SDKs descends into a document, and what it does when the
// document is deeper than it can descend is a property of the runtime rather than a
// verdict: Python's raises RecursionError, which is neither what a malformed document
// raises nor a failure any of these packages says it raises. A depth check placed AFTER the
// parse is reached only by documents harmless enough to parse — precisely the ones that did
// not need it.
//
// So the scan is lexical and runs first. Counting needs no recursion.
//
// Three callers today: the registration-schema compiler, reading a schema out of a third
// party's manifest, and both of the client's readers of a peer's own bytes — the response
// reader and the delivery edge's refusal reader.

/**
 * How deep a document this SDK did not write may nest.
 *
 * The same 32 the error-detail reader uses and the protocol sets for a stranger's JSON in
 * AccountRegistration.data_schema, so one number covers how deep any such document may be.
 * The deepest instance in the whole conformance corpus is 5.
 *
 * It lives beside the scan rather than at either call site, because a bound stated twice is
 * a bound two readers can disagree about.
 */
export const MAX_BODY_DEPTH = 32;

/**
 * rawNestingDepth returns the deepest JSON container nesting in `source`, counted
 * lexically — no parse, no recursion, one pass.
 *
 * It is string-aware, so a brace inside a string literal is text rather than a container,
 * and escape-aware so a literal quote does not end the string early. It does NOT check that
 * the brackets balance: an unbalanced document is the parser's to reject, and this only has
 * to produce an upper bound on how deep a parser would have to descend.
 *
 * It takes BYTES or TEXT and answers the same for both. Every delimiter it looks for is
 * ASCII, and neither a UTF-8 continuation byte nor a UTF-16 code unit above the ASCII range
 * can collide with one — so a caller that already holds one form never has to pay a
 * conversion to the other. The registration-schema compiler measures the bytes as served;
 * the client's readers already hold decoded text.
 */
export function rawNestingDepth(source: Uint8Array | string): number {
	const text = typeof source === "string";
	const length = source.length;
	let depth = 0;
	let deepest = 0;
	let inString = false;
	let escaped = false;
	for (let i = 0; i < length; i++) {
		const code = text
			? (source as string).charCodeAt(i)
			: ((source as Uint8Array)[i] as number);
		if (inString) {
			if (escaped) escaped = false;
			else if (code === 0x5c) escaped = true; // backslash
			else if (code === 0x22) inString = false; // quote
			continue;
		}
		if (code === 0x22) inString = true;
		else if (code === 0x7b || code === 0x5b) {
			// { [
			depth++;
			if (depth > deepest) deepest = depth;
		} else if (code === 0x7d || code === 0x5d) depth--; // } ]
	}
	return deepest;
}
