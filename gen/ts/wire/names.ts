// Recovering a proto field name from protojson's lowerCamelCase spelling of it.
// Hand-written; not regenerated. The Python twin is gen/python/wire/names.py, and the two
// are held to one answer by a shared vector set.
//
// This lives beside the generated schemas rather than in the SDK because the schema seam
// itself needs it: base.ts refuses an answer spelled in the json_name alias, and a rule
// the seam depends on cannot live in a tier above the seam. The SDK re-exports it, so
// there is one implementation per language rather than one per caller.
//
// The RAMP wire is snake_case proto-JSON everywhere — proto field names, the corpus, the
// generated clients — and the camelCase alias is out of contract. Two places still have to
// reason about it:
//
//   - Connect's error-detail `debug` projection IS lowerCamelCase and cannot be made
//     otherwise. connect-go renders it with its own protojson codec at default options,
//     inside a method on an unexported type, so the snake_case codec a RAMP deployment
//     registers reaches the response body and not the error beside it. That projection is
//     normalized before parsing.
//   - A response body from a server that registered no snake_case codec is lowerCamelCase
//     throughout. That one is REFUSED rather than normalized: it is out of contract, and
//     naming it is what turns a message with every multiword field silently missing into
//     an error.
//
// The boundary test is ASCII `A-Z` and nothing else, deliberately. protojson builds
// json_name by uppercasing the character after each underscore, and a proto field name is
// [a-z_][a-z0-9_]*, so an ASCII uppercase letter is the only boundary protojson can
// produce. A broader test — "not equal to its own lowercase", or a Unicode uppercase
// predicate — answers differently for characters protojson never emits (titlecase `ǅ` is
// the plain example), which is how three transcriptions of one rule drifted apart.
//
// The rewrite is textual. It is sound only while protojson's spelling inverts back to every
// field's name — it would not for a field like `field_2`, whose json_name is `field2` —
// which the conformance suite asserts for the whole contract.

/** Recover a proto field name from protojson's lowerCamelCase spelling of it. */
export function snakeFromJsonName(name: string): string {
	let out = "";
	for (const ch of name) {
		out += ch >= "A" && ch <= "Z" ? `_${ch.toLowerCase()}` : ch;
	}
	return out;
}
