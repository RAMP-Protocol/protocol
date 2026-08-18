// Cross-language parity: the registration-schema rules answer as the Go oracle does.
//
// The corpus at sdk/go/helpers/testdata/registration-schema-vectors.json is emitted
// from the real Go faces. This suite replays it unchanged. A vector change is a
// protocol-level change and goes through the vector-owning review, never in as a
// port fix — if a case here fails, the port is wrong until proven otherwise.
//
// Three dimensions: `compile` (which schemas may be published at all), `validate`
// (what a refusal SAYS — pointer, keyword, order and the 64-item cap) and `pattern`
// (the regex alphabet on its own, so a refusal that could have come from several
// rules is still attributable to one).
//
// The `error` PROSE is deliberately not pinned in any of them:
// RegistrationFieldError.error is documented as validator-defined and
// non-authoritative, so asserting the wording would fail this port for a difference
// the contract explicitly permits. The keyword is pinned instead — it is the same
// word in every JSON Schema library. That the prose never carries the submitted
// value is a separate, stronger claim, asserted here directly rather than by a
// vector, because it is a property of every possible payload rather than of these.

import { describe, expect, it } from "vitest";

import vectorsFile from "../../go/helpers/testdata/registration-schema-vectors.json";
import {
	checkRegistrationData,
	compileRegistrationSchema,
	isSafeSchemaPattern,
	maxPortableRepeat,
	maxRegistrationDataBytes,
	maxRegistrationDataMembers,
	maxRegistrationFieldErrorPathLen,
	maxRegistrationFieldErrorTextLen,
	maxRegistrationFieldErrors,
	maxRegistrationSchemaBytes,
	maxRegistrationSchemaDepth,
	maxRegistrationSchemaEvaluations,
	registrationSchemaDialect,
	registrationDataVerdicts,
	schemaVerdicts,
} from "../src/regschema";

type CompileVector = {
	name: string;
	schema?: string;
	// Carried as base64 when the input is not expressible as a JSON string — invalid
	// UTF-8. The rules are defined over the bytes AS SERVED, so a corpus that could
	// only state well-formed UTF-8 could not state the rule deciding what that means.
	schema_b64?: string;
	expected_verdict: string;
};

/**
 * wellFormed reports whether a string contains no lone surrogate. `String.isWellFormed`
 * would say so directly but needs a newer lib target than this package sets, and a
 * UTF-8 round trip answers the same question: encoding replaces a lone surrogate with
 * U+FFFD, so a string that survives unchanged had none.
 */
function wellFormed(s: string): boolean {
	return new TextDecoder().decode(new TextEncoder().encode(s)) === s;
}

function vectorBytes(v: { schema?: string; schema_b64?: string }): Uint8Array {
	if (v.schema_b64 !== undefined) return new Uint8Array(Buffer.from(v.schema_b64, "base64"));
	return new TextEncoder().encode(v.schema ?? "");
}
type ValidateVector = {
	name: string;
	schema: string;
	data: Record<string, unknown>;
	expected_paths: string[];
	expected_keywords: string[];
};
type PatternVector = { name: string; pattern: string; safe: boolean };
type RegDataVector = {
	name: string;
	data: Record<string, unknown>;
	expected_verdict: string;
};
type MatchVector = { name: string; pattern: string; value: string; matches: boolean };
type VectorsFile = {
	dialect: string;
	max_schema_bytes: number;
	max_schema_depth: number;
	max_field_errors: number;
	max_field_error_path_len: number;
	max_field_error_text_len: number;
	max_schema_evaluations: number;
	max_pattern_repeat: number;
	portable_pattern_escapes: string;
	verdicts: string[];
	registration_data_verdicts: string[];
	max_registration_data_bytes: number;
	max_registration_data_members: number;
	registration_data: RegDataVector[];
	compile: CompileVector[];
	validate: ValidateVector[];
	pattern: PatternVector[];
	match: MatchVector[];
};

const vectors = vectorsFile as VectorsFile;

describe("registration-schema parity", () => {
	it("ships the oracle's rule constants", () => {
		// The caps are the corpus's own header, so a port that picked its own numbers
		// fails before a single case runs.
		expect(registrationSchemaDialect).toBe(vectors.dialect);
		expect(maxRegistrationSchemaBytes).toBe(vectors.max_schema_bytes);
		expect(maxRegistrationSchemaDepth).toBe(vectors.max_schema_depth);
		expect(maxRegistrationFieldErrors).toBe(vectors.max_field_errors);
		expect(maxRegistrationFieldErrorPathLen).toBe(vectors.max_field_error_path_len);
		expect(maxRegistrationFieldErrorTextLen).toBe(vectors.max_field_error_text_len);
		expect(maxRegistrationSchemaEvaluations).toBe(vectors.max_schema_evaluations);
		expect(maxRegistrationDataBytes).toBe(vectors.max_registration_data_bytes);
		expect(maxRegistrationDataMembers).toBe(vectors.max_registration_data_members);
		// The two values that decide which patterns this port ADMITS, and the two this
		// suite did not check until a multi-comma repeat proved the alphabet had already
		// drifted from the other two SDKs.
		expect(maxPortableRepeat).toBe(vectors.max_pattern_repeat);
	});

	it("admits exactly the oracle's escape alphabet", () => {
		// Asserted through the RULE rather than against an exported set: every escape the
		// corpus lists must be admitted, and a letter outside the list must not be. That
		// needs no new public symbol and checks the behaviour the contract states rather
		// than a constant that happens to sit beside it.
		for (const c of vectors.portable_pattern_escapes) {
			expect(isSafeSchemaPattern(`\\${c}`)).toBe(true);
		}
		// A sample from outside the list, each one measured as divergent across the three
		// engines: the whitespace classes, the empty-string word boundary, a text anchor
		// and a named backreference.
		for (const c of ["s", "S", "B", "A", "k"]) {
			expect(vectors.portable_pattern_escapes).not.toContain(c);
			expect(isSafeSchemaPattern(`\\${c}`)).toBe(false);
		}
	});

	it("ships the oracle's verdict vocabularies", () => {
		// The corpus emits both lists so a port that grew a verdict the oracle does not
		// have, or lost one it does, is caught by comparing the list rather than by
		// whichever cases happen to exercise each token. Nothing read them until now, so
		// the hand-written union could drift with every gate green. Deriving the union
		// from this array is what keeps the type and the runtime list one object.
		expect([...schemaVerdicts]).toEqual(vectors.verdicts);
		expect([...registrationDataVerdicts]).toEqual(vectors.registration_data_verdicts);
	});

	it("ships a non-empty case set in every dimension", () => {
		// Vacuity. If the generator stopped emitting a dimension this suite would run
		// zero cases for it and pass, which is exactly what the `match` dimension — the
		// only one recording what an admitted schema then MATCHES — cannot afford.
		expect(vectors.compile.length).toBeGreaterThan(0);
		expect(vectors.validate.length).toBeGreaterThan(0);
		expect(vectors.pattern.length).toBeGreaterThan(0);
		expect(vectors.match.length).toBeGreaterThan(0);
		expect(vectors.registration_data.length).toBeGreaterThan(0);
	});

	it.each(vectors.compile.map((v) => [v.name, v] as const))("compile %s", (_name, v) => {
		const { schema, verdict } = compileRegistrationSchema(vectorBytes(v));
		expect(verdict).toBe(v.expected_verdict);
		// The schema is usable exactly when it was accepted — a port that returned a
		// compiled schema alongside a refusal would let a caller ignoring the verdict
		// enforce a schema the rules rejected.
		expect(schema !== null).toBe(verdict === "accepted");
	});

	it.each(vectors.validate.map((v) => [v.name, v] as const))("validate %s", (_name, v) => {
		const { schema, verdict } = compileRegistrationSchema(vectorBytes(v));
		expect(verdict).toBe("accepted");
		if (schema === null) throw new Error("the case's own schema did not compile");

		const violations = schema.violations(v.data);
		expect(violations.map((x) => x.path)).toEqual(v.expected_paths);
		expect(violations.map((x) => x.keyword)).toEqual(v.expected_keywords);

		// The public face carries the same pointers, in the same order, in the wire's
		// two-field shape.
		const fieldErrors = schema.validate(v.data);
		expect(fieldErrors.map((x) => x.path)).toEqual(v.expected_paths);
		expect(fieldErrors.length).toBeLessThanOrEqual(maxRegistrationFieldErrors);
		for (const fe of fieldErrors) {
			// CHARACTERS, which is what protovalidate's string.max_len counts. Measuring
			// `.length` here counts UTF-16 code units and would fail a pointer that is
			// comfortably inside the bound — the same unit confusion the port itself had.
			expect([...fe.path].length).toBeLessThanOrEqual(maxRegistrationFieldErrorPathLen);
			expect([...fe.error].length).toBeGreaterThanOrEqual(1);
			expect([...fe.error].length).toBeLessThanOrEqual(maxRegistrationFieldErrorTextLen);
			// A clamp that cut through a surrogate pair would leave a lone surrogate,
			// which is not a string the wire can carry. Encoding replaces one with
			// U+FFFD, so a round trip that comes back unchanged had none.
			expect(wellFormed(fe.path)).toBe(true);
			expect(wellFormed(fe.error)).toBe(true);
		}
	});

	it.each(vectors.pattern.map((v) => [v.name, v] as const))("pattern %s", (_name, v) => {
		expect(isSafeSchemaPattern(v.pattern)).toBe(v.safe);
	});

	// The dimension whose absence let a whole class of divergence ship. The other
	// three record which schemas are ADMITTED; this one records what an admitted
	// schema then MATCHES, which is where the three engines silently disagreed.
	it.each(vectors.match.map((v) => [v.name, v] as const))("match %s", (_name, v) => {
		const schema = JSON.stringify({
			type: "object",
			properties: { vat_id: { type: "string", pattern: v.pattern } },
		});
		const { schema: compiled, verdict } = compileRegistrationSchema(schema);
		expect(verdict).toBe("accepted");
		if (compiled === null) throw new Error("the case's own pattern is not admitted");
		expect(compiled.validate({ vat_id: v.value }).length === 0).toBe(v.matches);
	});

	it("never echoes the submitted value in a field error", () => {
		// The leakage rule, asserted directly rather than through a vector.
		// RegistrationFieldError.error states the violated constraint and never the
		// value, because a refusal travels back over the wire while registration_data
		// is an operator's business data. Ajv's own error.message quotes the offending
		// value for several keywords, and it is the obvious thing to reach for.
		const sentinel = "ZZTOPSECRETVALUE9999";
		const { schema, verdict } = compileRegistrationSchema(`{
			"type":"object",
			"required":["legal_name"],
			"properties":{
				"vat_id":{"type":"string","pattern":"^[A-Z]{2}[0-9]+$","minLength":40},
				"count":{"type":"number","minimum":10},
				"kind":{"enum":["a","b"]},
				"fixed":{"const":"only-this"},
				"tags":{"type":"array","uniqueItems":true}
			},
			"additionalProperties":false
		}`);
		expect(verdict).toBe("accepted");
		if (schema === null) throw new Error("the guard's own schema did not compile");

		const fieldErrors = schema.validate({
			vat_id: sentinel,
			count: 1,
			kind: sentinel,
			fixed: sentinel,
			tags: [sentinel, sentinel],
			[sentinel]: sentinel,
			nonempty: sentinel,
		});
		expect(fieldErrors.length).toBeGreaterThan(0);
		for (const fe of fieldErrors) {
			expect(fe.error).not.toContain(sentinel);
			expect(fe.path).not.toContain(sentinel);
		}
	});

	// The bounds on a SUBMITTED payload, which are the other half of the resource story:
	// the schema's caps bound the schema, and validation cost is the schema's cost
	// multiplied by the elements in the payload. The boundary cases pin the UNIT —
	// registration_data is not served as bytes, it arrives decoded, so the rule names an
	// encoding and a port measuring its own rendering would part on exactly these.
	it.each(vectors.registration_data.map((v) => [v.name, v] as const))(
		"registration_data %s",
		(_name, v) => {
			expect(checkRegistrationData(v.data)).toBe(v.expected_verdict);
		},
	);

	it("answers a non-finite number with a verdict rather than throwing", () => {
		// The one outcome the shared corpus cannot carry: JSON has no way to write NaN
		// or Infinity, which is exactly why a payload holding one has no canonical form
		// — and a decoded object can still hold one, because the value came from a
		// language rather than from a JSON document.
		for (const n of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) {
			expect(checkRegistrationData({ n })).toBe("uncanonicalizable");
		}
	});

});
