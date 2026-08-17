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
	compileRegistrationSchema,
	isSafeSchemaPattern,
	maxRegistrationFieldErrorPathLen,
	maxRegistrationFieldErrorTextLen,
	maxRegistrationFieldErrors,
	maxRegistrationSchemaBytes,
	maxRegistrationSchemaDepth,
	maxRegistrationSchemaEvaluations,
	registrationSchemaDialect,
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
});
