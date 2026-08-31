// Hand-written policy seam for the generated Zod schemas — the TS parallel of the Python
// wire.base.WireModel. This is the ONE place message-wide wire policy is set.
//
// Two rules live here, and both are applied at EVERY depth of a message:
//
// 1. Unknown keys are STRIPPED (Zod's default), so a top-level field from a newer protocol
//    version is ACCEPTED and dropped — matching Pydantic `extra="ignore"` and the Go typed-
//    struct re-marshal. To change the policy repo-wide, swap `.strip()` in wire() for
//    `.strict()` (reject) or `.passthrough()` (retain).
//
// 2. parseWire is the parse entry point, and it holds the two things the wire needs that a
//    bare schema cannot express: a `null` means the field has no value, and a
//    lowerCamelCase answer is refused. See parseWire.
//
// Map and Struct fields keep their own value schema and are never walked into: their keys
// and their values are caller-chosen data, so neither rule applies inside one.
import { z } from "zod";

import { snakeFromJsonName } from "./names.ts";

/**
 * wire sets the unknown-key policy on one generated schema.
 *
 * It returns a ZodObject, not a ZodEffects. That is load-bearing rather than incidental:
 * the readers that introspect these schemas — the from-wire offer inversion, the
 * snake-field guard — reach for `.shape` and `instanceof z.ZodObject` on the exported
 * value. An effect would break the first and silently stop matching in the second, which
 * is the worse failure: a guard that passes because it no longer looks at anything.
 */
export function wire<T extends z.ZodTypeAny>(schema: T): T {
	return schema instanceof z.ZodObject ? (schema.strip() as unknown as T) : schema;
}

/** The refusal parseWire raises. Carried as its own type so the caller above can map it to
 * a typed protocol failure without matching on a message string. */
export class WireNamingError extends Error {
	/** The offending key, as the peer spelled it. */
	readonly key: string;
	/** Dotted path to the message that carried it; "" at the root. */
	readonly path: string;

	constructor(key: string, path: string) {
		super(
			`peer answered with the lowerCamelCase json_name alias (${join(path, key)}); the ` +
				"RAMP wire is snake_case proto-JSON, so its answer cannot be read without " +
				"silently dropping every multiword field",
		);
		this.name = "WireNamingError";
		this.key = key;
		this.path = path;
	}
}

/**
 * parseWire validates one message against its generated schema, under the wire policy.
 *
 * A generated schema describes the message. It cannot describe the two things that are
 * true of the WIRE rather than of the message, so both live here — applied in one
 * schema-driven pass over the value, at every depth.
 *
 * **A `null` means the field has no value.** The canonical wire is proto-JSON, and there a
 * null is a field's default — for ANY field, not only a message-typed one. So a null is
 * dropped wherever the schema does not require a value: the field then reads as unset, or
 * takes the default the schema declares, which is what the oracle answers for the same
 * bytes. Where the schema DOES require a value the null is left in place for it to refuse.
 *
 * Both halves are load-bearing. EmitUnpopulated — what a RAMP Exchange serves — renders an
 * unpopulated non-optional message field as null rather than omitting it, so `{"ext":null}`
 * is the ordinary shape of a real response. It renders an unset Timestamp that way too, and
 * that is the case a narrower rule missed: the generator flattens a Timestamp to a string
 * schema, so a test for "is this a message?" answered no and every response carrying an
 * attestation without an attested-at, or a rate limit without a reset time, was refused
 * outright. Pydantic spells all of these `X | None` and accepts the null, so reading
 * presence rather than type is what keeps the two languages on one wire.
 *
 * **A lowerCamelCase answer is REFUSED.** The RAMP wire is snake_case proto-JSON and the
 * camelCase json_name alias is out of contract, so a conformant peer serves snake_case —
 * connect-go does that only when a codec with UseProtoNames is registered, which a RAMP
 * deployment does and a stock connect-go server does not. The generated schemas accept
 * snake_case only and STRIP what they do not recognise, so a camelCase answer would
 * otherwise parse SUCCESSFULLY into a message with every multiword field missing, and
 * nothing anywhere would say so.
 *
 * Depth is the point, for the refusal especially, and the money verb is why: a stock
 * connect-go server omits unset fields, so a TransactionResponse arrives as
 * `{ver, items}` — every root key a single word, identical in both spellings — while
 * `transaction_id` sits one level down in TransactionResultItem and is dropped. That reads
 * as a purchase that succeeded with no transaction id and no delivery URL, severing the
 * dispute chain at its first link.
 *
 * Open maps are out of reach by construction rather than by a hold-back list: the pass is
 * driven by the schema, and it stops at a map.
 *
 * Applied on the way in rather than baked into the schema, because the schema has to stay
 * portable: the repo runs Zod 3 in the SDK trees and Zod 4 in the canonical round-trip
 * gate, and the two disagree about how a schema is rebuilt — `.extend()` drops a
 * description on one of them, and a reconstructed array loses its bounds. Expressing it in
 * the JSON Schema instead would emit a union in place of every message field, which the
 * from-wire inversion reads as a scalar. The Python twin needs neither workaround: a
 * validator on WireModel is inherited by every nested model, so it recurses for free.
 */
export function parseWire<T>(
	schema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
	raw: unknown,
): { success: true; data: T } | { success: false } {
	const parsed = schema.safeParse(underWirePolicy(schema, raw, ""));
	if (!parsed.success) return { success: false };
	return { success: true, data: parsed.data as T };
}

/**
 * underWirePolicy returns `value` with the wire policy applied, refusing a non-canonical
 * field name. Exported so a guard can drive the policy without a parse behind it.
 *
 * The input is never mutated: a request goes through here too, and the caller keeps the
 * object it passed.
 */
export function underWirePolicy(schema: unknown, value: unknown, path: string): unknown {
	if (!(schema instanceof z.ZodType)) return value;
	const core = unwrapped(schema as z.ZodTypeAny);

	if (core instanceof z.ZodArray) {
		if (!Array.isArray(value)) return value;
		const element = core.element as z.ZodTypeAny;
		return value.map((item, i) => underWirePolicy(element, item, `${path}[${i}]`));
	}
	// A map's keys are caller-chosen data. Nothing below one is a proto field name, and a
	// null inside a Struct is a value (NullValue), not an absence.
	if (!(core instanceof z.ZodObject)) return value;
	if (typeof value !== "object" || value === null || Array.isArray(value)) return value;

	const shape = core.shape as Record<string, z.ZodTypeAny>;
	const out: Record<string, unknown> = {};
	for (const [key, member] of Object.entries(value as Record<string, unknown>)) {
		// hasOwn, not `shape[key] !== undefined`: a key like "__proto__" or "constructor"
		// resolves to an inherited member of Object.prototype, which would read as a
		// declared field and hand the walk something that is not a schema.
		if (!Object.hasOwn(shape, key)) {
			const name = snakeFromJsonName(key);
			if (name !== key && Object.hasOwn(shape, name)) throw new WireNamingError(key, path);
			// defineProperty, not assignment: a key named "__proto__" would replace this
			// object's prototype and create no member, so the value would never be walked
			// and the schema would then read declared keys back through the prototype
			// chain — accepting nested camelCase the depth check is here to refuse.
			keep(out, key, member); // unknown to this pin; the schema strips it
			continue;
		}
		const field = shape[key];
		if (field === undefined) continue;
		// A null is how proto-JSON spells "no value here". Absent and null are the same
		// state, so a field the schema does not require is left unset and one it does
		// require keeps the null for the schema to refuse.
		if (member === null && mayBeUnset(field)) continue;
		keep(out, key, underWirePolicy(field, member, join(path, key)));
	}
	return out;
}

/** keep writes a member, including one whose name is an inherited property of every
 * object. See the call sites: a plain assignment to "__proto__" sets a prototype. */
function keep(out: Record<string, unknown>, key: string, value: unknown): void {
	Object.defineProperty(out, key, {
		value,
		enumerable: true,
		writable: true,
		configurable: true,
	});
}

/** Peel the wrapper kinds that decorate a schema without changing what it holds: the ones
 * the generator emits around a field, and the refinement the cross-field layer attaches
 * around a whole message. `.unwrap()` and `.removeDefault()` are spelled the same way in
 * Zod 3 and Zod 4 — which is the whole reason this reads rather than rebuilds. */
function unwrapped(schema: z.ZodTypeAny): z.ZodTypeAny {
	let s = schema;
	for (;;) {
		if (s instanceof z.ZodOptional || s instanceof z.ZodNullable) {
			s = s.unwrap() as z.ZodTypeAny;
			continue;
		}
		if (s instanceof z.ZodDefault) {
			s = s.removeDefault() as z.ZodTypeAny;
			continue;
		}
		// A REFINEMENT wraps the object without changing what it holds. This is how the
		// cross-field layer attaches its rules (sdk/ts/src/crossfield.ts), and without this
		// branch the ZodObject test in underWirePolicy fails on every composed schema, so
		// the whole wire policy is skipped for it: a camelCase answer parses successfully
		// into a message with every multiword field missing, and the cross-field rule that
		// needed one of those fields cannot fire. Peeling here is INSPECTION ONLY — parseWire
		// still hands the ORIGINAL schema to safeParse, so the refinement still runs.
		//
		// Read as a method rather than through `instanceof z.ZodEffects`, because that class
		// exists only in Zod 3. In Zod 4 a refinement keeps the schema's own class, so the
		// ZodObject test already holds and there is nothing to peel — and naming the class
		// would throw, since scripts/check-canonical.sh runs this file under Zod 4.
		const innerType = (s as { innerType?: () => z.ZodTypeAny }).innerType;
		if (typeof innerType === "function") {
			// A PREPROCESS effect rewrites the input BEFORE the inner schema sees it, so the
			// inner shape is not the shape of what arrives here and the policy would be
			// applied against the wrong object. refine, superRefine and transform all check
			// the input against the inner schema first, so for those the inner shape is right.
			if (effectType(s) === "preprocess") return s;
			s = innerType.call(s) as z.ZodTypeAny;
			continue;
		}
		return s;
	}
}

/** Which kind of Zod 3 effect a schema carries. Only reached when `innerType` is present,
 * which in Zod 3 is ZodEffects and nothing else. */
function effectType(s: z.ZodTypeAny): string {
	return (s as unknown as { _def: { effect: { type: string } } })._def.effect.type;
}

/**
 * Whether the schema would accept this field carrying no value at all.
 *
 * This is the whole test for whether a null may be dropped, and it is deliberately a
 * question about PRESENCE rather than about type. The predicate it replaced asked whether
 * the field held a message or a map, which reads as the same question and is not: the
 * generator FLATTENS the well-known types, so a google.protobuf.Timestamp — a message on
 * the wire, rendered as null when unset like any other — arrives here as a plain string
 * schema and failed a structural test for messages. Every response carrying one was refused.
 *
 * Optional and defaulted both count, and the default is the reason the two are not one
 * check: dropping the null on a defaulted field lets the schema supply the default, which
 * is exactly what the oracle answers for the same bytes.
 */
function mayBeUnset(field: z.ZodTypeAny): boolean {
	let s = field;
	for (;;) {
		if (s instanceof z.ZodOptional || s instanceof z.ZodDefault) return true;
		if (s instanceof z.ZodNullable) {
			s = s.unwrap() as z.ZodTypeAny;
			continue;
		}
		return false;
	}
}

function join(path: string, key: string): string {
	return path === "" ? key : `${path}.${key}`;
}
