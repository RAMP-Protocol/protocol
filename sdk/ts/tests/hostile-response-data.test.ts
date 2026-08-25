// Data a peer controls produces a typed failure, never a raw exception.
//
// Mirrors sdk/python/tests/test_hostile_response_data.py.
//
// Both languages document that every verb throws exactly one failure type. Three places
// broke that, and each is reached from bytes a peer chose: a `debug` projection that does
// not decode (read on EVERY non-2xx, which is where a hostile peer operates), an offer-key
// resolver that throws, and a wire key naming an inherited object member.
import { describe, expect, it } from "vitest";
import { MockAgent } from "undici";

import { createVerifier } from "../core/verifier.ts";
import { fromWireOffer } from "../core/wire-canon.ts";
import { errorDetailFrom } from "../src/errordetail.ts";
import { MAX_BODY_DEPTH } from "../src/jsondepth.ts";
import { decodeResponse, parseMessage } from "../client/transport.ts";
import { fetchContent } from "../client/content.ts";
import { RampCallError } from "../client/errors.ts";
import { ResourceResponseSchema } from "../../../gen/ts/wire/schemas.ts";

const HOSTILE = { domain: 123, message: ["not", "a", "string"] };
const GOOD = {
	domain: "d",
	message: "m",
	transactionDenial: { reason: "DENIAL_REASON_INSUFFICIENT_BALANCE" },
};

const envelope = (...debugs: unknown[]) => ({
	details: debugs.map((debug) => ({ type: "ramp.v1.ErrorDetail", debug })),
});

describe("a debug projection a peer chose", () => {
	it("does not decode into an answer", () => {
		expect(errorDetailFrom(envelope(HOSTILE) as never)).toBeNull();
	});

	it("and does not stop the scan of the entries after it", () => {
		// `details` is a list; an entry that does not decode says nothing about the next.
		const detail = errorDetailFrom(envelope(HOSTILE, GOOD) as never);
		expect(detail).not.toBeNull();
		expect(detail?.domain).toBe("d");
	});
});

describe("a debug projection deeper than the reader's bound", () => {
	// A real ErrorDetail nests two deep. The bound is the same 32 the protocol sets for a
	// third party's JSON in AccountRegistration.data_schema.
	for (const [depth, readable] of [
		[2, true],
		[30, true],
		[4000, false],
		[50_000, false],
	] as Array<[number, boolean]>) {
		it(`depth ${depth} is ${readable ? "read" : "not an answer"}`, () => {
			const nested: Record<string, unknown> = {};
			let cursor = nested;
			for (let i = 0; i < depth; i += 1) {
				cursor["a_b"] = {};
				cursor = cursor["a_b"] as Record<string, unknown>;
			}
			// Recursing to the engine's stack limit throws a RangeError out of a reader
			// that promises a value.
			const detail = errorDetailFrom(envelope({ ...GOOD, extra: nested }) as never);
			expect(detail !== null).toBe(readable);
		});
	}

	it("a key named __proto__ inside one is a member, not a prototype", () => {
		const payload = JSON.parse(
			'{"details":[{"type":"ramp.v1.ErrorDetail","debug":{"domain":"d","message":"m","__proto__":{"x":1}}}]}',
		) as unknown;
		expect(errorDetailFrom(payload)?.domain).toBe("d");
	});
});

// How deep a document neither JSON client wrote may nest, pinned at its EDGE. The bound is
// a CONTRACT rather than a property of this runtime — V8's parser is iterative and nothing
// here overflows — but the two clients have to answer one thing for one body, so the number
// is asserted here exactly as its Python sibling asserts it. Go is not bounded and
// deliberately so; docs/design-history.md records the difference.
describe("a response body deeper than the bound", () => {
	// The root object is one, `ext` is two, and each further object adds one. `ext` is the
	// carrier because it is a google.protobuf.Struct: how deep it goes is the peer's choice
	// and nothing in the contract bounds it, which is what makes this the reachable shape
	// rather than a contrived one.
	const responseNesting = (total: number): string => {
		const nested: Record<string, unknown> = {};
		let cursor = nested;
		for (let i = 0; i < total - 2; i += 1) {
			cursor["k"] = {};
			cursor = cursor["k"] as Record<string, unknown>;
		}
		return JSON.stringify({ ver: "1.0", exchange: "e.test", ext: nested });
	};

	it("is read AT the bound", () => {
		const raw = decodeResponse("discover", {
			status: 200,
			body: responseNesting(MAX_BODY_DEPTH),
		});
		const msg = parseMessage<Record<string, unknown>>(
			"discover",
			raw,
			ResourceResponseSchema,
		);
		expect(msg["exchange"]).toBe("e.test");
	});

	// One container past it, refused FOR ITS DEPTH rather than for anything else about it,
	// which is what makes the number load-bearing. Both status bands, because the check runs
	// before the status is consulted: this is reachable on the SUCCESS path too, not only
	// where a hostile peer is expected.
	for (const status of [200, 500]) {
		it(`is refused one past the bound, status ${status}`, () => {
			const read = () =>
				decodeResponse("discover", {
					status,
					body: responseNesting(MAX_BODY_DEPTH + 1),
				});
			expect(read).toThrow(RampCallError);
			expect(read).toThrow(`deeper than ${MAX_BODY_DEPTH} containers`);
		});
	}
});

// The delivery leg's own reader of a peer's bytes, bounded the same way. Driven through the
// FULL verb rather than the reader, because what a deep body broke in the sibling was the
// contract the verb states: every one of them throws RampCallError and nothing else.
describe("a deeply nested delivery refusal body", () => {
	it("yields no token, and the SDK's own class instead", async () => {
		// A WELL-FORMED refusal carrying a token the SDK would otherwise repeat, with the
		// nesting beside it. That is what separates the guard from the absence of one: drop
		// the guard and this body still parses, and the token comes back.
		const depth = 1200;
		const hostile = `{"reason":"url_expired","x":${"[".repeat(depth)}${"]".repeat(depth)}}`;
		// The point is that the size cap does not bound the nesting.
		expect(hostile.length).toBeLessThan(4 << 10);

		const agent = new MockAgent();
		agent.disableNetConnect();
		agent
			.get("https://edge.test")
			.intercept({ path: "/x", method: "GET" })
			.reply(403, hostile, { headers: { "content-type": "application/json" } });

		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
		const err = (await fetchContent("https://edge.test/x", {
			keyPair: keys,
			dispatcher: agent,
		}).catch((e: unknown) => e)) as RampCallError;

		expect(err).toBeInstanceOf(RampCallError);
		// The edge said no, so the class is the SDK's own — and the token, which is the one
		// part of a refusal the SDK does not own, is absent rather than invented.
		expect(err.kind).toBe("refused");
		expect(err.reason).toBeUndefined();
	});
});

describe("an offer-key resolver that throws", () => {
	it("rejects one offer, not the whole answer", async () => {
		// On a Broker fan-out the exchange comes off a relayed offer, so one Exchange whose
		// key endpoint hangs would otherwise deny the agent every offer in the response.
		const verifier = createVerifier("strict", {
			resolve: async (exchange: string) => {
				throw new Error(`key endpoint unreachable for ${exchange}`);
			},
			now: () => 1_700_000_000,
		});
		const sorted = await verifier.sort([
			{ exchange: "a.test", signature: "00" },
			{ exchange: "b.test", signature: "00" },
		]);
		expect(sorted.verified).toHaveLength(0);
		expect(sorted.rejected).toHaveLength(2);
		expect(sorted.rejected[0]?.reason).toContain("key endpoint unreachable");
	});
});

describe("a wire key naming an inherited object member", () => {
	// shape["__proto__"] resolves to Object.prototype unless the lookup uses hasOwn, which
	// hands the walk something that is not a schema. An offer arrives from a peer, so the
	// key is attacker-chosen.
	for (const key of ["__proto__", "constructor", "toString", "valueOf"]) {
		it(`is treated as an unknown field: ${key}`, () => {
			const wire = JSON.parse(
				`{"offer_id":"o","exchange":"e.test","${key}":{"x":1}}`,
			) as Record<string, unknown>;
			expect(fromWireOffer(wire)["offer_id"]).toBe("o");
		});
	}
});
