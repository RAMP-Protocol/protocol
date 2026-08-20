// Data a peer controls produces a typed failure, never a raw exception.
//
// Mirrors sdk/python/tests/test_hostile_response_data.py.
//
// Both languages document that every verb throws exactly one failure type. Three places
// broke that, and each is reached from bytes a peer chose: a `debug` projection that does
// not decode (read on EVERY non-2xx, which is where a hostile peer operates), an offer-key
// resolver that throws, and a wire key naming an inherited object member.
import { describe, expect, it } from "vitest";

import { createVerifier } from "../core/verifier.ts";
import { fromWireOffer } from "../core/wire-canon.ts";
import { errorDetailFrom } from "../src/errordetail.ts";

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
