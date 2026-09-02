// A recipient the wire will not carry is refused locally, without echoing a credential.
//
// isBareDomain answers false for a value carrying userinfo — a verdict, not a parse
// error — so the value reaches the message and would be echoed whole unless the refusal
// redacts it. The routing check next door already redacts; this pins the catalog leg to
// the same rule, in the language the Go oracle is mirrored into.
//
// The other cases are the ones the ROUTING predicate would have waved through. Each is a
// usable host and none is a value `exchange` may hold, so vetting with the wider rule
// signed and sent a request the recipient could only refuse.
//
// Mirrors sdk/python/tests/test_catalog_recipient_redaction.py.
import { describe, expect, it } from "vitest";
import { createCatalogClient } from "../client/index.ts";
import { RampCallError } from "../client/errors.ts";

const CREDENTIAL = "s3cr3t";
const WITH_USERINFO = `publisher:${CREDENTIAL}@exchange.test`;
const NEVER_SENT = "the request must be refused before it is sent";

function push(exchange: string): Promise<unknown> {
	const client = createCatalogClient("https://exchange.test", {
		send: async () => {
			throw new Error(NEVER_SENT);
		},
	});
	return client.pushResources({
		exchange,
		tenant_id: "t",
		caller_id: "c",
		entries: [{ domain: "publisher.test", path: "/x" }],
	});
}

describe("the catalog client's recipient check", () => {
	it("refuses a recipient carrying userinfo without repeating it", async () => {
		const err = await push(WITH_USERINFO).then(
			() => undefined,
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(RampCallError);
		expect((err as RampCallError).kind).toBe("not_sent");
		// The whole rendered failure, not just its cause: a credential leaked into any
		// part of what a caller sees is the leak this test exists to catch.
		const text = `${String(err)} ${String((err as RampCallError).cause ?? "")}`;
		expect(text).not.toContain(CREDENTIAL);
		expect(text).toContain("[redacted]");
	});

	it.each(["_x.exchange.test", "exchange.test.", "[::1]:443", "https://exchange.test", "exchange.test/x"])(
		"refuses %s before signing",
		async (exchange) => {
			const err = await push(exchange).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(err).toBeInstanceOf(RampCallError);
			expect((err as RampCallError).kind).toBe("not_sent");
			expect(String((err as RampCallError).cause)).toContain("is not a bare domain");
		},
	);

	// The other half, or the check above would pass on a predicate that refuses all. A
	// port is part of a bare domain and a single-label host is one. The send itself is
	// what the double refuses, so reaching it is the assertion.
	it.each(["exchange.test", "exchange.test:8443", "edge"])(
		"does not refuse %s",
		async (exchange) => {
			await expect(push(exchange)).rejects.toThrow(NEVER_SENT);
		},
	);
});
