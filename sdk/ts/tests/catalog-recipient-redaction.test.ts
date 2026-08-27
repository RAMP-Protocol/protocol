// A recipient carrying userinfo is refused, and the refusal must not repeat the
// credential. isBareHost answers false for such a value — a verdict, not a parse
// error — so the value reaches the message and would be echoed whole unless the
// refusal redacts it. The routing check next door already redacts; this pins the
// catalog leg to the same rule, in the language the Go oracle is mirrored into.
import { describe, expect, it } from "vitest";
import { createCatalogClient } from "../client/index.ts";

const CREDENTIAL = "s3cr3t";
const WITH_USERINFO = `publisher:${CREDENTIAL}@exchange.test`;

describe("the catalog client's recipient refusal redacts a credential", () => {
	it("refuses a recipient carrying userinfo without repeating it", async () => {
		const client = createCatalogClient("https://exchange.test", {
			send: async () => {
				throw new Error("the request must be refused before it is sent");
			},
		});

		await expect(
			client.pushResources({
				exchange: WITH_USERINFO,
				tenant_id: "t",
				caller_id: "c",
				entries: [{ domain: "publisher.test", path: "/x" }],
			}),
		).rejects.toSatisfy((err: unknown) => {
			const text = String(err instanceof Error ? (err.cause ?? err) : err);
			expect(text).not.toContain(CREDENTIAL);
			expect(text).toContain("[redacted]");
			return true;
		});
	});
});
